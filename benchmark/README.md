# SkillSpector Benchmark

A standalone harness that runs SkillSpector over a benchmark dataset
([MalSkillBench](https://github.com/NVIDIA/MalSkillBench) today) and scores its
classifications into DuckDB, so you can measure precision/recall/accuracy.

## Why this is a separate project

This is a **dev/eval tool**, not part of the shipped `skillspector` package. It
lives in its own uv project with its own `pyproject.toml`, lockfile, and venv,
and depends on `skillspector` as an **editable path dependency** (`../`). That
means:

- Nothing here touches the root `pyproject.toml` / lockfile, so upstream merges
  from `NVIDIA/skillspector` stay conflict-free.
- The harness-only dependencies (`duckdb`, `filelock`, `tqdm`,
  `aws-bedrock-token-generator`) never ship to `skillspector` end users.
- Edits to `src/skillspector` are picked up immediately (editable install), so
  you always benchmark your working tree.

## Running

Three console scripts: `benchmark` (scan), `report` (compare two runs), and
`remove-run` (delete runs from a DB).

From the repo root (no `cd` needed):

```bash
uv run --directory benchmark benchmark /path/to/MalSkillBench/Dataset
```

Or from inside this directory:

```bash
cd benchmark
uv run benchmark /path/to/MalSkillBench/Dataset
uv run benchmark .../Dataset/Prompts/indirect-injection -o out.duckdb
uv run benchmark .../Dataset/Skills/malware --limit 50 --workers 8
uv run benchmark .../Dataset --no-llm        # static analysis only
```

> Note: the console-script name (`benchmark`) intentionally matches the package
> directory, so there is **no** `__main__.py` — adding one would make `uv run
> benchmark` execute the directory instead of the installed entry point. Invoke
> it via the `benchmark` command (as above) or `.venv/bin/benchmark` directly.

### Removing runs

`remove-run` deletes runs from a DB — handy for pruning throwaway
local-validation runs before you version the file. It takes the DB path and one
or more run ids (a unique prefix is accepted), removes each run's rows across all
of its tables, and confirms once before deleting (`--yes`/`-y` skips the prompt).
Ids that don't resolve are skipped with a warning; the rest are shown with their
row counts.

```bash
uv run remove-run results.duckdb <run_id> [<run_id> ...]
uv run remove-run results.duckdb ab12 9f3 c7 --yes   # several at once, no prompt
```

> Note: `DELETE` clears the runs' data but does **not** shrink the `.db` file on
> disk (DuckDB reuses the freed blocks internally); to reclaim file size, rewrite
> the DB to a fresh file.

### Key flags

| Flag | Meaning |
|------|---------|
| `-o, --output` | DuckDB output file (default `benchmark_<id>.duckdb`) |
| `--no-llm` | static analysis only (no LLM calls) |
| `--categories` | comma-separated unit categories to scan; default `skill,code`. **Prompts are excluded by default** — they're raw prompt-injection samples, not the repo config files this tool classifies (PI embedded in a skill is still covered via the `skill` units). Pass `--categories skill,code,prompt` to include them. |
| `--limit N` | cap units **per group** — a unit's parent directory (e.g. `--limit 20` on `Dataset/Skills` keeps 20 from `Skills/malware` *and* 20 from `Skills/benign`); 0 = no cap |
| `--workers N` | concurrent scan processes (default 8) |
| `--run-id` | extend an existing run instead of starting a new one (requires `-o`); re-scans only its unfinished units and appends into the same run |
| `--from-run` | re-scan the units of a previous run instead of a `DATASET_PATH` (requires `-o`; reads that run from the `-o` DB and appends a new run there). Omit the positional path. |
| `--failures-only` | with `--from-run`, re-scan only that run's **failed** units (FN, FP, timeouts, and errors) |
| `--dataset` | with `--from-run`, override the source run's recorded dataset path (if the checkout moved) |
| `--description` | free-text note stored on the run in the `runs` table |
| `--overwrite` | delete the output DB before running (default: append a new run to it) |
| `--auth-wait-seconds` | how long to pause for `aws sso login` on a mid-run SSO expiry |

Every invocation is a **new run** by default (multiple runs coexist in one DB).
To extend an interrupted run, re-run with `--run-id <id>` (printed when the run
is created): already-classified units are skipped and only failures re-scanned.

### Re-checking a previous run

`--from-run` re-scans the units of an earlier run rather than rediscovering a
dataset — `--failures-only` narrows that to the units that previously failed.
The intended loop: scan a baseline, change the analyzer, re-check the failures,
then `report` the two to see exactly which previously-failing units improved.

```bash
uv run benchmark /path/to/Dataset -o results.duckdb --description baseline   # 1. baseline
#   ... make analyzer changes ...
uv run benchmark --from-run <baseline_id> --failures-only -o results.duckdb \
    --description "after fix"                                                 # 2. re-check failures
uv run report results.duckdb <recheck_id> --base <baseline_id>               # 3. compare
```

> The unit *content* isn't stored in the DB (code/prompt units are materialized
> at scan time), so `--from-run` rediscovers the source run's dataset and filters
> to its unit_paths — the original checkout must still be on disk (or pass
> `--dataset`). Comparing a failures-only re-check against its full baseline will
> trip the report's coverage-skew warning; that's expected — the head-to-head
> section is the view you want there.

## Output

DuckDB tables `runs`, `units` (ground truth), `classifications` (SkillSpector
verdict), `issues`, `components`, plus an `evaluation` view labeling every scan
`TP`/`FP`/`TN`/`FN`/`ERROR`:

```bash
duckdb benchmark_<id>.duckdb "SELECT outcome, count(*) FROM evaluation GROUP BY 1"
```

## Inspecting classifier performance

The `queries/` directory holds ready-made DuckDB queries for evaluating how well
SkillSpector classified — precision/recall/F1 breakdowns, the false-negative and
false-positive lists worth eyeballing, run-health checks, and tuning aids. Run
one against an output DB with `.read`:

```bash
duckdb -readonly benchmark_<id>.duckdb ".read queries/01_overview.sql"
```

Each file is self-documenting (header comment explains what it shows) and, except
`01_overview.sql`, defaults to the **most recent run** in the DB — edit the `run`
CTE at the top to target a different run or span all of them.

| Query | What it answers |
|-------|-----------------|
| `01_overview.sql` | Per-run config + confusion matrix + precision/recall/F1/accuracy (compare runs) |
| `02_metrics_by_category.sql` | Metrics split by skill / code / prompt |
| `03_metrics_by_attack_vector.sql` | Metrics split by CI / PI / MIXED |
| `04_metrics_by_corpus.sql` | Metrics split by source corpus |
| `05_recall_by_behavior.sql` | Which attack behaviors (B1..B15) evade detection, worst first |
| `06_false_negatives.sql` | Malware that was cleared — the critical misses |
| `07_false_positives.sql` | Benign units flagged, with the rules that fired |
| `08_errors.sql` | Scans that failed (invalidate metrics if high) |
| `09_classification_status.sql` | LLM vs static vs **fallback** (catches "LLM didn't actually run") |
| `10_risk_score_distribution.sql` | Score histogram by ground truth — does the score separate classes? |
| `11_threshold_sweep.sql` | P/R/F1 across hypothetical `risk_score` cutoffs (tune the verdict) |
| `12_scan_timing.sql` | Timing percentiles + slowest scans |
| `13_label_coverage.sql` | How ground-truth labels were resolved (bounds trust in 03/05) |
| `14_top_rules.sql` | Which rules fire, on malicious vs benign (false-positive drivers) |

## Comparing two runs (PR-ready report)

The `report` command compares two runs in a DB and emits a markdown summary —
headline metrics with deltas, per-dimension distributions (category, benign vs
malicious, attack vector, behavior, …), timing, and an **outcome-transition**
analysis (which units moved `FN→TP`, `TP→FN`, etc.) that quantifies whether a
change actually helped. Visualize it locally, then paste it into a PR
description to show the improvement. If the two runs scanned materially
different sample sets, the report leads with a warning that the headline deltas
aren't a controlled comparison (the head-to-head section is the like-for-like view).

```bash
uv run report <db_path> <candidate_run> --base <baseline_run> -o report.md
```

`db_path` is the DuckDB file containing all relevant runs. The positional `RUN`
is the candidate (head); `--base` names the baseline. Omit `--base` for a
single-run summary. Deltas are `head − base`. A unique run-id **prefix** is
accepted. Output goes to stdout unless `-o` is given.

| Flag | Meaning |
|------|---------|
| `--base` | baseline run id to compare `RUN` against (omit for a single-run summary) |
| `-o, --output` | write the markdown to a file (default: stdout) |
| `--label` | display name for `RUN` / head (default: the run's description or short id) |
| `--base-label` | display name for the base run |
| `--top N` | max regression / fix rows to list (default 25; the full counts are always shown) |

> The output uses unicode bar charts + markdown tables, which render identically
> in a GitHub PR description, a local markdown preview, and plain text.

## Layout

```
benchmark/
  main.py                  # click CLI: `benchmark` (scan) + `report` (compare) + `remove-run` (delete) console scripts
  config.py                # provider/run constants + parent-process env wiring
  models.py                # Unit, ScanResult
  auth.py                  # Bedrock bearer-token manager (cross-process cache)
  db.py                    # DuckDB schema + result persistence
  runner.py                # the classifier seam: prepare a unit, run SkillSpector
  utils.py                 # cross-cutting helpers
  dataset_handler/
    base.py                # DatasetHandler abstraction
    malskillbench.py       # MalSkillBench implementation
    __init__.py            # handler registry + discover() dispatch
  report/                  # `report` command: compare two runs -> markdown
    data.py                # per-run metrics out of DuckDB
    compare.py             # deltas, coverage, outcome transitions
    charts.py              # unicode bars + delta formatters (template filters)
    render.py              # Jinja2 context assembly + render
    templates/report.md.j2 # the report layout
```

## Adding another dataset

Discovery is behind an interface so the harness isn't locked to MalSkillBench:

1. Subclass `DatasetHandler` (in `dataset_handler/base.py`), implementing
   `matches(root)` and `discover(root) -> list[Unit]`.
2. Register it in `dataset_handler/__init__.py`'s `_HANDLERS` list (most
   specific first; MalSkillBench is the default fallback).

Everything downstream (runner, DB, scoring) works in terms of `Unit` /
`ScanResult`, so a new handler is the only code a new benchmark needs.
