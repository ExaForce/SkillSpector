# P0 (O0): Measurement Tooling and Baseline-v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the tooling that every later plan uses to quantify a classifier change, and record a fresh full run
(`baseline-v2`) that stores finding tags. The tooling covers:
- run config capture;
- unit-list runs;
- a run-health gate;
- offline replay of scoring policies;
- same-day arm comparison;
- evaluation sets;
- SkillHarm attribution;
- label-tiered and per-corpus sections in `report`.

**Architecture:** Every change lives in the standalone `benchmark/` uv project; no classifier code changes. Each new
tool is a small module with a click entry point registered in `benchmark/pyproject.toml`, following the existing
`report` and `remove-run` scripts. The report gains an "extras" layer (`report/extras.py`) that joins MalSkillBench
label files at render time.

**Tech Stack:** Python 3.12+, click, DuckDB, Jinja2 (`StrictUndefined`), pytest.

**Spec:** `docs/superpowers/specs/2026-10-29-recall-improvement-program.md`. Background:
`benchmark/recall-boundaries.md` and `benchmark/recall-boundaries-review.md`.

## Global Constraints

- Everything in the spec's "Autonomy rules", "Data and paths" and "Evaluation protocol" applies.
- Branch: `git switch -c exaforce/recall-p0-measurement` from `exaforce/promote-confirmed-ssd-high`. Commit only the
  paths each task names.
- Only `benchmark/` files change. `src/` is untouched in this plan.
- Every run of the original baseline `113b02ab497b` has no `issues.tags`. Code must treat a NULL `tags` as `[]`.
- Ruff line length is 100. The Jinja environment uses `StrictUndefined`, so every attribute a template references
  must exist.
- The `health` thresholds are fixed by the spec: zero `SSD-`/`SDI-`/`SQP-` issues on an LLM run; >5% of scans with
  `llm_calls_succeeded < llm_calls_attempted`; >1% `ERROR` outcomes; median `run_time` <3 s on an LLM run.

## Review Focus

1. **Replay applied to a run with NULL `tags`** (`113b02ab497b`). A `confirmed` gate must fall back to "unknown" and
   say so, not silently treat every finding as confirmed. Test: `test_replay_confirmed_gate_requires_tags`.
2. **`--units-file` naming a unit absent from the dataset.** The run must print the missing count and continue, like
   `--from-run` already does. Test: `test_units_file_reports_missing`.
3. **SkillHarm unit with no clean counterpart.** Attribution falls back to `target_path` and records
   `method="target_path"`. Test: `test_injected_files_fallback`.
4. **`report` on a DB whose `dataset_path` label files are missing.** The extras sections render "labels not found",
   not a crash. Test: `test_extras_missing_labels`.
5. **`arms` with a single control replicate.** The noise floor uses the floor constants (3 TP, 2 FP) and the output
   flags "1 replicate". Test: `test_arms_single_replicate`.

---

## File Structure

- `benchmark/benchmark/db.py`: MODIFY. Add the `runs.config_json` column and its migration (Task 1). The `issues.tags`
  change is already in the working tree; Task 1 commits it.
- `benchmark/benchmark/main.py`: MODIFY. Record `config_json`; add the `--units-file` option (Tasks 1-2).
- `benchmark/benchmark/health.py`: CREATE. `check_health` and the `health` CLI (Task 3).
- `benchmark/benchmark/replay.py`: CREATE. Policy replay into a synthetic run (Task 4).
- `benchmark/benchmark/attribution.py`: CREATE. Derive SkillHarm injected files (Task 5).
- `benchmark/benchmark/report/extras.py`: CREATE. Data for the new report sections (Task 6).
- `benchmark/benchmark/report/{__init__,render}.py` and `templates/*.j2`: MODIFY. Render the extras; add
  `--split-file` (Task 6).
- `benchmark/benchmark/arms.py`: CREATE. Same-day arm comparison and verdict (Task 7).
- `benchmark/benchmark/evalset.py`: CREATE. Evaluation-set builder (Task 8).
- `benchmark/pyproject.toml`: MODIFY. Add scripts `health`, `replay`, `arms`, `evalset`, `attribution`.
- `benchmark/tests/test_{db,health,replay,attribution,extras,arms,evalset,units_file}.py`: CREATE or MODIFY.
- `benchmark/results/`: CREATE. Holds `evalsets/`, `recall-ledger.md` and `recall-p0-report.md` (Task 9).

---

### Task 1: Persist finding tags and run configuration

**Files:**
- Modify: `benchmark/benchmark/db.py` (`_SCHEMA` runs table, `_MIGRATIONS`, and a new `config_snapshot`)
- Modify: `benchmark/benchmark/main.py` (the `runs` INSERT)
- Test: `benchmark/tests/test_db.py`

**Interfaces:**
- Produces:
  - `config_snapshot(environ: Mapping[str, str], git_sha: str) -> str`: JSON with `git_sha` plus every
    `SKILLSPECTOR_*` and `MODEL_OVERRIDE` env var whose name contains none of `KEY`, `TOKEN`, `SECRET` or `PASSWORD`.
  - `runs.config_json TEXT`.
  - `issues.tags VARCHAR[]`, already implemented.

- [ ] **Step 1: Write failing tests**

```python
def test_config_snapshot_keeps_flags_drops_secrets():
    snap = json.loads(config_snapshot(
        {"SKILLSPECTOR_EXA_X": "on", "SKILLSPECTOR_API_KEY": "s", "OPENAI_API_KEY": "s", "PATH": "/bin"}, "abc123"))
    assert snap == {"git_sha": "abc123", "env": {"SKILLSPECTOR_EXA_X": "on"}}

def test_open_db_adds_config_json_to_an_older_db(tmp_path): ...  # mirror the existing tags migration test
```

- [ ] **Step 2:** `cd benchmark && uv run pytest tests/test_db.py -q`. Expect 2 failures.
- [ ] **Step 3:** Implement. In `main.py`, take `git_sha` from `git rev-parse --short HEAD`, with a `-dirty` suffix
  when `git status --porcelain -- ../src` is non-empty. Write `config_snapshot(os.environ, sha)` into the `runs` row.
- [ ] **Step 4:** Tests pass. All of `uv run pytest -q` in `benchmark/` passes.
- [ ] **Step 5:** Commit `benchmark/benchmark/db.py benchmark/benchmark/main.py benchmark/tests/test_db.py` with the
  message `feat(benchmark): persist finding tags and run config`.
- [ ] **Step 6:** Commit the program documents, so every later branch carries them:
  `docs/superpowers/specs/2026-10-29-recall-improvement-program.md` and
  `docs/superpowers/plans/2026-10-29-recall-p{0,1,2,3,4,5,6,7}-*.md`, by explicit path. Use the message
  `docs: recall improvement program spec and plans P0-P7`.

### Task 2: `--units-file` for scanning an explicit unit list

**Files:**
- Modify: `benchmark/benchmark/main.py` (`run` options and `_run_benchmark` selection, near lines 200-250)
- Test: `benchmark/tests/test_units_file.py`

**Interfaces:**
- Produces:
  - CLI `--units-file PATH`: one `unit_path` per line; `#` comments and blank lines are ignored.
  - It works with `DATASET_PATH` or with `--from-run`, and filters the selected units to those listed.
  - `read_units_file(path) -> list[str]`.

- [ ] **Step 1: Write failing tests.**
  - `test_read_units_file_ignores_comments_and_blanks`.
  - `test_units_file_reports_missing`: build a fake discover list of 3 units and a file naming 2 of them plus 1
    absent. Assert 2 selected and that the printed line contains `1 not found`. Factor the selection into a pure
    helper `select_units(units, wanted) -> tuple[list[Unit], int]` so it is testable without scanning.
- [ ] **Step 2:** Run. Expect failures.
- [ ] **Step 3:** Implement. The selection keeps file order. `--failures-only` combined with `--units-file` is an
  error, so the semantics stay simple.
- [ ] **Step 4:** Tests pass.
- [ ] **Step 5:** Commit with the message `feat(benchmark): scan an explicit unit list with --units-file`.

### Task 3: Run-health gate

**Files:**
- Create: `benchmark/benchmark/health.py`
- Modify: `benchmark/pyproject.toml` (add `health = "benchmark.health:main"`)
- Test: `benchmark/tests/test_health.py`

**Interfaces:**
- Produces:
  - `check_health(con, run_id: str) -> list[str]`: an empty list means healthy. Each string names a failed check and
    its value.
  - CLI `health DB RUN`: prints the problems and exits 1 when there are any, 0 when healthy.

- [ ] **Step 1: Write failing tests.** Seed in-memory DBs (reuse `_fresh_db` from `test_db.py`):
  - `test_health_flags_llm_run_without_semantic_rules`: `use_llm=True`, 20 units, issues only `SC1`. Expect a
    problem containing `no SSD-/SDI-/SQP- issues`.
  - `test_health_flags_dropped_llm_calls`: 2 of 20 scans with `llm_calls_succeeded < llm_calls_attempted`. Expect
    a problem containing `10.0%`.
  - `test_health_ok`: a healthy fixture returns `[]`.
  - `test_health_static_run_skips_llm_checks`: `use_llm=False` with no semantic rules returns `[]`.
- [ ] **Step 2:** Run. Expect failures.
- [ ] **Step 3:** Implement the four thresholds from Global Constraints.
- [ ] **Step 4:** Tests pass. Also run `uv run health results/../malskillbench_agentguard_seed.duckdb 113b02ab497b`
  and expect exit 0.
- [ ] **Step 5:** Commit with the message `feat(benchmark): health gate for poisoned or degraded runs`.

### Task 4: Offline policy replay

Replay recomputes a run's verdicts under a different scoring policy from its stored issues and components, and
writes the result as a **synthetic run** in the same DB, so `report` and `arms` work on it unchanged. That is how
later plans quantify scoring changes from existing test results.

**Files:**
- Create: `benchmark/benchmark/replay.py`
- Modify: `benchmark/pyproject.toml` (add `replay = "benchmark.replay:main"`)
- Test: `benchmark/tests/test_replay.py`

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) class Policy`, with fields:
    - `threshold: int = 51`;
    - `gate_rules: tuple[str, ...] = ()`;
    - `gate_min_severity: str = "HIGH"`;
    - `gate_mode: Literal["any", "confirmed"] = "any"`;
    - `doc_medium_cap: int | None = None`.
  - `rescore(findings: list[dict], executable_files: set[str], policy: Policy) -> float`: the upstream additive
    formula. Per rule id: diminishing weights 1, 0.5, 0.25 with at most 3 per rule; findings sorted by
    `(rule_id, severity rank)`; confidence clamped to [0, 1] and ≤0 skipped; ×1.3 when the finding's file is
    executable. Then `doc_medium_cap`: when set, after the first N MEDIUM findings from non-executable files, further
    MEDIUM findings from non-executable files contribute 0.
  - `replay_run(con, src_run: str, policy: Policy, description: str) -> str`: returns the new run id.
    - New score = stored `risk_score` + (`rescore(policy)` − `rescore(Policy())`), clamped to 0-100. This delta method
      keeps unaffected units exact; plain recomputation matches the stored score for only 95.8% of units.
    - Predicted malicious = new score ≥ `policy.threshold`, OR a gate hit. A gate hit is any finding whose `rule_id`
      is in `gate_rules` or matches a prefix entry ending in `-`, with severity rank ≥ `gate_min_severity`. In
      `confirmed` mode the finding must also not be tagged `llm-unconfirmed`.
    - It copies the `units`, `issues` and `components` rows. It writes `classifications` (status `Replay`, copying `run_time` and the
      `llm_calls_*` columns from the source, so `health` and the timing sections still mean something) and a
      `runs` row whose `config_json` records `{"replay_of": src_run, "policy": asdict(policy)}`.
  - CLI `replay DB RUN --policy JSON --description TEXT`: prints the new run id and a one-line confusion summary.

- [ ] **Step 1: Write failing tests.**
  - `test_rescore_matches_upstream_formula`: two HIGH SSD-1 at confidence 1.0 score 25 + 12.5 = 37.5; a CRITICAL in
    an executable file at confidence 0.8 scores 52.0.
  - `test_gate_blocks_on_rule_prefix`: `gate_rules=("SSD-",)`, one SSD-3 HIGH, stored score 25 → predicted
    malicious.
  - `test_replay_confirmed_gate_requires_tags`: in `confirmed` mode, an `llm-unconfirmed` SSD-1 HIGH does not gate.
    When the source run's tags are all NULL, `replay_run` raises `SystemExit` naming the missing tags.
  - `test_doc_medium_cap`: 5 MEDIUM findings in `ref.md` with cap 2 contribute only the first 2.
  - `test_replay_identity_policy_reproduces_verdicts`: `Policy()` reproduces the source run's verdicts exactly,
    because of the delta method.
  - `test_replay_fidelity_on_seed_db`: skip if the seed DB is absent. On `113b02ab497b`, the `Policy()` replay has
    identical TP/FP/TN/FN.
- [ ] **Step 2:** Run. Expect failures.
- [ ] **Step 3:** Implement. The synthetic run id is a fresh `uuid4().hex[:12]`.
- [ ] **Step 4:** Tests pass. Then reproduce the review's number:
  `uv run replay malskillbench_agentguard_seed.duckdb 113b02ab497b --policy '{"gate_rules":["SSD-","P2"]}' --description tmp`
  must print TP=4748 FP=376 (+210/+24). Delete that synthetic run afterwards with `uv run remove-run ... --yes`.
- [ ] **Step 5:** Commit with the message `feat(benchmark): replay scoring policies over stored findings`.

### Task 5: SkillHarm injected-file attribution data

SkillHarm's own metric counts a detection only when it points at the injected payload, so this task records, for
each malicious SkillHarm unit, which files are the injection.

**Files:**
- Create: `benchmark/benchmark/attribution.py`
- Modify: `benchmark/pyproject.toml` (add `attribution = "benchmark.attribution:main"`)
- Test: `benchmark/tests/test_attribution.py`
- Output (not committed; lives with the other label files):
  `/Users/will/workspace/MalSkillBench/Dataset/Skills/_skillharm_injected.jsonl`. Add a short section documenting it
  to `_BOUNDARY_LABELS.md` in the same directory.

**Interfaces:**
- Produces:
  - `injected_files(unit_dir: Path, clean_dirs: list[Path], target_path: str | None) -> tuple[list[str], str]`. It
    returns `(relative paths, method)`, where method is `"diff"` or `"target_path"`.
    - Diff: the files whose relative path is absent from, or has different bytes in, the best clean counterpart. The
      best counterpart is the clean dir with the fewest differing files.
    - Clean counterparts are the `benign/<skill>__skillharm-clean-*` dirs that share the unit's `<skill>` prefix
      (before `__`).
    - Fallback when there is no counterpart: `target_path` with its leading `environment/skills/<skill>/` stripped.
  - CLI `attribution DATASET_DIR`: writes `_skillharm_injected.jsonl` with rows `{unit_path, files, method}` for
    every malicious SkillHarm unit.

- [ ] **Step 1: Write failing tests.**
  - `test_injected_files_diff`: build tmp dirs. The clean dir has `SKILL.md` and `a.py`. The unit has a changed
    `SKILL.md`, the same `a.py`, and a new `runbook.pdf`. Expect `(["SKILL.md", "runbook.pdf"], "diff")`.
  - `test_injected_files_picks_closest_clean`.
  - `test_injected_files_fallback`: no clean dirs, `target_path="environment/skills/pdf/SKILL.md"` → `(["SKILL.md"],
    "target_path")`.
- [ ] **Step 2:** Run. Expect failures.
- [ ] **Step 3:** Implement. Compare by `hashlib.sha1` of the bytes.
- [ ] **Step 4:** Tests pass. Run `uv run attribution /Users/will/workspace/MalSkillBench/Dataset`. Check that it
  writes one row per malicious SkillHarm unit (890 expected, from the features file; print the count), and that every
  `redirect_to_new_pdf` unit's file list contains a `.pdf`.
- [ ] **Step 5:** Commit the code and tests with the message `feat(benchmark): derive SkillHarm injected files`.
  The JSONL lives outside the repo.

### Task 6: Report extras

**Files:**
- Create: `benchmark/benchmark/report/extras.py`
- Modify: `benchmark/benchmark/report/__init__.py`, `render.py`, `templates/report.md.j2`,
  `templates/summary.md.j2`, and `benchmark/benchmark/main.py` (`report` gets `--split-file`)
- Test: `benchmark/tests/test_extras.py`

**Interfaces:**
- Consumes: `check_health(con, run_id)` from Task 3, and the label files from the spec's paths.
- Produces: `load_extras(con, run_id: str, split_file: Path | None) -> Extras`, a dataclass with these sections:
  - `health: list[str]`.
  - `stb_split: list[Breakdown]`: recall with keys `SkillTrustBench` and `non-STB`.
  - `validity_tiers: list[Breakdown] | None`: annotated malicious units only, keyed `working` (CORRECT), `intent`
    (BROKEN, UNVERIFIABLE) or `not_malicious` (WEAK, MISLABELED). Raw counts, rendered with a note that it covers
    the 412 annotated units, unweighted.
  - `skillharm_attributed: AttributedRecall | None`, with fields `units`, `verdict_tp`, `attributed_tp`, `recall`
    and `attributed_recall`. A verdict TP counts as attributed when ≥1 issue of severity MEDIUM or above has `file`
    in the unit's injected files.
  - `fp_by_size: list[Breakdown]`: benign units bucketed by component count, `1` / `2-5` / `6-20` / `21+`.
  - `splits: list[Breakdown] | None`: from a TSV `unit_path<TAB>split` when `--split-file` is given.
  - `labels_found: bool`.
- In comparison mode, each section shows base and head side by side with a delta, reusing `_merge_dim`.

- [ ] **Step 1: Write failing tests.**
  - `test_extras_stb_split`.
  - `test_extras_attributed_recall`: two SkillHarm TPs, one with a HIGH issue on its injected file. Expect
    `attributed_recall == 0.5 * recall`.
  - `test_extras_missing_labels`: point `dataset_path` at an empty dir. Expect `labels_found=False`, and the rendered
    markdown contains `labels not found`.
  - `test_report_renders_extras_sections`: the rendered summary contains the headings `Health`,
    `SkillTrustBench vs rest`, `Label-validity tiers`, `SkillHarm attributed recall` and `Benign FP rate by package
    size`.
- [ ] **Step 2:** Run. Expect failures.
- [ ] **Step 3:** Implement. Read the label files with DuckDB `read_json_auto` from
  `<runs.dataset_path>/Skills/`. Healthy runs render "Health: OK".
- [ ] **Step 4:** Tests pass. Render the original baseline with
  `uv run report malskillbench_agentguard_seed.duckdb 113b02ab497b`, and check the extras against the review's
  numbers:
  - STB recall 0.902;
  - non-STB recall 0.427 (1,113 TP of 2,606);
  - benign 21+ FP rate 48.8%.
- [ ] **Step 5:** Commit with the message `feat(benchmark): report health, STB split, validity tiers, attribution`.

### Task 7: Same-day arm comparison

**Files:**
- Create: `benchmark/benchmark/arms.py`
- Modify: `benchmark/pyproject.toml` (add `arms = "benchmark.arms:main"`)
- Test: `benchmark/tests/test_arms.py`

**Interfaces:**
- Produces:
  - `compare_arms(con, control: list[str], treatment: list[str], kind: Literal["recall", "fp"] = "recall") -> ArmsResult`.
    The fields are mean TP/FP/FN/TN per arm, `n_tp`, `n_fp`, `d_tp`, `d_fp`, `attributed_recall` per arm, `verdict`
    (`PROMISING` or `REJECT`), `reasons: list[str]` and `replicates: tuple[int, int]`.
  - The verdict rules are copied verbatim from the spec's "Decision rules":
    - recall: `d_tp ≥ 2·n_tp` and `d_fp ≤ max(n_fp, d_tp/8)` and every treatment run healthy;
    - fp: `−d_fp ≥ 2·n_fp` and `−d_tp ≤ −d_fp/2` and attributed recall not lower.
  - All runs must cover the same unit set, otherwise `SystemExit`.
  - CLI `arms DB --control r1,r2 --treatment t1,t2 [--kind recall|fp] [-o FILE]`: prints a markdown table plus
    `VERDICT: <verdict>`.

- [ ] **Step 1: Write failing tests.**
  - `test_arms_promising`: control TP 100/102, treatment TP 112/114, FP flat → PROMISING, `n_tp=3`, `d_tp=12`.
  - `test_arms_reject_on_fp_cost`: `d_tp=12` with `d_fp=5` → REJECT, with a reason mentioning `8:1`.
  - `test_arms_single_replicate`: one control run → floors 3/2 are used, and the output says `1 replicate`.
  - `test_arms_rejects_mismatched_units`.
- [ ] **Step 2:** Run. Expect failures.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Tests pass.
- [ ] **Step 5:** Commit with the message `feat(benchmark): same-day arm comparison with pre-registered verdicts`.

### Task 8: Evaluation sets

**Files:**
- Create: `benchmark/benchmark/evalset.py`
- Modify: `benchmark/pyproject.toml` (add `evalset = "benchmark.evalset:main"`)
- Test: `benchmark/tests/test_evalset.py`
- Output (committed):
  - `benchmark/results/evalsets/core-dev.txt`;
  - `benchmark/results/evalsets/splits.tsv`;
  - `benchmark/results/evalsets/README.md`.

**Interfaces:**
- Produces:
  - `build_core(con, run_id: str, labels_path: Path, seed: int = 29) -> list[str]`, the union of:
    - every annotated malicious unit in `_boundary_labels.jsonl` (412);
    - every FP of the run;
    - 600 TNs sampled with `random.Random(seed)`, stratified proportionally by corpus × package-size bucket, with the
      `6-20` and `21+` buckets oversampled 3× because that is where FPs live.
  - `build_focus(con, run_id: str, sql_where: str, cap: int | None, seed: int = 29) -> list[str]`:
    - query: `SELECT e.unit_path FROM evaluation e LEFT JOIN read_json_auto('<Skills>/_boundary_features.jsonl') bf
      USING (unit_path) WHERE e.run_id = ? AND (<sql_where>)`;
    - `bf` columns are NULL for benign units;
    - when there are more matches than `cap`, sample deterministically with `random.Random(seed)`, keeping every
      malicious match before sampling benign ones.
  - `write_splits(all_units, dev_sets: list[list[str]], out: Path)`: a TSV labelling each unit `dev` when it is in
    any dev set, otherwise `holdout`.
  - CLI `evalset core OUT --db DB --run RUN`, `evalset focus OUT --db DB --run RUN --where SQL [--cap N]`, and
    `evalset splits OUT --db DB --run RUN DEVFILE...`.

- [ ] **Step 1: Write failing tests.**
  - `test_build_core_is_deterministic`: same seed gives the same list.
  - `test_build_core_includes_all_fps_and_annotated`.
  - `test_build_focus_sql_and_cap`.
  - `test_write_splits_marks_holdout`.
- [ ] **Step 2:** Run. Expect failures.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Tests pass. Generate `core-dev.txt` from `113b02ab497b` in the seed DB and print its size (about
  1,364). Generate `splits.tsv` from core only; later plans regenerate it with their focus sets. In `README.md`, write
  one line per file: how it was built (command plus seed), and that the selection was made from the original
  baseline's outcomes.
- [ ] **Step 5:** Commit the code, tests and `benchmark/results/evalsets/*` with the message
  `feat(benchmark): deterministic evaluation sets`.

### Task 9: Program DB, baseline-v2 full run, and the P0 overview

**Files:**
- Create: `benchmark/results/recall.duckdb` (not committed), `benchmark/results/recall-ledger.md` and
  `benchmark/results/recall-p0-report.md` (both committed)

- [ ] **Step 1:** `cp benchmark/malskillbench_agentguard_seed.duckdb benchmark/results/recall.duckdb`.
- [ ] **Step 2: Preflight** (spec autonomy rule 6). Run `aws sts get-caller-identity`. Then run one known-malicious
  unit:
  ```bash
  printf 'Skills/malware/pptx__skillharm-fpp-a4db25e26d\n' > /tmp/one.txt
  uv run benchmark /Users/will/workspace/MalSkillBench/Dataset -o results/recall.duckdb --units-file /tmp/one.txt \
    --auth-wait-seconds 0 --description "p0 preflight"
  ```
  Check that the run has ≥1 `SSD-`/`SDI-`/`SQP-` issue (`health` needs more units to be meaningful). On failure,
  follow autonomy rule 5.
- [ ] **Step 3: baseline-v2 full run** with default flags:
  ```bash
  uv run benchmark /Users/will/workspace/MalSkillBench/Dataset -o results/recall.duckdb --auth-wait-seconds 0 \
    --description "baseline-v2: P0 tree, tags recorded"
  uv run health results/recall.duckdb <run>
  ```
  If the scan aborts, resume with `--run-id <run>`. If `health` fails, re-run once; if it fails again, follow
  autonomy rule 5.
- [ ] **Step 4: Overview.**
  ```bash
  uv run report results/recall.duckdb <baseline_v2> --base 113b02ab497b \
    --label baseline-v2 --base-label original -o results/recall-p0-report.md
  ```
  P0 changes no classifier behaviour, so the delta between these two runs measures drift plus nondeterminism. Prepend
  a short paragraph to the report:
  - recall and precision delta;
  - fixed and regressed unit counts, labelled as noise;
  - the share of SSD HIGH findings tagged `llm-unconfirmed`, from
    `SELECT avg(list_contains(tags,'llm-unconfirmed')::int) FROM issues WHERE run_id=? AND rule_id LIKE 'SSD-%' AND severity IN ('HIGH','CRITICAL')`.
- [ ] **Step 5:** Create `recall-ledger.md` with the column header from the spec, rows for the preflight and
  baseline-v2 runs, and a `## P0` decision block. The block records the `baseline-v2` run id that every later plan
  uses as its replay source and cumulative base.
- [ ] **Step 6:** Commit `benchmark/results/recall-ledger.md benchmark/results/recall-p0-report.md` with the message
  `docs(benchmark): baseline-v2 run and P0 overview`.
