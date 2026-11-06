# Sequential Futility Screen Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop a dev-arm candidate early once it is clearly going to be rejected. The screen scans the dev set in
stratified batches and judges each batch, so failing candidates cost a fraction of two full replicates. This matters
most when iterating on prompt phrasing.

**Architecture:**
- A new benchmark CLI command, `uv run screen`, in `benchmark/benchmark/screen.py`. It orchestrates scans by calling the
  existing `benchmark` command as a subprocess, one run per batch and arm, so scan semantics stay in one place.
- It splits a units file into stratified batches of about 150 units, never repeating a unit. After each batch it pairs
  treatment with same-day control on the same units and applies a pre-registered futility boundary.
- It stops only to reject. Candidates that pass the screen go on to the spec's standard dev verdict, and the screen's
  batch runs count as treatment replicate 1.
- `arms` learns to treat `a+b+c` as one replicate made of disjoint runs.

**Tech Stack:** Python 3.12, click, duckdb; the existing `benchmark/` uv project. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-29-recall-improvement-program.md`. Task 3 amends its "Decision rules" section.
The method was requested by the user on 2026-11-04: stratified batches, no repeated units, stop early only for
failure.

## Global Constraints

- Harness changes go only in `benchmark/` (code in `benchmark/benchmark/`, tests in `benchmark/tests/`). Classifier
  code (`src/`) is untouched. No new dependencies.
- Never commit or touch `benchmark/benchmark/dataset_handler/malskillbench.py`, `benchmark/uv.lock`,
  `benchmark/tests/test_external_labels.py`, or untracked `.md` files in `benchmark/`. Stage by explicit path only.
  Never push. Never use `--no-verify`. Never revert files you did not change.
- Tests: from `benchmark/`, run `uv run pytest -q`. Lint: `uv run ruff check <files> && uv run ruff format --check <files>`.
- Pre-registered constants, used verbatim:
  - batch size 150;
  - seed 29;
  - FP weight 8 (the spec's 8:1 rule);
  - minimum batches before any stop: 3;
  - z = 2.8 (one-sided per look, about 0.26%; over about 16 looks the false-futility rate stays below 5%);
  - allowance `16·n/N`, which is the spec's `N_FP ≥ 2` floor (8·2) scaled to the n of N units judged so far.
- Per-unit paired score:
  - `d_i = (tp_t − tp_c) − 8·(fp_t − fp_c)`, where `tp`/`fp` are the unit's TP/FP indicators. With several runs on a
    side, they are means over that side's runs that contain the unit.
  - A unit whose outcome is ERROR in any run on either side is excluded from `d` and counted separately.
- Boundary:
  - `D = Σ d_i` over the n judged units so far.
  - `SE = sd(d, ddof=1)·sqrt(n)`, or 0 when n < 2.
  - Stop (FUTILE) iff the batch count is ≥ 3 and `D + 2.8·SE < −16·n/N`.
  - Never stop for success.
- FP-reducing candidates (`--kind fp`, mirroring `arms --kind`). The spec's rule needs `−ΔTP ≤ (−ΔFP)/2`, that is
  `2·ΔTP − ΔFP ≥ 0`.
  - The per-unit score is `d_i = 2·(tp_t − tp_c) − (fp_t − fp_c)`, and the allowance is 0.
  - Stop iff the batch count is ≥ 3 and `D + 2.8·SE < 0`.
  - The default is `--kind recall`.
- Stratum key per unit, from a reference run's `evaluation` row: `'benign'` when not malicious, else
  `coalesce(behavior, corpus, 'unknown')`. A unit absent from the reference run gets `'unknown'`.

## Review Focus

1. **A batch scan that hangs.** P2 and P3 each had one run stall at its last unit. The screen kills a scan whose output
   has not grown for `--stall-seconds` (default 1200) and resumes it with `--run-id`, at most twice. After that, the
   screen stops with an error naming the run. Test: `test_stall_kills_and_resumes`.
2. **Reused control runs that do not cover a batch's units** (a different units file, or a run from another day). The
   screen refuses with a message listing the uncovered count. It warns, but does not refuse, when the control's date or
   git sha differs from the treatment's. Test: `test_control_runs_must_cover_batch`.
3. **ERROR outcomes.** A unit that errored on either side is excluded from `D`, and the per-batch table reports it.
   Test: `test_judge_excludes_errors`.
4. **An `arms` union whose members overlap** (one unit in two runs of one replicate). Refused. Test:
   `test_union_overlap_refused`.
5. **A clearly positive candidate.** It must never stop, however early. Test: `test_never_stops_on_positive`.

---

### Task 1: `arms` replicate unions

**Files:**
- Modify: `benchmark/benchmark/arms.py`
- Test: `benchmark/tests/test_arms.py` (add tests)

**Interfaces:**
- Produces:
  - `--control` and `--treatment` accept comma-separated replicates. Each replicate is one run id or several joined by
    `+`, for example `a+b+c,d`, which is two replicates.
  - A union replicate's TP/FP/FN/TN are the sums over its member runs.
  - Its health passes only if every member passes.
  - Its provenance rows list every member.
  - Overlapping members raise `click.UsageError` naming the shared unit count.
  - `parse_replicates(spec: str) -> list[list[str]]` is exported for Task 2.

- [ ] **Step 1:** Write failing tests, using the existing `test_arms.py` fixtures to build a DB:
  - `test_parse_replicates` (`"a+b,c"` gives `[["a","b"],["c"]]`);
  - `test_union_counts_sum`;
  - `test_union_health_requires_all_members`;
  - `test_union_overlap_refused`.
- [ ] **Step 2:** Run `uv run pytest -q tests/test_arms.py`. Expect the new tests to fail.
- [ ] **Step 3:** Implement. Single-run replicates must behave exactly as before; the existing tests stay green.
- [ ] **Step 4:** Run `uv run pytest -q`. All pass.
- [ ] **Step 5:** Commit with the message `feat(benchmark): arms accepts multi-run replicates (a+b)`.

### Task 2: `screen` command

**Files:**
- Create: `benchmark/benchmark/screen.py`
- Modify: `benchmark/pyproject.toml` (`[project.scripts]` gains `screen = "benchmark.screen:main"`)
- Test: `benchmark/tests/test_screen.py`

**Interfaces:**
- Consumes: `parse_replicates` (Task 1); the `benchmark` CLI as a subprocess, whose stdout contains
  `starting run <id>` and `wrote <db> (run id <id>)`.
- Produces:
  - `strata_for(con, ref_run: str, units: list[str]) -> dict[str, str]`.
  - `build_batches(units: list[str], strata: dict[str, str], batch_size: int = 150, seed: int = 29) -> list[list[str]]`.
    - The batch count is `ceil(len(units)/batch_size)`.
    - Within each stratum (strata in sorted key order), sort the units, then shuffle them with one shared
      `random.Random(seed)`. Concatenate the strata and deal unit `i` to batch `i % B`, so every batch has the same
      composition.
  - `unit_outcomes(con, run_ids: list[str], units: list[str]) -> dict[str, tuple[float, float, bool]]`, mapping each
    unit to `(tp, fp, errored)`. A unit no run covers is absent.
  - `@dataclass Look(batch, n, n_errors, d_tp, d_fp, D, se, ucb, allowance, stop)` and
    `judge(control, treatment, units, n_total, z=2.8, batch=…, min_batches=3) -> Look`. These are exactly the Global
    Constraints formulas.
  - The CLI `screen DATASET_PATH --db PATH --units-file PATH --ref-run ID --label TEXT` takes these options:
    - `[--kind recall|fp]` (default `recall`), which `judge` receives as `kind=`;
    - `[--treatment-env K=V ...]` and `[--control-env K=V ...]`;
    - `[--control-runs SPEC]`, which reuses existing same-day control runs and skips control scans;
    - `[--batch-size 150] [--seed 29] [--z 2.8] [--min-batches 3]`;
    - `[--stall-seconds 1200] [--auth-wait-seconds 0]`;
    - `[--out-dir results/screens]`;
    - `[--simulate --treatment-runs SPEC]`.
  - **Normal mode.**
    - Writes the batch files and `manifest.json` under `<out-dir>/<label-slug>/`. The manifest holds the batches,
      each batch's control and treatment run ids, and every `Look`. It is rewritten after each batch, so a crash
      leaves a resumable record.
    - For each batch it scans control (unless `--control-runs`), then treatment, by running `uv run benchmark
      DATASET_PATH -o DB --units-file <batch file> --auth-wait-seconds N --description "<label> <arm> b<k>"` with the
      env additions.
    - It judges after each batch and prints a markdown table, one row per look.
    - It ends with `SCREEN: FUTILE at batch k (n units)` or `SCREEN: PASSED (N units)`. The last line is
      `arms: --control <spec> --treatment <spec>`, using `+`-joined runs, ready for the standard verdict.
  - **`--simulate`.** It runs no scans. It judges existing full runs (`--control-runs`, `--treatment-runs`) batch by
    batch, using the same batches, and prints the table and the stop point.

- [ ] **Step 1:** Write failing tests. Subprocess scans are replaced by a fake `benchmark` command: a small script
  passed through an internal option or monkeypatched runner, which writes rows into a temp DuckDB and prints the
  expected lines.
  - `test_build_batches_deterministic_and_proportional`: same seed gives the same batches; strata counts differ by at
    most 1 between batches; no unit repeats.
  - `test_strata_benign_behavior_corpus_unknown`.
  - `test_judge_formula`: a hand-computed 6-unit example, with D, SE and the stop decision asserted, for both
    `kind="recall"` and `kind="fp"`.
  - `test_judge_excludes_errors`.
  - `test_never_stops_on_positive`.
  - `test_stops_on_clear_futility_after_min_batches`, which also checks that it does not stop before batch 3.
  - `test_control_runs_must_cover_batch`.
  - `test_stall_kills_and_resumes`: the fake command sleeps without output, `--stall-seconds 1`, and the test asserts
    a second invocation carries `--run-id`.
  - `test_manifest_written_each_batch`.
  - `test_simulate_matches_full_runs`.
- [ ] **Step 2:** Run `uv run pytest -q tests/test_screen.py`. Expect failures.
- [ ] **Step 3:** Implement. Stream the subprocess stdout to a per-scan log file under the screen directory. The
  stall check uses that log's size, because the DB is locked by the writer for the whole scan and cannot be polled.
- [ ] **Step 4:** Run `uv run pytest -q`. All pass. Lint is clean.
- [ ] **Step 5: Validation on real data** (simulate only, no LLM calls). From `benchmark/`:
  - `uv run screen <Dataset> --db results/recall.duckdb --units-file results/evalsets/p3-dev.txt --ref-run e16e394f65c3 --label p3-b1-sim --simulate --control-runs bfcbcbe585e5,2e6e81859349 --treatment-runs a9949fa84c95,2a94f96eb7c8`
    (P3 B1, whose full verdict was REJECT on FP cost);
  - the same with `--treatment-runs bfcbcbe585e5 --control-runs 2e6e81859349` (control against control, a null
    candidate: it must not stop);
  - `uv run screen <Dataset> --db results/recall.duckdb --units-file results/evalsets/p4-dev.txt --ref-run e16e394f65c3 --label p4-a-sim --simulate --control-runs 54ce3a6bbe59,01d373aebd37 --treatment-runs daed644651be,a753a1ba2c6c`.

  Put the three tables (stop batch and units scanned) in the report.
- [ ] **Step 6:** Commit with the message `feat(benchmark): screen command for sequential futility screening`.

### Task 3: Spec rule and plan adoption

**Files:**
- Modify: `docs/superpowers/specs/2026-10-29-recall-improvement-program.md` (the "Decision rules" section)
- Modify: `docs/superpowers/plans/2026-10-29-recall-p4-necessity-audit.md`,
  `docs/superpowers/plans/2026-10-29-recall-p5-*.md`, `...-p6-*.md` and `...-p7-*.md` (their dev-arm steps)
- Modify: `benchmark/README.md` (document `screen` next to `arms`)

- [ ] **Step 1:** In the spec, after the iteration-budget paragraph, add a subsection **"Sequential futility screen
  (pre-registered 2026-11-04)"** stating:
  - every Global Constraints formula and constant of this plan, verbatim;
  - a candidate is screened with `uv run screen` before its full dev replicates;
  - a FUTILE screen is that candidate's dev verdict, REJECT, and it still counts toward the 5-candidate budget;
  - a PASSED screen is followed by the standard dev verdict. The screen's union of treatment batch runs is treatment
    replicate 1, and its control is control replicate 1 (or the reused control runs). One more full replicate of each
    arm is run the same day, then `uv run arms` judges;
  - control runs are reused only from the same day, tree and dev set;
  - the screen never accepts.
- [ ] **Step 2:** In each of P4 (the remaining arms: B, B+gate if ever enabled, the prompt revision) and P5, P6 and P7,
  amend the dev-arms step so each candidate runs `uv run screen` first, reusing the day's control runs, with a
  one-line pointer to the spec subsection. Do this especially for prompt-iteration candidates.
  - Use `--kind fp` for candidates the plan judges as FP-reducing.
  - Where a plan judges its candidates only offline (with `replay`, no live scans), add a one-line note that the screen
    does not apply, instead of a step.

  Change nothing else in those plans.
- [ ] **Step 3:** Document `screen` (purpose, options, outputs, `--simulate`) in `benchmark/README.md`.
- [ ] **Step 4:** Commit with the message `docs: pre-register sequential futility screen and adopt it in P4-P7`.
