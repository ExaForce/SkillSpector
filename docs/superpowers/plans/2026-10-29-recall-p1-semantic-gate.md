# P1 (O1): Semantic-Finding Gate and Documentation-Finding Cap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Block a skill when a strong semantic finding (`SSD-1..4`, `P2`) is at HIGH or above, even if the additive
score stays below 51. Optionally, also cap how many MEDIUM findings from non-executable files count toward the score.
Each change is chosen offline from existing results, confirmed live, and accepted or rejected by the spec's rules.

**Architecture:**
1. Choose the policies offline with `uv run replay` (from P0) over the `baseline-v2` run's stored findings and tags.
2. Implement them as one fork-local runtime patch that intercepts `skillspector.nodes.report._compute_risk_score`.
3. Confirm with same-day arms on the dev set, then full runs.

The classifier patch and `benchmark/replay.py` must implement identical semantics; a parity test enforces that.

**Tech Stack:** Python 3.12+, `src/skillspector/exaforce/` patch framework, pytest, and the benchmark harness from P0.

**Spec:** `docs/superpowers/specs/2026-10-29-recall-improvement-program.md`. Background: O1 and B1 in
`benchmark/recall-boundaries.md`.

## Global Constraints

- Spec rules apply: autonomy, flags, protocol, decision rules.
- Branch: `exaforce/recall-p1-semantic-gate`, from P0's final commit.
- Read the `baseline-v2` run id from the `## P0` block of `benchmark/results/recall-ledger.md`, and
  `export BV2=<id>`. Every later plan does the same.
- Flags, all read per call:
  - `SKILLSPECTOR_EXA_SEMANTIC_GATE`: `off` (default), `any` or `confirmed`.
  - `SKILLSPECTOR_EXA_GATE_RULES`: default `SSD-1,SSD-2,SSD-3,SSD-4,P2`. Comma-separated; an entry ending in `-` is a
    prefix. Later plans (P2-P5) may extend this default.
  - `SKILLSPECTOR_EXA_GATE_MIN_SEVERITY`: default `HIGH`.
  - `SKILLSPECTOR_EXA_DOC_MEDIUM_CAP`: unset means off; an integer N means only the first N MEDIUM findings from
    non-executable files count.
- Gate semantics, identical in classifier and replay:
  - A hit is a finding whose `rule_id` matches an entry and whose severity rank is at least the minimum (CRITICAL
    above HIGH above MEDIUM above LOW).
  - In `confirmed` mode, a finding whose tags include `llm-unconfirmed` does not hit.
  - On a hit the result is `(max(score, 51), band(max(score, 51)), "DO_NOT_INSTALL")`.
- Cap semantics: sort MEDIUM findings from files whose component metadata says `executable: False` by
  `(rule_id, file, start_line)`, keep the first N, and drop the rest from the list passed to the upstream scorer.
  Reported findings are unchanged.
- Plan minimum for acceptance: +0.5 recall points. Plan-specific guard: SkillHarm attributed recall must not drop.

## Review Focus

1. **Findings whose `tags` is empty or missing.** `confirmed` mode treats them as confirmed, because static findings
   never get the tag. This matches upstream, where only floor-kept findings are tagged. Test:
   `test_confirmed_mode_untagged_counts`.
2. **The score is already ≥ 51 when the gate hits.** The score is unchanged, not lowered. Test:
   `test_gate_keeps_higher_score`.
3. **A malformed `SKILLSPECTOR_EXA_GATE_RULES`** (empty string, or spaces) means no rules, which means no gate. Do not
   crash. Test: `test_gate_rules_blank`.
4. **`component_metadata` is None**, so executability is unknown. The cap treats every file as executable and caps
   nothing. Test: `test_cap_without_metadata_is_noop`.
5. **Upstream renames `_compute_risk_score` or its parameters.** Raise `PatchDriftError` at import. Test:
   `test_score_patch_drift`.

---

### Task 1: Choose policies offline from existing results

No classifier code. This task is the quantification from existing results that the spec requires.

**Files:**
- Create: `benchmark/results/recall-p1-offline.md`
- Modify: `benchmark/results/recall-ledger.md`

- [ ] **Step 1:** From `benchmark/`, replay the grid on `baseline-v2`. Each command prints a new run id; record each
  one.
  ```bash
  for mode in any confirmed; do
    uv run replay results/recall.duckdb $BV2 --description "p1 offline gate=$mode" \
      --policy "{\"gate_rules\":[\"SSD-1\",\"SSD-2\",\"SSD-3\",\"SSD-4\",\"P2\"],\"gate_mode\":\"$mode\"}"
  done
  for n in 2 3 5; do
    uv run replay results/recall.duckdb $BV2 --description "p1 offline cap=$n" --policy "{\"doc_medium_cap\":$n}"
  done
  ```
- [ ] **Step 2:** Run `uv run report results/recall.duckdb <synthetic> --base $BV2` for each synthetic run, and
  assemble `recall-p1-offline.md`. It needs a table of policy, ΔTP, ΔFP, recall, precision, SkillHarm attributed
  recall, and STB / non-STB recall. Include the corpus breakdown of the gate's added TPs (the review found 154 of 210
  in native wild and PI).
- [ ] **Step 3: Apply the selection rules** and write the decision block in the ledger.
  - Gate: among `any` and `confirmed`, keep the modes with `ΔTP ≥ 8·ΔFP` and `ΔTP ≥ 32` (+0.5 points of 6,403).
    Choose the one with the higher `ΔTP − 8·ΔFP`. If neither qualifies, set `GATE=none`.
  - Cap: keep the N values with `−ΔFP ≥ 10`, `−ΔTP ≤ −ΔFP/2`, and attributed SkillHarm recall not lower. Choose the
    largest `−ΔFP`. If none qualifies, set `CAP=none`.
  - Replay is deterministic, so there is no noise floor offline. The live arms in Task 4 provide it.
- [ ] **Step 4:** Commit `benchmark/results/recall-p1-offline.md benchmark/results/recall-ledger.md` with the message
  `docs(benchmark): P1 offline policy selection`.

If `GATE=none` and `CAP=none`, skip Tasks 2-4. Go to Task 5 and write a REJECTED overview from the offline results.

### Task 2: A patchlib helper that sees call arguments

**Files:**
- Modify: `src/skillspector/exaforce/_patchlib.py`
- Test: `tests/exaforce/test_patchlib.py`

**Interfaces:**
- Produces: `intercept_module_callable(module, attr, interceptor: Callable[[Callable, tuple, dict], object], *, expected_params: tuple[str, ...] = ()) -> None`.
  - It replaces the module global `attr` with a wrapper that calls `interceptor(original, args, kwargs)`.
  - It has the same drift guards and idempotence marker (`_exaforce_wrapped`) as `wrap_module_callable`.

- [ ] **Step 1:** Write failing tests:
  - `test_intercept_sees_args_and_can_replace_result`;
  - `test_intercept_is_idempotent`;
  - `test_intercept_drift_missing_param`.
- [ ] **Step 2:** `uv run pytest tests/exaforce/test_patchlib.py -q`. Expect failures.
- [ ] **Step 3:** Implement next to `wrap_module_callable`, sharing its guard code.
- [ ] **Step 4:** Tests pass.
- [ ] **Step 5:** Commit with the message `feat(exaforce): patchlib helper that intercepts call arguments`.

### Task 3: Score patch with gate and cap

**Files:**
- Create: `src/skillspector/exaforce/_score_patches.py`
- Modify: `src/skillspector/exaforce/__init__.py` (call `_score_patches.apply()` in `apply_patches`)
- Test: `tests/exaforce/test_score_patches.py` and `benchmark/tests/test_replay_parity.py`

**Interfaces:**
- Consumes: `intercept_module_callable` (Task 2); `report._compute_risk_score(findings, has_executable_scripts,
  component_metadata=None) -> tuple[int, str, str]`; and `report._RISK_SEVERITY_BANDS`.
- Produces:
  - `gate_hit(findings: list[Finding], rules: tuple[str, ...], min_severity: str, mode: str) -> bool`;
  - `cap_doc_mediums(findings, component_metadata, cap: int | None) -> list[Finding]`;
  - `apply() -> None`.

- [ ] **Step 1: Write failing tests** in `tests/exaforce/test_score_patches.py`, using `monkeypatch.setenv`:
  - `test_gate_off_is_identity`;
  - `test_gate_any_blocks_single_high_ssd`: one SSD-2 HIGH at confidence 0.9 → `(51, "HIGH", "DO_NOT_INSTALL")`;
  - `test_confirmed_mode_skips_unconfirmed`;
  - `test_confirmed_mode_untagged_counts`;
  - `test_gate_keeps_higher_score`;
  - `test_gate_rules_blank`;
  - `test_cap_drops_excess_doc_mediums`: 5 MEDIUM findings in a non-executable `.md`, cap 2 → score from 2 only;
  - `test_cap_without_metadata_is_noop`;
  - `test_score_patch_drift`: monkeypatch `_compute_risk_score` to a function with other parameter names → `apply()`
    raises `PatchDriftError`.
- [ ] **Step 2: Write the failing parity test** in `benchmark/tests/test_replay_parity.py`. Generate 200 random
  finding lists with `random.Random(1)`, mixing rules, severities, confidences, files and the
  `llm-unconfirmed` tag. Assert that `benchmark.replay` and the patched `_compute_risk_score` agree on the
  verdict for every list, for each of `Policy()`, the gate in both modes, and cap 3.
- [ ] **Step 3:** Run both test files. Expect failures.
- [ ] **Step 4:** Implement. Read the env vars on every call.
- [ ] **Step 5:** Run the tests until they pass, then run the full suites (`uv run pytest -q` at the root;
  `cd benchmark && uv run pytest -q`).
- [ ] **Step 6: End-to-end check on the final report.** The fork has shipped a patch that passed unit tests and did
  nothing in the report. Add `test_gate_reaches_report_node` to `tests/exaforce/test_score_patches.py`: call the
  `report` graph node (`skillspector.nodes.report.report`) with a minimal state holding one SSD-1 HIGH finding.
  Inspect the node for the keys it needs. Parse `report_body`, and assert `risk_assessment.recommendation ==
  "DO_NOT_INSTALL"` with the flag on and `"SAFE"`/`"CAUTION"` with it off.
- [ ] **Step 7:** Commit `src/skillspector/exaforce/_score_patches.py src/skillspector/exaforce/__init__.py
  tests/exaforce/test_score_patches.py benchmark/tests/test_replay_parity.py` with the message
  `feat(exaforce): flag-gated semantic block gate and doc-finding cap`.

### Task 4: Live confirmation on the dev set

**Files:**
- Create: `benchmark/results/evalsets/p1-dev.txt` (a copy of `core-dev.txt`; P1 needs no focus set)
- Modify: `benchmark/results/recall-ledger.md`

- [ ] **Step 1:** Preflight (spec rule 6).
- [ ] **Step 2:** Control ×2, then treatment ×2 for the chosen gate. For example:
  ```bash
  B="uv run benchmark /Users/will/workspace/MalSkillBench/Dataset -o results/recall.duckdb --units-file results/evalsets/p1-dev.txt --auth-wait-seconds 0"
  $B --description "p1 dev control r1"; $B --description "p1 dev control r2"
  SKILLSPECTOR_EXA_SEMANTIC_GATE=<mode> $B --description "p1 dev gate=<mode> r1"
  SKILLSPECTOR_EXA_SEMANTIC_GATE=<mode> $B --description "p1 dev gate=<mode> r2"
  uv run health results/recall.duckdb <each run>
  uv run arms results/recall.duckdb --control c1,c2 --treatment t1,t2 -o /tmp/p1-gate-arms.md
  ```
- [ ] **Step 3:** If `CAP` was chosen, run two cap treatment replicates against the same controls. Use
  `uv run arms ... --kind fp`. Gate and cap are judged separately (one change per comparison).
- [ ] **Step 4:** Append every run, and both verdicts with their arms tables, to the ledger. Any change that is not
  PROMISING is dropped from final acceptance.
- [ ] **Step 5:** Commit the ledger and `p1-dev.txt` with the message `docs(benchmark): P1 dev arms`.

### Task 5: Final acceptance, default flip, and overview

**Files:**
- Modify: `src/skillspector/exaforce/_score_patches.py` (the defaults, only if accepted)
- Create: `benchmark/results/recall-p1-report.md`
- Modify: `benchmark/results/recall-ledger.md`

- [ ] **Step 1:** Run the full control and the full treatment on the same day, with all PROMISING changes enabled
  together. Each is judged as a whole against control. Check `health` on both.
- [ ] **Step 2:** Apply the spec's final acceptance rule, plus the plan guard (attributed SkillHarm recall not lower).
  The holdout split comes from `results/evalsets/splits.tsv`.
- [ ] **Step 3:** If ACCEPTED, change the defaults to the accepted values, update the test that asserts the default,
  and re-run the tests. Commit with the message `feat(exaforce): enable semantic gate by default (P1 accepted)`.
- [ ] **Step 4: Overview.** Create the report with the spec's two `report` commands. Start it with a 5-line verdict:
  - ACCEPTED or REJECTED, with the flags;
  - Δrecall and Δprecision against same-day control;
  - offline-predicted against live Δ;
  - where the gain landed, by corpus;
  - the share of gate hits that were `llm-unconfirmed`.
- [ ] **Step 5:** Commit `benchmark/results/recall-p1-report.md benchmark/results/recall-ledger.md` with the message
  `docs(benchmark): P1 overview`.
