# P6 (O6): Re-Tune the Block Threshold Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** After P1-P5 have changed the score distribution, check whether a block threshold other than 51 gives
more recall at a pre-registered precision floor. Ship it behind a flag if it does.

**Architecture:** A threshold change is deterministic given a run's findings. So this plan replaces the usual
two-full-run acceptance with a **paired** comparison: one fresh full run under the current defaults, then
`uv run replay` with only the threshold changed. Same findings, so zero nondeterminism noise. That is the most exact
use of existing results available. The classifier side extends P1's `_score_patches.py` with a flag-gated threshold,
and a parity test keeps it identical to replay.

**Tech Stack:** Python 3.12+, the fork score patch, the P0 replay tool.

**Spec:** `docs/superpowers/specs/2026-10-29-recall-improvement-program.md`. Background: O6 in
`benchmark/recall-boundaries.md`.

## Global Constraints

- Spec rules apply, **except** final acceptance, which uses the paired replay described above. The spec's acceptance
  rule exists to control nondeterminism, and a paired replay has none. Branch `exaforce/recall-p6-threshold`, from
  P5's final commit.
- Flag: `SKILLSPECTOR_EXA_BLOCK_THRESHOLD`. Unset means 51, the upstream behaviour.
- Semantics (identical in the classifier and in `Policy.threshold`): predicted malicious when score ≥ T, or on a
  gate hit.
  - The severity band follows the upstream bands, except that a score in [T, 51) reports band `HIGH` and
    recommendation `DO_NOT_INSTALL`.
  - A score in [51, T) (when T > 51) reports band `MEDIUM` and recommendation `CAUTION`, unless the gate hit.
- Selection rule (pre-registered), over T ∈ {31, 33, ..., 61}:
  - keep the T values with precision ≥ 0.92 **and** precision ≥ (precision at 51) − 0.01 **and** FP ≤ 1.15 × FP at
    51;
  - among those, choose the T with the highest recall;
  - break ties toward 51.
- If the chosen T is 51, the verdict is REJECTED (no change). Still produce the overview.
- Plan minimum: +0.5 recall points, from the paired replay.

## Review Focus

1. **T > 51 combined with a gate hit.** It still blocks. Test: `test_threshold_above_51_gate_still_blocks`.
2. **T below 21** would put the MEDIUM band below the LOW band. Reject values < 21 with a `ValueError` at read time,
   and log it. Test: `test_threshold_out_of_range`.
3. **A non-integer flag value.** Ignore it and log a warning. Test: `test_threshold_non_integer_ignored`.
4. **Replay parity** for every T in the grid. Extend P1's `benchmark/tests/test_replay_parity.py`.
5. **Band text in the report** for a score in [T, 51) is `HIGH`, so downstream consumers keyed on the band agree with
   the recommendation. Test: `test_band_matches_recommendation`.

---

### Task 1: Paired offline sweep on a fresh full run

The sequential futility screen (`uv run screen`) does not apply here: candidates are judged offline with `replay`, not
with live scans.

- [ ] **Step 1:** Preflight. Then run one full run with the current defaults, which include every accepted change
  from P1-P5. Use `--description "p6 full control (current defaults)"`. Check `health`.
- [ ] **Step 2:** For each T in the grid, run `uv run replay results/recall.duckdb <run> --policy '{"threshold": T}'`,
  keeping the gate rules the defaults currently use, so the policy reflects the shipped gate. Run `uv run report`
  for each synthetic run against `<run>`.
- [ ] **Step 3:** Write `benchmark/results/recall-p6-offline.md`. It needs the sweep table (T, TP, FP, recall,
  precision, non-STB recall, benign 21+ FP rate) and the selection rule applied. Commit it with the ledger, with the
  message `docs(benchmark): P6 paired threshold sweep`.

If the chosen T is 51, skip to Task 3.

### Task 2: Flag-gated threshold in the score patch

**Files:**
- Modify: `src/skillspector/exaforce/_score_patches.py`
- Test: `tests/exaforce/test_score_patches.py` and `benchmark/tests/test_replay_parity.py`

**Interfaces:**
- Consumes: P1's interceptor around `report._compute_risk_score`, and `report._RISK_SEVERITY_BANDS`.
- Produces: `block_threshold() -> int`, which reads the flag (default 51, range 21-80). The intercepted result is
  re-banded per Global Constraints.

- [ ] **Step 1:** Write failing tests: the four unit tests from Review Focus, plus the parity extension.
- [ ] **Step 2:** Run. Expect failures.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Tests pass, then the full suite passes. Then make one live smoke check: with the flag set to the
  chosen T, scan a unit whose baseline score lies in [T, 51). Find one with a query over `<run>`. The report must say
  `DO_NOT_INSTALL`. Re-run until the LLM reproduces a score in range, at most 3 tries; otherwise record "not
  reproduced" (the unit tests cover the logic).
- [ ] **Step 5:** Commit with the message `feat(exaforce): flag-gated block threshold`.
- [ ] **Step 6:** Turn the default on at the chosen T, update the default test, and commit with the message
  `feat(exaforce): block threshold <T> by default (P6 accepted)`.

### Task 3: Overview

- [ ] **Step 1:** Write `benchmark/results/recall-p6-report.md` from `uv run report results/recall.duckdb <replay at T>
  --base <run>`, which is the paired claim, plus the cumulative report against `baseline-v2`. Start with a verdict
  block: T, Δrecall, Δprecision, ΔFP, and the note "paired replay: zero nondeterminism; findings identical".
- [ ] **Step 2:** Commit the report and the ledger with the message `docs(benchmark): P6 overview`.
