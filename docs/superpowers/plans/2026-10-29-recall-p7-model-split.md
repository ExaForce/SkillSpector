# P7 (O7): Stronger Model for Per-Skill Passes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Check whether routing only the few per-skill LLM passes to a stronger model buys recall that the default
model cannot. Those passes are P3's `exaforce_instruction_flow`, P4's `exaforce_necessity`, and, when neither
shipped, `semantic_security_discovery`. Per-file passes and the meta-analyzer stay on the cheap model. Then write the
program-wide overview.

**Architecture:** No classifier code is needed. Model choice per analyzer already exists through the
`SKILLSPECTOR_MODEL_<SLOT>` env vars: upstream `constants._resolve_slot_model` covers the upstream slots, and P3/P4
check `SKILLSPECTOR_MODEL_EXAFORCE_*` in their own nodes. The plan probes which models are actually routable, runs
arms, and accepts or rejects. On acceptance, the default is shipped as a fork-local default:
`_model_defaults.py` sets the slot env vars with `os.environ.setdefault` when patches apply.

**Tech Stack:** The P0 harness, the benchmark's OpenAI-compatible Bedrock endpoint (`benchmark/benchmark/config.py`),
and the fork patch framework.

**Spec:** `docs/superpowers/specs/2026-10-29-recall-improvement-program.md`. Background: O7 in
`benchmark/recall-boundaries.md`, and the model notes in `benchmark/industry_benchmark_datasets.md` and
`benchmark/model_swap_report.md`.

## Global Constraints

- Spec rules apply. Branch `exaforce/recall-p7-model-split`, from P6's final commit.
- **Target slots (pre-registered):**
  - the env vars `SKILLSPECTOR_MODEL_EXAFORCE_INSTRUCTION_FLOW` and `SKILLSPECTOR_MODEL_EXAFORCE_NECESSITY`, for each
    node whose flag defaults to on after P3/P4;
  - if neither defaults to on, `SKILLSPECTOR_MODEL_SEMANTIC_SECURITY_DISCOVERY`.
- **Candidate models (pre-registered):**
  - every model id that the endpoint's `/v1/models` lists, other than the current default
    (`nvidia.nemotron-super-3-120b`);
  - **and** that passes the probe in Task 1;
  - at most 3, taken in the endpoint's listing order.

  A model listed in the catalog may still not be invocable, so every candidate is probed before use.
- Cost guard: treatment p95 scan time ≤ 1.5× control, and the timeout/ERROR rate does not exceed control by more than
  0.5 points.
- Plan minimum: +0.5 recall points.
- Never change the meta-analyzer's model in this plan. It is the largest latency share, and it is out of scope.

## Review Focus

1. **The endpoint lists a model that 400s or times out on structured output.** The probe excludes it, and the ledger
   records why. Covered by the Task 1 probe criteria.
2. **The stronger model writes `rule_id` values outside the schema** (for example `IF-1` instead of `EXA-IF1`).
   Detect it: count issues from the target analyzer whose `rule_id` is not in the allowed set, in each arm. Any count
   above 0 is recorded, and above 2% of that analyzer's findings rejects the arm.
3. **Slot env vars leak into the control arm.** The control commands must `unset` every `SKILLSPECTOR_MODEL_*` var
   other than the benchmark's own. Check `runs.config_json` of each control run.
4. **A shipped default that overrides a user's explicit env.** `_model_defaults.py` uses `setdefault` only. Test:
   `test_model_defaults_respect_explicit_env`.
5. **Token auth expiry over longer runs.** A stronger model is slower and can outlast the 12 h token. The harness
   re-mints the token; an SSO expiry follows autonomy rule 5.

---

### Task 1: Probe routable models

- [ ] **Step 1:** List the models. Use the same base URL and token mechanism as `benchmark/benchmark/config.py` and
  `auth.py`, from a short Python snippet run with `uv run python -c ...`. Write the ids into the ledger.
- [ ] **Step 2:** For each candidate, in listing order, run one scan of the 5-unit probe set: 4 known-malicious units
  from the core set that baseline-v2 caught through the target slot's analyzer, plus 1 benign unit. Set the target
  slot env var(s) to the candidate. A candidate passes when all of these hold:
  - `health` passes;
  - every scan has `llm_calls_succeeded == llm_calls_attempted`;
  - the target analyzer produced ≥1 finding on ≥2 of the 4 malicious units;
  - the median scan time ≤ 3× the default model's on the same 5 units, measured the same day.

  Stop after 3 passing candidates.
- [ ] **Step 3:** Commit the ledger with the message `docs(benchmark): P7 model probe`. If no candidate passes, skip
  to Task 4 with verdict REJECTED ("no routable stronger model").

### Task 2: Dev arms

- [ ] **Step 1:** Dev set: the union of `core-dev.txt` and the focus sets of every plan whose target slot is in use
  (`p3-focus.txt`, `p4-focus.txt`, or `p1-dev.txt` for the SSD fallback). Write it as `p7-dev.txt`, and regenerate
  the splits.
- [ ] **Step 2:** Preflight. Control ×2. Then each passing candidate (at most 3), screened first (see below), then one more full
  run. Run
  `health` after each. Judge each candidate with `uv run arms` against control, then apply the cost guard and the
  rule_id check (Review Focus 2).
  Run each candidate through `uv run screen` first (`--kind recall`, `--control-runs <the day's control runs>`, the
  target slot env var(s) via `--treatment-env`); a FUTILE screen is that candidate's dev verdict, REJECT (spec,
  "Sequential futility screen"). A PASSED screen is followed by one more full treatment
  run (the reused control runs are the control replicates, ×2), then `arms`.
- [ ] **Step 3:** Choose the best PROMISING candidate that passes the guards. Commit the evalsets and the ledger with
  the message `docs(benchmark): P7 dev arms`.

### Task 3: Final acceptance and fork default

**Files:**
- Create: `src/skillspector/exaforce/_model_defaults.py`
- Modify: `src/skillspector/exaforce/__init__.py`
- Test: `tests/exaforce/test_model_defaults.py`

- [ ] **Step 1:** Full control and full treatment, same day, both healthy. Apply acceptance plus the cost guard.
- [ ] **Step 2:** If ACCEPTED, write the failing tests:
  - `test_model_defaults_set_slot_when_unset`;
  - `test_model_defaults_respect_explicit_env`;
  - `test_model_defaults_flag_off`: `SKILLSPECTOR_EXA_MODEL_DEFAULTS=off` disables it.
- [ ] **Step 3:** Run. Expect failures. Implement `apply()`, called **first** in `apply_patches`, before
  `constants.MODEL_CONFIG` is read by any node. If `MODEL_CONFIG` is computed at import before the patches apply,
  set the env var **and** update `constants.MODEL_CONFIG[slot]` in place for upstream slots.
- [ ] **Step 4:** Tests pass, then the full suite passes.
- [ ] **Step 5:** Commit with the message `feat(exaforce): route <slots> to <model> by default (P7 accepted)`.

### Task 4: P7 overview and program summary

- [ ] **Step 1:** Write `benchmark/results/recall-p7-report.md` with the spec's two `report` commands, plus a verdict
  block: candidate, Δrecall, Δprecision, p95 time ratio, ERROR-rate change, and the rule_id violation count.
- [ ] **Step 2:** Write `benchmark/results/recall-program-summary.md`, the overall view:
  - `uv run report results/recall.duckdb <latest full run with all accepted defaults> --base <baseline-v2> --split-file results/evalsets/splits.tsv`.
    The latest such run is P7's treatment if accepted, otherwise P7's control, otherwise the last plan's.
  - A table with one row per plan: verdict, flags shipped, same-day Δrecall, Δprecision, and the report link.
  - Cumulative recall and precision against `baseline-v2`, and against the original `113b02ab497b`. State that both
    cumulative comparisons cross days and include endpoint drift; the per-plan same-day deltas are the causal
    estimates.
  - Recall per low-recall behaviour (the 11 behaviours below 0.80 at the start), original against final.
  - What is still below 0.80, mapped to the boundary in `recall-boundaries.md` that explains it.
- [ ] **Step 3:** Commit both reports and the ledger with the message
  `docs(benchmark): P7 overview and recall program summary`.
