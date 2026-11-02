# P4 (O4): Necessity Audit of Imperative Steps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Catch harm that is only visible against the skill's purpose. Examples are falsified numbers, swapped
recommendations, a "preflight" that deletes one log, or a forged attestation. The method is to ask, for each
imperative step or output rule, whether the stated purpose requires it. This is the B3 boundary, about 0.25 recall,
and the core of Content Manipulation.

**Architecture:** Two arms, cheapest first.
- **(A) Prompt extension.** Add a fifth category, `SSD-5`, to the existing `semantic_security_discovery` prompt with
  a runtime prompt patch (`replace_module_str`). This adds no LLM calls.
- **(B) Dedicated node.** `exaforce_necessity` makes one LLM call per SKILL.md, applying the four-question audit and
  emitting `EXA-NE1`. Run it only if (A) is not PROMISING, or as an additional candidate when (A) is PROMISING but
  under +0.5 points.

Both are measured with and without adding their rule to P1's gate.

**Tech Stack:** Python 3.12+, fork patch framework, the P2 registry, the P0 harness.

**Spec:** `docs/superpowers/specs/2026-10-29-recall-improvement-program.md`. Background: O4 and B3 in
`benchmark/recall-boundaries.md`. The review's correction 1 explains why this plan targets domain-contextual and
purpose-fit payloads, not "operational-step framing".

## Global Constraints

- Spec rules apply. Branch `exaforce/recall-p4-necessity`, from P3's final commit.
- Flags:
  - `SKILLSPECTOR_EXA_SSD5=on|off` (default off);
  - `SKILLSPECTOR_EXA_NECESSITY=on|off` (default off).
- The four questions (exact wording, used in both arms):
  1. Does the skill's stated purpose require this step or rule?
  2. Does it touch anything outside the task's working data: shell startup files, SSH or cloud credentials, logs,
     permissions, network destinations, other skills?
  3. Does it change facts, numbers, attributions, citations or recommendations in the output in a way the user did
     not ask for?
  4. Is it framed as mandatory, silent, or not to be mentioned or questioned?

  Report a finding only when Q1 = no, and Q2, Q3 or Q4 = yes. Severity is HIGH when Q2 or Q3 = yes **and** Q4 = yes;
  MEDIUM otherwise.
- `SSD-5` is scoped to markdown and text files: the prompt text says to apply it only to instructions written in
  natural language. `EXA-NE1` runs on SKILL.md only, with the skill's name and description.
- Plan minimum: +0.5 recall points.
- Plan guard (FP), measured on these dev guard sets:
  - benign units whose SKILL.md has setup, preflight, cleanup or reporting-rule language (the focus clause below);
  - the 41 Skill-Inject clean skills;
  - benign `21+`-file packages.

  Guard FP must not rise by more than `max(N_FP, 0.5% of guard benign units)`.
- No domain facts in prompts. Do not write things like "a +0.5 K offset is suspicious". The prompt reasons about
  necessity only.

## Review Focus

1. **Legitimate setup steps** ("run `npm install` first", "set `API_BASE` in your shell"). Expect no finding, because
   Q1 = yes. Test: a canned-LLM fixture, `test_ne1_prompt_includes_purpose_first`, which checks that the prompt asks
   Q1 before Q2-Q4, and a dev-guard measurement.
2. **A SKILL.md with no frontmatter description.** The purpose comes from the first heading and paragraph. Test:
   `test_purpose_fallback_without_description`.
3. **The `SSD-5` patch when upstream rewrites the SSD prompt.** Raise `PatchDriftError` at import. Test:
   `test_ssd5_patch_drift`.
4. **A very long SKILL.md.** Cap it at the analyzer's input budget, chunked like other batches, with the purpose
   header on every chunk. Test: `test_necessity_chunks_keep_purpose`.
5. **The model returns `SSD-5` for a non-markdown file.** Keep the finding, but log a count, and record the share in
   the dev arms so a prompt-scope failure is visible. Test: `test_ssd5_non_md_counted`.

---

### Task 1: SSD-5 prompt patch (arm A)

**Files:**
- Create: `src/skillspector/exaforce/_necessity_prompt.py`
- Modify: `src/skillspector/exaforce/__init__.py`
- Test: `tests/exaforce/test_necessity_prompt.py`

**Interfaces:**
- Consumes:
  - `replace_module_str(module, attr, old, new)` from `_patchlib`. It cannot be flag-gated at call time, so this task
    instead adds a flag-gated **prompt selector**. Keep two strings, `ANALYZER_PROMPT_BASE` (upstream) and
    `ANALYZER_PROMPT_SSD5` (patched). Intercept `LLMAnalyzerBase.__init__` (with `intercept_method` from P3) so that
    when `node == "semantic_security_discovery"` and the flag is on, `base_prompt` is swapped for the SSD5 version.
  - The upstream SSD prompt block at `semantic_security_discovery.py:42-80`, which defines SSD-1..4.
- Produces:
  - `NECESSITY_QUESTIONS: str` (the exact four questions), shared with Task 2.
  - `ssd5_prompt(base: str) -> str`: inserts the `SSD-5 – Unnecessary or purpose-violating instruction` block after
    the SSD-4 block. The anchor is the exact SSD-4 heading line; when the anchor is missing, raise `PatchDriftError`.
  - `apply()`.

- [ ] **Step 1:** Write failing tests:
  - `test_ssd5_prompt_inserts_after_ssd4`;
  - `test_ssd5_patch_drift`;
  - `test_ssd_analyzer_uses_patched_prompt_only_when_on`: construct `LLMAnalyzerBase(base_prompt=ANALYZER_PROMPT,
    model="m", node="semantic_security_discovery")` and inspect `.base_prompt`;
  - `test_other_analyzers_unaffected`;
  - `test_ssd5_non_md_counted`.
- [ ] **Step 2:** Run. Expect failures.
- [ ] **Step 3:** Implement. `SSD-5` already starts with `SSD-`, so it is an LLM finding and is covered by gate prefix
  `SSD-` but **not** by P1's explicit default list `SSD-1..4,P2`. Gate inclusion is a separate arm.
- [ ] **Step 4:** Tests pass, then the full suite passes.
- [ ] **Step 5:** Commit with the message `feat(exaforce): flag-gated SSD-5 necessity category`.

### Task 2: Dedicated necessity node (arm B)

**Files:**
- Create: `src/skillspector/exaforce/_necessity.py`
- Modify: `src/skillspector/exaforce/__init__.py`
- Test: `tests/exaforce/test_necessity.py`

**Interfaces:**
- Consumes: `register_analyzer` (P2), `NECESSITY_QUESTIONS` (Task 1), and the analyzer pattern from P3's
  `_instruction_flow.py`, which this task mirrors for ledger, usage and model resolution.
- Produces:
  - `ANALYZER_ID = "exaforce_necessity"`, plus the model env override `SKILLSPECTOR_MODEL_EXAFORCE_NECESSITY`.
  - `skill_purpose(skill_md: str) -> str`: the frontmatter `name: description`, else the first `#` heading plus its
    first paragraph, capped at 600 characters.
  - `NECESSITY_PROMPT: str`, which states: the purpose header; extract every imperative step and output rule; apply
    `NECESSITY_QUESTIONS`; report as `EXA-NE1`.
  - `node(state)`: SKILL.md only. Chunks carry the purpose header.

- [ ] **Step 1:** Write failing tests, with the LLM mocked:
  - `test_purpose_from_frontmatter`;
  - `test_purpose_fallback_without_description`;
  - `test_ne1_prompt_includes_purpose_first`;
  - `test_necessity_chunks_keep_purpose`;
  - `test_node_disabled_by_flag`;
  - `test_ne1_are_llm_findings`.
- [ ] **Step 2:** Run. Expect failures.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Tests pass, then the full suite passes. E2E: run one real-LLM scan of one Skill-Inject contextual
  malicious unit with the flag on. Confirm the node ran: the run's issues include `EXA-NE1`, or the ledger records
  0 findings.
- [ ] **Step 5:** Commit with the message `feat(exaforce): flag-gated per-skill necessity analyzer EXA-NE1`.

### Task 3: Dev arms

**Files:**
- Create: `benchmark/results/evalsets/p4-focus.txt` and `p4-dev.txt`; regenerate `splits.tsv`
- Modify: `benchmark/results/recall-ledger.md`

- [ ] **Step 1: Focus set**, from `$BV2`. It joins the annotation file for target selection. Only `label_validity`,
  `purpose_fit` and the `harm_explicitness` range are allowed, never `pretext`.
  ```bash
  L=/Users/will/workspace/MalSkillBench/Dataset/Skills/_boundary_labels.jsonl
  uv run evalset focus results/evalsets/p4-focus.txt --db results/recall.duckdb --run $BV2 --cap 1000 --where "
    e.behavior IN ('Content Manipulation','Goal Hijacking','Resource Abuse')
    OR bf.boundary_cluster IN ('C01_skillharm_skillmd_plaintext','C11_skillinject')
    OR e.unit_path IN (SELECT unit_path FROM read_json_auto('$L')
         WHERE label_validity='CORRECT' AND (purpose_fit OR harm_explicitness='domain_contextual'))
    OR (NOT e.truth_malicious AND (e.unit_path LIKE '%skillinject-clean%'
         OR e.unit_path IN (SELECT unit_path FROM components WHERE run_id='$BV2' GROUP BY 1 HAVING count(*)>20)))"
  ```
  Then add the setup-language benign guard. Use `grep -l -i -E 'preflight|before (you|using)|must (first|always)|setup|clean ?up|always (report|include|format)'`
  over `Skills/benign/*/SKILL.md`, deterministically sample 300 (seed 29), and append them to `p4-focus.txt`.
  Record that list's command in the evalset README. Build `p4-dev.txt` and regenerate the splits.
- [ ] **Step 2:** Preflight. Control ×2. Candidates ×2, each with `arms` against control:
  - A: `SSD5=on`;
  - A+gate: `SSD5=on` with `SSD-5` appended to `SKILLSPECTOR_EXA_GATE_RULES`, only if P1's gate is accepted;
  - B: `NECESSITY=on` (run when A is not PROMISING, or when A's ΔTP < 32);
  - B+gate;
  - one prompt revision of the best arm, under P3's rule: error classes from at most 10 FNs and 10 FPs, committed
    before it runs.
- [ ] **Step 3:** For each arm, record into the ledger:
  - ΔTP and ΔFP overall;
  - ΔTP on Content Manipulation units;
  - ΔTP on annotated `domain_contextual` CORRECT units;
  - guard FP for each of the three guard sets;
  - the share of `SSD-5` findings on non-markdown files (Review Focus 5).
- [ ] **Step 4:** Choose the best PROMISING arm whose guard FP passes. Commit with the message
  `docs(benchmark): P4 dev arms`.

### Task 4: Final acceptance, default flip, and overview

- [ ] **Step 1:** Full control and full treatment, same day, both healthy.
- [ ] **Step 2:** Apply acceptance plus the guard: FP on all benign units with setup language must not rise by more
  than 0.5%, computed on the full run. If ACCEPTED, flip the defaults, plus the gate rule when a `+gate` arm won.
  Update the default tests and commit with the message `feat(exaforce): enable <flags> by default (P4 accepted)`.
- [ ] **Step 3: Overview** in `benchmark/results/recall-p4-report.md`, using the spec's two `report` commands. The
  verdict block must cover:
  - Δrecall for Content Manipulation, Goal Hijacking and Resource Abuse;
  - Δrecall for SkillHarm no-code categories (`native_categories` in `anti_forensics`, `output_manipulation`,
    `poisoning`, from the external labels);
  - guard FP;
  - LLM calls per scan;
  - one sentence on whether Content Manipulation is still the weakest behaviour.
- [ ] **Step 4:** Commit the report and the ledger with the message `docs(benchmark): P4 overview`.
