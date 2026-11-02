# P3 (O3): Skill-Level Context and Instruction-Flow Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop judging auxiliary files in isolation. When SKILL.md tells the agent to "open X and follow it",
the per-file LLM call for X should know that. Optionally, add one per-skill LLM pass that lists every action the
instruction bundle tells the agent to take, and flags the ones the stated purpose does not need.

**Architecture:** Two flag-gated mechanisms, measured as separate arms.
- **(a) Context header.** A patch on `LLMAnalyzerBase` records a per-batch header in `get_batches`, and prepends it in
  `build_prompt`, for non-SKILL.md files that SKILL.md references. The header holds the skill name, the description
  and the referencing SKILL.md lines.
- **(b) Instruction-flow node.** `exaforce_instruction_flow` is a new LLM analyzer, registered with P2's
  `register_analyzer`. It sends one bundle per skill (SKILL.md plus the files it references) and emits `EXA-IF1`
  findings mapped back to the original file and line.

**Tech Stack:** Python 3.12+, the fork patch framework, `LLMAnalyzerBase`, and the P0 harness.

**Spec:** `docs/superpowers/specs/2026-10-29-recall-improvement-program.md`. Background: O3 and B2 in
`benchmark/recall-boundaries.md`.

## Global Constraints

- Spec rules apply. Branch `exaforce/recall-p3-skill-context`, from P2's final commit.
- Flags:
  - `SKILLSPECTOR_EXA_SKILL_CONTEXT`: `off` (default), `ssd` (only `semantic_security_discovery`), or `semantic`
    (SSD, SDI and SQP).
  - `SKILLSPECTOR_EXA_INSTRUCTION_FLOW=on|off` (default off).
- **Referenced file:** a component other than SKILL.md whose relative path, or whose basename (when that basename is
  unique among components), appears in SKILL.md. Matching is case-sensitive and bounded by non-word characters.
- **Header** (exact template, at most 8 referencing lines, each at most 300 characters):
  ```
  [skill context] This file belongs to skill "<name>": <description, first 300 chars>.
  SKILL.md refers to it in these lines (the agent will act on this file as instructed there):
  <line no>: <line>
  Judge this file as instructions the agent will follow, not as passive documentation.
  ```
- **Instruction-flow bundle:**
  - SKILL.md first, then the referenced files in SKILL.md order. Each file is preceded by `=== FILE: <path> ===`.
  - Skip files over 50,000 characters, and `.xsd`/`.xml` schema files.
  - Cap the bundle at 24,000 estimated tokens (`estimate_tokens`) by dropping trailing files.
  - The node runs only when ≥1 referenced file exists. Otherwise it reports `not_applicable`.
- `EXA-IF1` severity: HIGH when an instructed action does all three of these:
  - it touches host config, credentials, keys, the network, logs or permissions, or changes facts or numbers in the
    output;
  - it is not required by the stated purpose;
  - it is presented as mandatory or not to be mentioned.

  MEDIUM when it is unnecessary but benign-looking. Findings must classify as LLM findings
  (`_filter_patches.is_llm_finding` is True), so the semantic floor applies to them.
- The prompt must not mention benchmark names, unit names, hosts, or any phrase copied from a unit. It asks about
  **necessity, not presence**: benign skills legitimately say "read REFERENCE.md first".
- Plan minimum: +0.5 recall points. Plan guards: median scan time ≤ 1.25× control for (a) and ≤ 1.40× for (b);
  and benign FP on the multi-doc benign guard units does not rise by more than `N_FP`.

## Review Focus

1. **A SKILL.md that mentions a file which is not in the package.** No header, no bundle entry, no crash. Test:
   `test_referenced_missing_file_ignored`.
2. **Basename collisions** (two `README.md` files). Only a path match counts. Test:
   `test_ambiguous_basename_not_matched`.
3. **A large office skill with hundreds of `.xsd` files.** The bundle drops schemas and stays under the cap. Test:
   `test_bundle_skips_schemas_and_caps_tokens`.
4. **`EXA-IF1` line numbers in the bundle.** They are mapped back to the right file and line, including on file
   boundaries. Test: `test_bundle_line_mapping`.
5. **Context header when a file is chunked into several batches.** Every chunk gets the header, and line numbering
   still starts at the chunk's own `start_line`. Test: `test_header_on_every_chunk`.

---

### Task 1: Reference detection and bundle building (pure functions)

**Files:**
- Create: `src/skillspector/exaforce/_skill_refs.py`
- Test: `tests/exaforce/test_skill_refs.py`

**Interfaces:**
- Produces:
  - `referenced_files(skill_md: str, components: list[str]) -> dict[str, list[tuple[int, str]]]`: maps a referenced
    path to its referencing `(line_no, line)` pairs, in order.
  - `context_header(manifest: dict, refs: list[tuple[int, str]]) -> str`: the exact template.
  - `build_bundle(skill_md_path: str, file_cache: dict[str, str], refs: dict[str, list]) -> Bundle`, where
    `@dataclass Bundle: text: str; offsets: list[tuple[int, str, int]]`. Each offset is (bundle start line, path,
    file start line).
  - `map_line(bundle: Bundle, line: int) -> tuple[str, int]`.

- [ ] **Step 1:** Write failing tests:
  - `test_referenced_by_path`;
  - `test_ambiguous_basename_not_matched`;
  - `test_referenced_missing_file_ignored`;
  - `test_header_exact_template`;
  - `test_bundle_skips_schemas_and_caps_tokens`;
  - `test_bundle_line_mapping`.
- [ ] **Step 2:** Run. Expect failures.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Tests pass.
- [ ] **Step 5:** Commit with the message `feat(exaforce): skill reference detection and instruction bundle`.

### Task 2: Context header patch

**Files:**
- Modify: `src/skillspector/exaforce/_patchlib.py` (add `intercept_method`)
- Create: `src/skillspector/exaforce/_context_patches.py`
- Modify: `src/skillspector/exaforce/__init__.py`
- Test: `tests/exaforce/test_patchlib.py` and `tests/exaforce/test_context_patches.py`

**Interfaces:**
- Consumes:
  - `LLMAnalyzerBase.get_batches(self, file_paths, file_cache, findings=None) -> list[Batch]`;
  - `LLMAnalyzerBase.build_prompt(self, batch, **kwargs) -> str`;
  - `LLMAnalyzerBase` has a `node` attribute (the analyzer id), set by `__init__(..., node=...)`;
  - `_skill_refs` from Task 1.
- Produces:
  - `intercept_method(cls, name, interceptor: Callable[[Callable, object, tuple, dict], object], *, expected_params)`,
    with the same guards as `intercept_module_callable`.
  - `apply()`:
    - `get_batches`: when the flag selects `self.node` and the file is referenced, record the header in a
      `weakref.WeakKeyDictionary[Batch, str]`. If `Batch` is not weakref-able, key on `id(batch)` in a dict that the
      `build_prompt` wrapper clears after reading.
    - `build_prompt`: prepend the header plus a blank line.
    - The manifest comes from parsing SKILL.md frontmatter in `file_cache`, using `build_context._parse_manifest`'s
      logic. Copy it; do not import a private helper whose signature takes a directory.

- [ ] **Step 1:** Write failing tests:
  - `test_intercept_method_*`: mirror P1's three patchlib tests;
  - `test_header_added_for_referenced_file_ssd_only`;
  - `test_header_not_added_when_off`;
  - `test_header_on_every_chunk`;
  - `test_semantic_mode_covers_sdi_and_sqp`;
  - `test_skill_md_itself_never_gets_header`.
- [ ] **Step 2:** Run. Expect failures.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Tests pass, then the full suite passes.
- [ ] **Step 5:** Commit with the message `feat(exaforce): flag-gated skill-context header for referenced files`.

### Task 3: Instruction-flow analyzer node

**Files:**
- Create: `src/skillspector/exaforce/_instruction_flow.py`
- Modify: `src/skillspector/exaforce/__init__.py`
- Test: `tests/exaforce/test_instruction_flow.py`

**Interfaces:**
- Consumes:
  - `register_analyzer(analyzer_id, node, enabled=...)` (P2);
  - `LLMAnalyzerBase` and the `semantic_security_discovery.node` flow, as the pattern to copy for ledger events,
    `llm_call_log` and `inference_usage`;
  - `_skill_refs` (Task 1).
- Produces:
  - `ANALYZER_ID = "exaforce_instruction_flow"`.
  - `INSTRUCTION_FLOW_PROMPT: str`, which states the task: list each action the bundle instructs the agent to take,
    and report only those the stated purpose does not require, as `EXA-IF1` with the severity rule from Global
    Constraints. It must ask about necessity, not presence.
  - `class InstructionFlowAnalyzer(LLMAnalyzerBase)`:
    - `get_batches` returns exactly one `Batch(file_path="SKILL.md", content=bundle.text)`;
    - `parse_response` maps each finding's `start_line`/`end_line` through `map_line` to the real file and line.
  - `node(state) -> AnalyzerNodeResponse`. The model is resolved like SSD:
    `model_config.get(ANALYZER_ID) or model_config.get("default")`, plus the env var
    `SKILLSPECTOR_MODEL_EXAFORCE_INSTRUCTION_FLOW` checked first. P7 uses that env var.

- [ ] **Step 1:** Write failing tests. Mock the LLM: patch the analyzer's invoke path so it returns a canned
  `LLMAnalysisResult`.
  - `test_node_not_applicable_without_refs`;
  - `test_node_single_batch_per_skill`;
  - `test_findings_mapped_to_original_file`;
  - `test_if1_findings_are_llm_findings` (`is_llm_finding` is True);
  - `test_node_disabled_by_flag`;
  - `test_model_env_override`.
- [ ] **Step 2:** Run. Expect failures.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Tests pass, then the full suite passes. **E2E:** with the flag on and a real LLM, scan the unit
  `Skills/malware/pptx__skillharm-fpp-a4db25e26d` once through `uv run benchmark --units-file`. Confirm in the DB that
  the run has issues from analyzer `exaforce_instruction_flow` (rule `EXA-IF1`), or record "0 findings" in the ledger.
  Either is acceptable; a crash or a missing node is not.
- [ ] **Step 5:** Commit with the message `feat(exaforce): flag-gated per-skill instruction-flow analyzer EXA-IF1`.

### Task 4: Dev arms and prompt iteration

**Files:**
- Create: `benchmark/results/evalsets/p3-focus.txt` and `p3-dev.txt`; regenerate `splits.tsv`
- Modify: `benchmark/results/recall-ledger.md`

- [ ] **Step 1: Focus set**, from `$BV2`:
  ```bash
  uv run evalset focus results/evalsets/p3-focus.txt --db results/recall.duckdb --run $BV2 --cap 900 --where "
    bf.boundary_cluster IN ('C02_skillharm_redirect','C06_msb_agenttrap_leak_asm','C11_skillinject')
    OR (e.unit_path IN (SELECT unit_path FROM components WHERE run_id='$BV2'
          AND path ILIKE '%.md' AND path NOT ILIKE '%SKILL.md'))"
  ```
  The second clause selects the multi-doc guard: benign and malicious units with a non-SKILL markdown file. Then
  build `p3-dev.txt` as core plus focus, regenerate the splits, and record the composition.
- [ ] **Step 2:** Preflight. Control ×2. Then candidates, each ×2, each judged with `arms` against control:
  - A1: `SKILL_CONTEXT=ssd`;
  - A2: `SKILL_CONTEXT=semantic`;
  - B1: `INSTRUCTION_FLOW=on`;
  - B2: B1 with `EXA-IF1` appended to `SKILLSPECTOR_EXA_GATE_RULES`, only if P1's gate is accepted;
  - B3 (optional, the 5th candidate): one revision of `INSTRUCTION_FLOW_PROMPT`, made from B1's dev errors.
    - Read at most 10 FNs and 10 FPs from the dev set.
    - Write down the **class** of each error before editing (for example "treated a mandatory preflight in a doc as
      configuration"), and edit only toward those classes, under the spec's anti-overfitting rules.
    - Commit the revision before running it, so every arm has a sha.
    - The holdout split in final acceptance is the overfitting check.
- [ ] **Step 3:** For each arm, record ΔTP, ΔFP, the noise floor, the median scan time ratio, and the guard FP
  change. Compute the guard FP change by restricting `evaluation` to benign units in the multi-doc clause; write the
  SQL into the ledger.
- [ ] **Step 4: Choose.**
  - Choose the best PROMISING (a) arm and the best PROMISING (b) arm.
  - If both exist, run one combined arm ×2, (a)+(b). Keep it only if it is PROMISING against the better single arm.
  - Arms that fail a time guard are rejected.
- [ ] **Step 5:** Commit the evalsets and the ledger with the message `docs(benchmark): P3 dev arms`.

### Task 5: Final acceptance, default flip, and overview

- [ ] **Step 1:** Full control and full treatment, same day, both healthy.
- [ ] **Step 2:** Apply acceptance plus the plan guards. If ACCEPTED, flip the defaults, plus `EXA-IF1` in the gate
  rules when B2 won. Update the default tests and commit with the message
  `feat(exaforce): enable <flags> by default (P3 accepted)`.
- [ ] **Step 3: Overview** in `benchmark/results/recall-p3-report.md`, using the spec's two `report` commands. The
  verdict block must cover:
  - Δrecall overall, on C02 redirect units, and on `cross_file` annotated units;
  - SkillHarm attributed recall before and after (the B2 boundary's real metric);
  - median and p95 scan time;
  - LLM calls per scan.
- [ ] **Step 4:** Commit the report and the ledger with the message `docs(benchmark): P3 overview`.
