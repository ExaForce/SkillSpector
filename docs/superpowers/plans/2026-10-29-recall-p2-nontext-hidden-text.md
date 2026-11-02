# P2 (O2): Text from Non-Text Files and Hidden-Text Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let SkillSpector's analyzers see the text inside PDF and office files, and flag instruction text that is
hidden from a human reader. Hidden here means:
- white or invisible PDF text;
- zero-width or bidi control characters in markdown;
- imperative HTML comments in markdown.

**Architecture:**
- A pure-stdlib extractor (`exaforce/_doc_text.py`) is patched in after `build_context._read_file_cache`. It replaces
  the unreadable UTF-8-decoded bytes of `.pdf/.docx/.pptx/.xlsx` with extracted text.
- When the hidden-text flag is on, hidden PDF spans come out marked with a `[hidden] ` line prefix.
- A fork-local static analyzer node (`exaforce_hidden_text`) emits `EXA-HT1..3`. It is registered through a new
  helper, `exaforce/_analyzer_registry.py`, which P3-P5 reuse.

Three arms are measured independently against control:
- A: extraction;
- B: A plus the hidden-text rules;
- C: B plus `EXA-HT1` in P1's gate.

**Tech Stack:** Python 3.12+ stdlib (`zlib`, `base64`, `re`, `zipfile`, `xml.etree.ElementTree`), the fork patch
framework, and the P0 harness.

**Spec:** `docs/superpowers/specs/2026-10-29-recall-improvement-program.md`. Background: O2 and B2 in
`benchmark/recall-boundaries.md`, and correction 5 in `benchmark/recall-boundaries-review.md`.

## Global Constraints

- Spec rules apply. Branch `exaforce/recall-p2-nontext`, from P1's final commit.
- Flags:
  - `SKILLSPECTOR_EXA_DOC_TEXT=on|off` (default off);
  - `SKILLSPECTOR_EXA_HIDDEN_TEXT=on|off` (default off). Hidden markers, and the `EXA-HT1` rule that depends on them,
    need DOC_TEXT on as well.
- No new dependencies. Never render, execute or decompress unbounded:
  - skip PDFs over 5,000,000 bytes;
  - stop a Flate stream at 10,000,000 decompressed bytes (`zlib.decompressobj().decompress(data, max_length)`);
  - reject office zips with more than 2,000 entries or more than 20,000,000 total uncompressed bytes;
  - cap extracted text at 200,000 characters.
- Extracted content format (exact):
  - first line `[exaforce: text extracted from <ext>; <n> hidden spans]`;
  - then one line per text run;
  - hidden runs (the HIDDEN_TEXT flag on) are prefixed `[hidden] `.
- PDF hidden means any of these, applied to text shown with `Tj`, `TJ`, `'` or `"`:
  - the current non-stroking fill is `g`/`rg`/`k` with every component ≥ 0.95, or `k` all ≤ 0.05 (white in CMYK);
  - text render mode `3 Tr`;
  - font size `Tf` below 1.5.
- Rule IDs and severities:
  - `EXA-HT1` HIGH: ≥40 characters of `[hidden] ` lines in one extracted file.
  - `EXA-HT2` MEDIUM: ≥3 characters from U+200B-U+200F, U+202A-U+202E, U+2060-U+2064 or U+FEFF (not at file start)
    in a `.md`/`.txt` file, outside fenced code blocks.
  - `EXA-HT3` MEDIUM: an HTML comment of ≥40 characters in a `.md` file whose text starts with an imperative
    directed at an agent. The verb list is fixed:
    `run|execute|ignore|delete|remove|send|upload|post|curl|wget|chmod|ssh|copy|append|always|never|do not (tell|mention|ask)`.
- **Precision of `EXA-HT*` and of PDF extraction is unmeasured on this benchmark**: there are 6 benign PDFs in one
  unit. The overview must say so. Do not tune the rules on SkillHarm PDFs alone, because they all use one generator.
- Plan minimum: +0.5 recall points. Plan guard: the FP count on benign units containing a `.md` HTML comment must not
  rise by more than `N_FP`.

## Review Focus

1. **Encrypted or object-stream PDFs.** Extraction returns the header line with 0 runs; the content is not left as
   garbage bytes. Test: `test_pdf_unparseable_streams_yield_header_only`.
2. **A malicious zip bomb disguised as `.docx`.** The caps trip, and the extractor falls back to the header plus
   `extraction skipped: limits`. Test: `test_ooxml_zip_bomb_guard`.
3. **A zero-width joiner in legitimate emoji or Indic text.** U+200D inside a word between non-ASCII letters is not
   counted. Test: `test_ht2_ignores_zwj_in_script_text`.
4. **An HTML comment that is a normal authoring note** (`<!-- TODO: add example -->`) does not fire. Test:
   `test_ht3_ignores_todo_comment`.
5. **A PDF whose real text is white on a dark header band.** This is a known false-positive shape. It fires only
   when the white text is ≥40 characters; record it as a limitation. Test:
   `test_ht1_threshold_counts_chars`.

---

### Task 1: Stdlib document-text extractor

**Files:**
- Create: `src/skillspector/exaforce/_doc_text.py`
- Test: `tests/exaforce/test_doc_text.py`

**Interfaces:**
- Produces:
  - `@dataclass class DocText: text_runs: list[str]; hidden_runs: list[str]; skipped_reason: str | None`.
  - `extract_pdf(data: bytes) -> DocText`.
  - `extract_ooxml(data: bytes, ext: str) -> DocText`, where ext is `.docx`, `.pptx` or `.xlsx`. It reads
    `word/document.xml`, `ppt/slides/slide*.xml` and `xl/sharedStrings.xml`, concatenating `<w:t>`, `<a:t>` and
    `<t>` text.
  - `render(doc: DocText, ext: str, mark_hidden: bool) -> str`, producing the exact content format.

- [ ] **Step 1: Write failing tests.** Build the PDF bytes in the test: a minimal PDF with one Flate stream (use
  `zlib.compress`) containing `BT /F1 12 Tf (visible) Tj 1 1 1 rg (hidden instruction text that is long enough to
  count) Tj ET`, and one ASCII85+Flate stream.
  - `test_pdf_extracts_visible_and_hidden`;
  - `test_pdf_render_mode_3_is_hidden`;
  - `test_pdf_tiny_font_is_hidden`;
  - `test_pdf_size_cap`;
  - `test_pdf_unparseable_streams_yield_header_only`;
  - `test_ooxml_docx_text` (build the zip in memory);
  - `test_ooxml_zip_bomb_guard`;
  - `test_render_format_exact`;
  - `test_real_skillharm_pdf`: skip if `/Users/will/workspace/MalSkillBench` is absent. For three PDFs under
    `Skills/malware/*__skillharm-fpp-*/**/*.pdf`, expect ≥200 characters of text and ≥1 hidden run.
- [ ] **Step 2:** `uv run pytest tests/exaforce/test_doc_text.py -q`. Expect failures.
- [ ] **Step 3:** Implement. Track the fill colour and `Tr`/`Tf` state through the content stream with a small token
  loop. Decode the string escapes `\(`, `\)`, `\\` and octal `\ddd`. `TJ` arrays concatenate their strings.
- [ ] **Step 4:** Tests pass.
- [ ] **Step 5:** Commit with the message `feat(exaforce): stdlib PDF/OOXML text extractor with hidden-text detection`.

### Task 2: Feed extracted text to the analyzers

**Files:**
- Create: `src/skillspector/exaforce/_build_context_patches.py`
- Modify: `src/skillspector/exaforce/__init__.py`
- Test: `tests/exaforce/test_build_context_patches.py`

**Interfaces:**
- Consumes: `build_context._read_file_cache(skill_dir: Path, components: list[str]) -> tuple[dict[str, str], list]`;
  `intercept_module_callable` (P1); and `_doc_text` (Task 1).
- Produces: `apply()`. When DOC_TEXT is on, it re-reads each `.pdf/.docx/.pptx/.xlsx` component as bytes and
  replaces that cache entry with `render(...)`. `mark_hidden` follows the HIDDEN_TEXT flag.

- [ ] **Step 1: Write failing tests.**
  - `test_cache_replaced_when_flag_on`: tmp skill dir with `SKILL.md` and `guide.pdf`; call
    `build_context._read_file_cache`; assert the cache entry starts with `[exaforce: text extracted from .pdf`.
  - `test_cache_untouched_when_flag_off`.
  - `test_hidden_markers_follow_hidden_flag`.
  - `test_build_context_node_end_to_end`: call the `build_context` node on the tmp dir and assert the state's
    `file_cache` holds the extracted text. This guards against a downstream stage re-reading files.
- [ ] **Step 2:** Run. Expect failures.
- [ ] **Step 3:** Implement with `intercept_module_callable(build_context, "_read_file_cache", ...,
  expected_params=("skill_dir", "components"))`.
- [ ] **Step 4:** Tests pass, then the full suite passes.
- [ ] **Step 5:** Commit with the message `feat(exaforce): flag-gated extracted text for PDF/office files`.

### Task 3: Analyzer registry helper and the hidden-text static node

**Files:**
- Create: `src/skillspector/exaforce/_analyzer_registry.py`
- Create: `src/skillspector/exaforce/_hidden_text.py`
- Modify: `src/skillspector/exaforce/__init__.py`
- Test: `tests/exaforce/test_analyzer_registry.py` and `tests/exaforce/test_hidden_text.py`

**Interfaces:**
- Consumes: `skillspector.nodes.analyzers.ANALYZER_NODE_IDS` (a list, mutated in place) and `ANALYZER_NODES` (a
  dict). `graph.create_graph()` iterates both at call time.
- Produces:
  - `register_analyzer(analyzer_id: str, node: Callable, *, enabled: Callable[[], bool]) -> None`. It is
    idempotent. It wraps `node` so that when `enabled()` is false the node returns the same "disabled" response shape
    `semantic_security_discovery.node` uses when `use_llm` is False. That keeps the inspection ledger consistent.
  - Module `_hidden_text` with `ANALYZER_ID = "exaforce_hidden_text"`, `analyze(content, path, file_type) ->
    list[AnalyzerFinding]`, and `node(state)` delegating to `static_runner.run_static_patterns_with_ledger`, as in
    `static_patterns_ssrf.py`.
  - `EXA-HT1..3` get an explanation and a remediation through the same mechanism `pattern_defaults.get_explanation`
    uses. If that table is not extensible without editing upstream, pass explicit `explanation`/`remediation` on the
    `AnalyzerFinding`.

- [ ] **Step 1: Write failing tests.**
  - `test_register_analyzer_adds_node_once`.
  - `test_registered_node_disabled_returns_disabled_status`.
  - `test_graph_includes_registered_node`: `create_graph()` succeeds and its nodes include `exaforce_hidden_text`.
  - `test_ht1_fires_on_hidden_lines`, `test_ht1_threshold_counts_chars`.
  - `test_ht2_counts_zero_width_outside_fences`, `test_ht2_ignores_zwj_in_script_text`.
  - `test_ht3_fires_on_imperative_comment`, `test_ht3_ignores_todo_comment`.
  - `test_hidden_findings_reach_report`: run the full graph with `use_llm=False` on a tmp skill holding an
    imperative HTML comment, with HIDDEN_TEXT on. The final `report_body` issues contain `EXA-HT3`.
- [ ] **Step 2:** Run. Expect failures.
- [ ] **Step 3:** Implement. `enabled` is `lambda: os.environ.get("SKILLSPECTOR_EXA_HIDDEN_TEXT") == "on"`.
- [ ] **Step 4:** Tests pass, then the full suite passes.
- [ ] **Step 5:** Commit with the message `feat(exaforce): analyzer registry and hidden-text rules EXA-HT1..3`.

### Task 4: Dev arms

**Files:**
- Create: `benchmark/results/evalsets/p2-focus.txt` and `p2-dev.txt` (core plus focus); regenerate `splits.tsv`
- Modify: `benchmark/results/recall-ledger.md`

- [ ] **Step 1: Build the focus set** from `baseline-v2` (`$BV2`):
  ```bash
  uv run evalset focus results/evalsets/p2-focus.txt --db results/recall.duckdb --run $BV2 --where "
    bf.has_nontext_file OR bf.injection_pattern IN ('redirect_to_new_pdf','redirect_to_new_doc')
    OR e.unit_path IN (SELECT unit_path FROM components WHERE run_id='$BV2' AND (
         path ILIKE '%.pdf' OR path ILIKE '%.docx' OR path ILIKE '%.pptx' OR path ILIKE '%.xlsx'))
    OR (NOT e.truth_malicious AND e.unit_path IN (SELECT unit_path FROM components WHERE run_id='$BV2' AND path ILIKE '%.md'))" --cap 900
  cat results/evalsets/core-dev.txt results/evalsets/p2-focus.txt | sort -u > results/evalsets/p2-dev.txt
  uv run evalset splits results/evalsets/splits.tsv --db results/recall.duckdb --run $BV2 results/evalsets/*-dev.txt
  ```
  The last benign clause samples markdown-bearing benign units as the guard for HT2/HT3. Print the focus composition
  by corpus and outcome into the ledger.
- [ ] **Step 2:** Preflight. Run control ×2. Then run treatments ×2 each:
  - A: `DOC_TEXT=on`;
  - B: `DOC_TEXT=on HIDDEN_TEXT=on`;
  - C: B plus `SKILLSPECTOR_EXA_GATE_RULES=<P1 default>,EXA-HT1`. Run C only when P1's gate was accepted.

  Run `health` after every run.
- [ ] **Step 3:** Run `uv run arms` for each of A, B and C against the controls. Also compute the plan guard: the FP
  change on benign units with an HTML comment in a `.md` file (a SQL query over `issues` joined to `evaluation`;
  write it into the ledger). Choose the best PROMISING arm by `ΔTP − 8·ΔFP`. B or C can only win when it is
  PROMISING against **A**, i.e. rerun `arms --control A1,A2 --treatment B1,B2`. Each addition must earn its place.
- [ ] **Step 4:** Commit the evalsets and ledger with the message `docs(benchmark): P2 dev arms`.

### Task 5: Final acceptance, default flip, and overview

- [ ] **Step 1:** Full control and full treatment (the chosen arm), same day, both healthy.
- [ ] **Step 2:** Apply the spec's acceptance rule plus the plan guard. If ACCEPTED, flip the defaults of the chosen
  flags. When C won, append `EXA-HT1` to the default gate rules in `_score_patches.py`. Update the default tests, run
  the suites, and commit with the message `feat(exaforce): enable <flags> by default (P2 accepted)`.
- [ ] **Step 3: Overview** in `benchmark/results/recall-p2-report.md`, using the spec's two `report` commands. Start
  it with a verdict block that states:
  - Δrecall, with the gain on `has_nontext_file` units and on `redirect_to_new_doc` units shown separately;
  - SkillHarm attributed recall before and after;
  - **"Precision for PDF/office extraction and EXA-HT1 is unmeasured: 6 benign PDFs in 1 unit."**
  - mean scan time change. Extraction adds LLM input tokens.
- [ ] **Step 4:** Commit the report and the ledger with the message `docs(benchmark): P2 overview`.
