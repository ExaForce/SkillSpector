# P5 (O5): Remote-Installer Lure Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Flag "install the required helper first" lures whose payload is off-package. Examples are pipe-to-shell
from a bare IP or a paste site, a password-protected archive to download and run, base64-wrapped execution, and
instructions to skip verification. Precision must hold against documented vendor installers.

**Architecture:**
1. Prototype candidate regexes offline over the whole dataset's files. Static rules are cheap, so each candidate
   gets an exact benign/malicious match count before any code ships; that is the existing-results quantification for
   static rules.
2. Implement only the candidates that pass a pre-registered precision bar, as a fork-local static node
   `exaforce_lure_rules` (via P2's `register_analyzer`).
3. Confirm with arms and full runs.

**Tech Stack:** Python 3.12+, `re`, fork patch framework, the P0 harness.

**Spec:** `docs/superpowers/specs/2026-10-29-recall-improvement-program.md`. Background: O5 and B5 in
`benchmark/recall-boundaries.md`.

## Global Constraints

- Spec rules apply. Branch `exaforce/recall-p5-lure-rules`, from P4's final commit.
- Flag: `SKILLSPECTOR_EXA_LURE_RULES=on|off` (default off).
- **Policy (pre-registered, no human decision needed):**
  - A lure with no in-package payload **is** a positive for an install gate.
  - Gains on annotated `UNVERIFIABLE` units must be reported separately, using P0's validity-tier section, so lure
    TPs are never presented as payload detection.
- Candidate rules, written as classes so they do not overfit:
  - `EXA-LU1` HIGH: fetch-and-execute (`curl|wget|iwr|Invoke-WebRequest|irm` piped or chained to
    `sh|bash|zsh|iex|Invoke-Expression|python|node`) where the URL host is a literal IPv4 address, or a
    general-purpose paste or snippet service.
    - The service list lives in `_lure_rules.PASTE_HOSTS`.
    - Every entry must be a public general-purpose paste service, each with a one-line comment naming what it is.
    - The reviewer rejects any entry seen only inside dataset units.
  - `EXA-LU2` HIGH: an instruction to download an archive **and** a stated archive password, within 5 lines of each
    other, **and** an instruction to run or open its content.
  - `EXA-LU3` MEDIUM: an instruction to disable integrity or authenticity checks during install. Covers "skip/ignore
    checksum|signature|verification", `curl -k`/`--insecure` piped to a shell, `--trusted-host` with
    `--index-url http://`, and `Set-ExecutionPolicy Bypass` with a download.
  - `EXA-LU4` HIGH: base64-decoded content executed (`base64 -d|--decode` piped to a shell; PowerShell
    `-EncodedCommand`/`-enc`; `FromBase64String` followed by `iex`/`Invoke-Expression`).
- **Precision bar for implementing a candidate:**
  - it matches ≤ 0.2% of benign units across all benign corpora (≤ 12 of 6,307);
  - it matches ≥ 15 malicious units that baseline-v2 missed (FN);
  - fewer than half of its malicious FN matches already carry an existing rule at HIGH or above in baseline-v2.
- **Precision bar amended (2026-11-04, user decision, after the Task 1 offline run).** The run DROPped every rule,
  three of four on the third bar. That bar assumed a new HIGH finding adds nothing to a FN that already carries one.
  Upstream scoring is additive across distinct rule ids (HIGH = 25·confidence; malicious iff risk > 50), and the
  matched FNs sit at risk 21–50, so the assumption is false. Bars 2 and 3 are replaced by the direct measure they
  stood in for. Implement a candidate iff:
  - it matches ≤ 12 benign units (bar 1, unchanged);
  - **replay:** at least 15 of the baseline-v2 FN units it matches would reach risk > 50 if one finding of the rule
    were added at its severity points × 0.8 (HIGH +20, MEDIUM +8) to the unit's baseline-v2 `risk_score`.

  `rulelab` reports the replay for both FN→TP and TN→FP. This is a post-hoc change, made by the user with the
  offline results in view. The spec's dev and acceptance rules are unchanged and still decide P5.
- Plan minimum: +0.5 recall points. Plan guard: FP on benign units containing any `curl|wget|iwr` install line must
  not rise by more than `N_FP`.

## Review Focus

1. **A vendor's own documented installer** (`curl -fsSL https://<vendor domain>/install.sh | sh`) does not fire
   LU1, because the host is a domain, not an IP or a paste service. Test: `test_lu1_ignores_vendor_domain`.
2. **An IPv4 address in an unrelated context** (`ping 10.0.0.1`, a version number like `1.2.3.4`) does not fire.
   Test: `test_lu1_requires_fetch_and_exec`.
3. **A password for something other than an archive** ("database password: x") does not fire LU2. Test:
   `test_lu2_requires_archive_and_run`.
4. **Base64 in documentation of an image data URI** does not fire LU4. Test: `test_lu4_requires_exec`.
5. **Code-fenced examples inside security-education skills.** Expect a match: the rule does not know intent. This is
   measured by the benign guard, not by a unit test; record the benign examples in the ledger.

---

### Task 1: Offline prototyping over the dataset

**Files:**
- Create: `benchmark/benchmark/rulelab.py` (a small harness tool, reusable by later rule work)
- Modify: `benchmark/pyproject.toml` (add `rulelab = "benchmark.rulelab:main"`)
- Test: `benchmark/tests/test_rulelab.py`
- Create: `benchmark/results/recall-p5-offline.md`

**Interfaces:**
- Produces:
  - `match_units(dataset: Path, patterns: dict[str, re.Pattern], units: list[str]) -> dict[str, set[str]]`, mapping
    each rule to the unit_paths it matches. It reads text files under each unit dir, with the same 2 MB per-file
    skip as the scanner's `MAX_FILE_CHARS`.
  - CLI `rulelab DB RUN --patterns-module benchmark.lure_candidates -o FILE`, which writes for each rule:
    - benign units matched;
    - malicious TP and FN matched;
    - FN matched that already have an existing HIGH+ rule;
    - matches by corpus;
    - and the precision-bar verdict `IMPLEMENT` or `DROP`.
- Also create `benchmark/benchmark/lure_candidates.py`, holding the four candidate patterns as compiled regexes
  (`PATTERNS: dict[str, re.Pattern]`).

- [ ] **Step 1:** Write failing tests for `match_units` on a tmp dataset: 2 benign and 2 malicious units, with
  known matches.
- [ ] **Step 2:** Run. Expect failures.
- [ ] **Step 3:** Implement `rulelab.py` and `lure_candidates.py`.
- [ ] **Step 4:** Tests pass. Run `uv run rulelab results/recall.duckdb $BV2 --patterns-module benchmark.lure_candidates -o results/recall-p5-offline.md`.
  You may revise a candidate regex **at most twice**, and only to remove benign matches. After each revision, re-run
  and record it in the offline report. A revision that was made to gain malicious matches is not allowed. Record the
  final verdicts.
- [ ] **Step 5:** Commit the code, tests and offline report with the message
  `feat(benchmark): rulelab offline rule prototyping; P5 lure candidates`.

If no candidate is `IMPLEMENT`, skip to Task 4 and write a REJECTED overview from the offline report.

### Task 2: The lure-rules static node

**Files:**
- Create: `src/skillspector/exaforce/_lure_rules.py`
- Modify: `src/skillspector/exaforce/__init__.py`
- Test: `tests/exaforce/test_lure_rules.py`

**Interfaces:**
- Consumes: `register_analyzer` (P2); the `static_runner.run_static_patterns_with_ledger` pattern (as in
  `_hidden_text.py`); and the **final** regexes from `benchmark/benchmark/lure_candidates.py`. Copy them; `src/`
  must not import from `benchmark/`.
- Produces:
  - `ANALYZER_ID = "exaforce_lure_rules"`;
  - `PASTE_HOSTS: tuple[str, ...]`;
  - `analyze(content, path, file_type) -> list[AnalyzerFinding]`, only for the rules marked `IMPLEMENT`;
  - `node(state)`.

- [ ] **Step 1:** Write failing tests:
  - one positive per implemented rule;
  - the four Review Focus negatives;
  - `test_lure_findings_reach_report`: full graph, `use_llm=False`, flag on, on a tmp skill;
  - `test_patterns_match_rulelab_copy`: assert each regex source equals the one in
    `benchmark/benchmark/lure_candidates.py` (read it as text) so the two cannot drift.
- [ ] **Step 2:** Run. Expect failures.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Tests pass, then the full suite passes.
- [ ] **Step 5:** Commit with the message `feat(exaforce): flag-gated lure rules EXA-LU*`.

### Task 3: Dev arms

- [ ] **Step 1: Focus set**, from `$BV2`:
  ```bash
  uv run evalset focus results/evalsets/p5-focus.txt --db results/recall.duckdb --run $BV2 --cap 900 --where "
    bf.boundary_cluster IN ('C05_msb_wild_usenix','C07_native_wild')
    OR bf.injection_pattern LIKE '%dropper%' OR bf.injection_pattern LIKE '%installer%'
    OR e.unit_path IN (<every unit, benign or malicious, matched by any IMPLEMENT rule in the rulelab output>)"
  ```
  Have `rulelab` also write `results/evalsets/p5-matched.txt`, and use it for the last clause. Then build
  `p5-dev.txt` as core plus focus, regenerate the splits, and record the composition.
- [ ] **Step 2:** Preflight. Control ×2. Candidates, each screened first (see below), then one more full run and `arms` against
  control:
  - L: `LURE_RULES=on`;
  - L+gate: L plus the HIGH `EXA-LU*` rules appended to `SKILLSPECTOR_EXA_GATE_RULES`, only if P1's gate is
    accepted.

  Each candidate runs `uv run screen` first, reusing the day's control runs; a FUTILE screen is that candidate's dev
  verdict, REJECT (spec, "Sequential futility screen"). Both are recall-raising (`--kind recall`, the default):
  ```bash
  uv run screen /Users/will/workspace/MalSkillBench/Dataset --db results/recall.duckdb \
    --units-file results/evalsets/p5-dev.txt --ref-run $BV2 --label p5-L \
    --control-runs <c1>,<c2> --treatment-env SKILLSPECTOR_EXA_LURE_RULES=on
  ```
  The reused control runs are the control replicates (×2); a PASSED screen's treatment union is replicate 1, and only
  the treatment gets one more full same-day run, then `arms`.
- [ ] **Step 3:** For each arm, record into the ledger:
  - ΔTP;
  - ΔTP on annotated `CORRECT` units against `intent`-tier units, kept separate;
  - ΔFP;
  - the guard FP.

  Choose the best PROMISING arm whose guard passes.
- [ ] **Step 4:** Commit the evalsets and the ledger with the message `docs(benchmark): P5 dev arms`.

### Task 4: Final acceptance, default flip, and overview

- [ ] **Step 1:** Full control and full treatment, same day, both healthy.
- [ ] **Step 2:** Apply acceptance plus the guard. If ACCEPTED, flip the defaults, plus the gate rules for `+gate`.
  Commit with the message `feat(exaforce): enable lure rules by default (P5 accepted)`.
- [ ] **Step 3: Overview** in `benchmark/results/recall-p5-report.md`, using the spec's two `report` commands. The
  verdict block must cover:
  - Δrecall on native wild, on the STB dropper cells and on MSB-wild;
  - the share of new TPs that are lure-only (`intent` tier or `UNVERIFIABLE`);
  - the benign matches, listed by unit, so a reader can judge them.
- [ ] **Step 4:** Commit the report and the ledger with the message `docs(benchmark): P5 overview`.
