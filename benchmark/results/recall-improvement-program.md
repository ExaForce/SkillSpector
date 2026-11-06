# Recall improvement program (P0–P7): what was tried and what came of it

<sub>Written 2026-11-06 as the entry point for the single PR that carries plans P0–P7 (branch
`exaforce/recall-p7-model-split`, one linear stack on `main`). It stands on its own; the detailed records it summarises
are listed in [Where the records live](#where-the-records-live). Every number here is copied from those records. Where
two records disagree, the text says which one was used.</sub>

## TL;DR

- **Goal** (`docs/superpowers/specs/2026-10-29-recall-improvement-program.md`): raise malicious-skill recall above the
  0.709 of run `113b02ab497b` while keeping precision at about 0.92 or better.
- **Outcome: met, by a small margin.** The shipped defaults reach recall **0.734** at precision **0.926** on all
  12,718 units (head run `60503e65c287`). Against the original: +0.025 recall, −0.002 precision.
- **Only about +0.015 of that is causal**, measured same-day: P5 lure rules +0.0064 (+0.0059 after drift
  correction) and P6 threshold 49 +0.0087. The rest is endpoint drift and run-to-run churn, which is large: with
  identical classifier code, 7.4% of units changed outcome between two runs 5 days apart (P0).
- **Shipped, on by default:**
  - P5: static lure rules `EXA-LU1` (pipe-to-shell from an IP literal or paste service) and `EXA-LU4` (base64
    decode piped into an interpreter or `eval`). Flag `SKILLSPECTOR_EXA_LURE_RULES`, `=off` disables (`45fb9511`).
  - P6: block threshold 49 instead of 51, with a score clamp so CLI and MCP agree. Flag
    `SKILLSPECTOR_EXA_BLOCK_THRESHOLD`, `=51` restores upstream (`4e6863d1`, `33271de5`).
- **Not shipped (code rolled back, records kept):**
  - P1 semantic gate, P3 skill context / instruction flow, P4 necessity audit: each found real misses (ΔTP +31.5,
    up to +113, up to +79 on their dev sets) and was **rejected on FP cost and run health**, not for too little
    gain.
  - P7 stronger model for the SSD slot: rejected for too little gain (best +13 TP against a bar of 20).
  - P2 text from PDF/office files and hidden-text rules: **no verdict** (one replicate only), rolled back.
- **The lasting asset is the measurement tooling** built in P0 and after (`arms`, `screen`, `replay`, `health`,
  `report` extras, `evalset`, `rulelab`), and the protocol around it: same-day replicated arms, noise floors,
  pre-registered verdicts, a futility screen, a health gate, and holdout scoring.
- **Why most remaining misses stay missed:** on P7's dev set about 90% of missed malicious units carry no HIGH+
  semantic (SSD) finding under any of four models. The dominant limit is **detection**, not the scoring cap. The
  scoring cap (one HIGH LLM finding scores at most 25 of the ~50 needed) is real but explains a minority of misses.

## 1. Starting point: why recall was low

The original run `113b02ab497b` (2026-10-28, `nvidia.nemotron-super-3-120b`, LLM on, 12,718 units: 6,403 malicious,
6,315 benign) had recall 0.709 and precision 0.928. The analysis behind the program is `benchmark/recall-boundaries.md`
(revised after an independent check in `benchmark/recall-boundaries-review.md`). Its main findings:

- **Low recall is mostly a corpus effect.** Every behaviour below 0.80 gets most of its misses from two imported
  corpora, SkillHarm (recall 0.22) and MaliciousSkillBench (0.32). On units with valid labels, SkillTrustBench (STB)
  recall is about 0.95 and every other corpus together about 0.46. Every report since P0 therefore shows STB and
  non-STB recall separately.
- **Many misses are not working malware.** An outcome-blind annotation of 412 units puts the sampled clusters' FNs at
  about 26% not malicious (WEAK, MISLABELED), 22% intent without a working payload (BROKEN, UNVERIFIABLE) and 51%
  working payloads.
- **Recall rises with package size** because the scorer is additive: 0.45 for SKILL.md-only units against 0.77 for
  multi-file ones. The benign FP rate rises the same way, to 48.8% for benign units with 21+ files.

### Boundaries and the options that targeted them

| boundary | what it is | option → plan |
|---|---|---|
| B0 label validity | not a classifier limit: MSB units sanitised or redacted, placeholder hosts, STB "suspicious" tier | O0 measurement → P0 (tooling, tiers in reports) |
| B1 scoring | the LLM finds it, but one HIGH finding adds 25·confidence and blocking needed > 50; one CRITICAL at 0.95 scores 47 | O1 semantic gate → P1; O6 threshold → P6 |
| B2 visibility | payload where the per-file LLM cannot see it: PDF text (all 127 SkillHarm PDF payloads are white text), or an auxiliary doc judged without the SKILL.md that tells the agent to obey it | O2 doc text → P2; O3 skill context → P3 |
| B3 purpose-fit harm | domain-contextual harm: falsified numbers, swapped recommendations, a "preflight" that deletes one log; recall about 0.25 | O4 necessity audit → P4 |
| B4 (withdrawn) | "prose vs script" was a SkillTrustBench pooling artefact | none |
| B5 remote-only lures | the package only points at a download; recall about 0.05 | O5 lure rules → P5 |
| (model) | not measured in the analysis | O7 → P7 |

The 11 behaviours below 0.80 recall in the original run, and where each stands now, are in
[Section 5](#per-behaviour-recall).

## 2. How the program was run

- **One plan per option, in order P0 → P7, one session each**, on stacked branches. Every plan pre-registered its
  candidates, its decision rule and its guards before any run, so verdicts were applied mechanically. Any change to
  a rule after data was seen is recorded as a numbered ruling (for example P1-R9, P5-R16) and called post-hoc where it
  was.
- **Every classifier change shipped behind a `SKILLSPECTOR_EXA_<NAME>` flag**, read on every call, default off until
  final acceptance. Classifier code lives only in `src/skillspector/exaforce/` as drift-guarded runtime patches;
  harness code only in `benchmark/`. No new runtime dependencies.
- **A rejected plan's code was rolled back and its record kept** (the user's convention from P3 on): the report, the
  ledger section, the evaluation sets and the runs in `recall.duckdb` stay; the code is recoverable from the listed
  commits.

### Pre-P0 commits included in this PR

- `9e8c48cb`: `benchmark --workers` defaults to the smallest of half the RAM at 256 MB per worker, 6 per CPU, and 96
  (throughput peaks near 96 on a 16-core Mac, then Bedrock queues). The harness stores attempted vs succeeded LLM
  calls per scan and warns when scans dropped calls. That count became `health`'s dropped-call check.
- `c3cc13f2`: `src/skillspector/exaforce/UPSTREAM_UPGRADE_HOLD.md` records why the fork stays on upstream 2.8.1: the
  best patched 2.13.1 tree still had 2× the FPs, 45 scan timeouts and 2.7× slower scans.

## 3. Measurement method and tooling (P0 and after)

### Why it was needed

- **Per-unit churn.** `baseline-v2` (`e16e394f65c3`, 2026-11-02) and the original run (2026-10-28) used identical
  classifier code: 492 units fixed and 449 regressed, 7.4% of all units. That spans 5 days, so it is churn plus
  endpoint drift; the spec's estimate for same-day re-runs is about 3%. Near the cut a unit's verdict is close to a
  coin flip: in P6's live smoke check, scores of units near the cut moved 2–51 points (median 26) from run to run.
- **Endpoint health.** Dropped LLM calls silently remove LLM findings and so bias a run toward FN and low FP. The
  original run dropped calls in 6.9% of scans; P3 dev runs dropped 5.0–10.7%, P4 6.6–9.4% (screen batches up to 13.4%).
- **Drift.** Any comparison across days mixes endpoint drift into the effect. In P5's full pair, units the rules could
  not touch moved +59 TP / −11 FP, about 1 recall point, larger than the rules' own effect.

So every claim in this program is a same-day comparison on the same code tree, with arms differing only in env flags.

### Tools (all under `benchmark/`, run with `uv run <tool>` from `benchmark/`)

| tool | what it is for | key commits |
|---|---|---|
| `benchmark` | scans; `--units-file` scans an explicit unit list; persists finding tags (`llm-unconfirmed`) and run config; refuses to resume a run under different flags; atomic per-unit recording | `04c3f727`, `e3434f82`, `6134a95a`, `e2023f4e`, `1db355d1` |
| `health` | gate for poisoned or degraded runs: an LLM run with no `SSD-`/`SDI-`/`SQP-` issues; dropped LLM calls > 10% of scans (5% until P4); ERROR > 1%; median scan time < 3 s. Judges a union of screen batches pooled, as one run | `47cdc4e2`, `422a4895`, `256b294b` |
| `report` | head vs base: outcomes, precision/recall, health, STB/non-STB split, label-validity tiers, SkillHarm attributed recall, per-behaviour, `--split-file` dev/holdout | `669930d8`, `51354d39` |
| `attribution` | derives which files of each SkillHarm unit are the injected payload (`_skillharm_injected.jsonl`), so SkillHarm recall can be counted only when attributable | `d4888e2a`, `4c2a59fe` |
| `replay` | re-decides a stored run under another scoring policy (threshold, rule gate, doc-finding cap) and writes a synthetic run; no scans, no LLM. Exact for pure scoring changes | `f29f3f5e`, `c3e415af` |
| `evalset` | deterministic dev, focus and holdout sets (seed 29): `core` (all 412 annotated + all FPs + 600 stratified TNs), `focus --where`, `splits` | `ccf30f1b` |
| `arms` | same-day arm comparison: replicate means, noise floors, the pre-registered PROMISING/REJECT verdict, run provenance; accepts union replicates (`a+b`) | `ee46dbf2`, `503b024c`, `8fbdfa84` |
| `screen` | sequential futility screen: scans a dev set in stratified batches against reused same-day controls, stops early only to reject | `dd69e346`, `0e8b3cd7`, `422a4895`, `2eea2ea0` |
| `rulelab` | exact benign and malicious match counts for candidate static regexes over the dataset files, joined to a run's outcomes, plus a replay of what one added finding would flip | `553b7d0d`, `29929aab` |

The program DB is `benchmark/results/recall.duckdb` (gitignored, local), a copy of the seed DB with every program run
appended. It also holds the original run.

### Protocol (spec, "Evaluation protocol" and "Decision rules")

1. **Offline first.** Scoring changes are quantified by `replay` over a stored full run; static rules by `rulelab`.
   Live arms then confirm.
2. **Dev arms.** On the plan's dev set (core-dev, 1,364 units, plus the plan's focus set), control and treatment are
   each run twice, the same day, on the same tree. Controls are reused for every candidate that day.
3. **Noise floor.** `N_TP = max(3, |TP(c1) − TP(c2)|)`, `N_FP = max(2, |FP(c1) − FP(c2)|)`.
4. **PROMISING (recall-raising)** iff `ΔTP ≥ 2·N_TP`, `ΔFP ≤ max(N_FP, ΔTP/8)` (at least 8 TPs per extra FP), and both
   treatment replicates pass `health`. Otherwise REJECT. At most 5 candidates per plan.
   An FP-reducing candidate needs `−ΔFP ≥ 2·N_FP`, `−ΔTP ≤ −ΔFP/2`, and no drop in SkillHarm attributed recall.
5. **Sequential futility screen v2** (pre-registered and validated 2026-11-04, before any live use). Batches of 150,
   seed 29, at least 3 batches before a stop, z = 2.8. It projects the final two-replicate `arms` totals and stops
   (FUTILE = REJECT) when even the optimistic bound misses the TP bar, or when the 8:1-weighted gain is surely
   negative and ΔFP surely exceeds N_FP. The FP clause is off when N_FP is unknown (fewer than 2 complete reused
   controls). It never accepts. On historical replays it stopped 0 of 4 promising, 4 of 10 reject and 2 of 3 null
   replays. A passed screen's union is treatment replicate 1; one more full run follows.
6. **Health.** A replicate passes when at most 10% of its scans dropped an LLM call (5% for P0–P4; amended
   2026-11-04 before any P5 run, because every P4 run that day, controls included, dropped 6.6–9.4%). An unhealthy
   replicate is replaced once, same tree and day; if the replacement is also unhealthy, all replicates are used
   (rulings P1-R7, P3-R12, P4-R10).
7. **Full-run acceptance.** One full treatment run and one same-day full control (about 1 h each at 96 workers):
   recall gain ≥ +0.5 points, precision ≥ control − 0.005, holdout recall gain ≥ 0, both runs healthy, plus any plan
   guard.
8. **Holdout split.** `results/evalsets/splits.tsv`: every unit in no dev set is holdout. It was regenerated as dev
   sets grew; it now holds 4,241 dev and 8,477 holdout units.

**Run conventions.** Every scan used `-o results/recall.duckdb --auth-wait-seconds 0` (an SSO expiry aborts to a
resumable DB instead of waiting), `--units-file`, a `--description` label, and a preflight (AWS identity plus a 1-unit
LLM scan that must pass `health`). Arms were launched through a session wrapper (`run-arm.sh`, not committed) that
detects stalls by **log growth** (the DuckDB file is locked for the whole run, so polling it does nothing) and resumes
a stalled run with `--run-id <id>`, which rescans only missing units. Every run gets one ledger row.

## 4. The plans

| plan | change | verdict | same-day Δrecall (where) | Δprecision | code status |
|---|---|---|---|---|---|
| P0 | measurement tooling; `baseline-v2` `e16e394f65c3` | n/a | +0.003, drift only (full set) | +0.003 | tooling kept |
| P1 | semantic-finding gate; doc-finding cap | REJECTED (FP cost) | +0.076 (dev 1,364) | +0.030 | rolled back `5a0bbb04` |
| P2 | text from PDF/office; hidden-text rules | no verdict (1 replicate) | rep 1: +37 TP / +3 FP (A), +37 / −13 (B) (dev 2,154) | – | rolled back `68032655` |
| P3 | skill-context header; per-skill instruction flow | REJECTED (FP cost, health) | +0.097 best arm B3 (dev 2,112) | +0.030 | rolled back `1b950d70` |
| P4 | necessity audit (SSD-5; EXA-NE1) | REJECTED (FP cost, health) | +0.070 best arm B (dev 2,393) | −0.010 | rolled back `b9354821` |
| P5 | lure rules EXA-LU1, EXA-LU4 | **ACCEPTED** | **+0.0064** (full set, rule-affected units: +41 TP / 0 FP) | +0.0006 | **on by default** |
| P6 | block threshold 51 → 49, score clamp | **ACCEPTED** | **+0.0087** (full set, paired replay: +56 TP / +26 FP) | −0.0040 | **on by default** |
| P7 | stronger model for the SSD slot | REJECTED (too little gain) | +0.032 best, deepseek (dev 1,364) | +0.029 | no classifier code; records rolled back `cb417b57` |

Dev-set deltas are on each plan's own dev set and do not compare across plans. The dev sets are FP-heavy by
construction, so dev precision is far below full-set precision. P5's Δprecision is the program summary's figure for
the rule effect alone (+41 TP / 0 FP on the control's totals); the whole-set pair moved +0.0036, mostly drift.

### P0: measurement (tooling, `baseline-v2`)

- **Hypothesis:** later plans need tooling that separates an effect from noise, drift and endpoint failure.
- **Built:** the tools in Section 3, the core dev set (`core-dev.txt`, 1,364 units: 412 annotated malicious, 352
  original FPs, 600 stratified TNs) and `splits.tsv`, plus `baseline-v2`.
- **Numbers:** `baseline-v2` recall 0.712, precision 0.931, healthy (4.2% dropped, 0 errors). The original run fails
  `health` (6.9% dropped). 7.9% of SSD HIGH/CRITICAL findings (198 of 2,509) are `llm-unconfirmed` (kept by the
  severity floor, not confirmed by the meta-analyzer). The `baseline-v2` run crashed at unit 10,638 on an out-of-range
  line number; `1db355d1`/`e2023f4e` fixed it and the run resumed.
- **Takeaway:** 7.4% per-unit churn with identical code is why every later claim is same-day and replicated.

### P1: semantic-finding gate and doc-finding cap (O1, B1)

- **Hypothesis:** block any unit with a HIGH+ `SSD-1..4` or `P2` finding (`confirmed` mode: only meta-confirmed
  findings); optionally cap MEDIUM findings from documentation files to cut FPs.
- **Offline** (replay of `baseline-v2`): gate `any` +210 TP / +24 FP, `confirmed` +185 / +18 (recall 0.712 → 0.741,
  precision −0.001); holdout +159 / +14 (11:1). No cap setting removed 10 FPs, so the cap was dropped.
- **Dev** (`p1-dev` = core-dev, 1,364 units, `a7497284`): control 154.0 TP / 199.0 FP, gate 185.5 / 212.5. ΔTP +31.5,
  ΔFP +13.5 against an allowance of max(N_FP 8, 3.9) = 8. **REJECT** on FP cost.
- **Why, and how firm:** the verdict is fragile. Control FP across three replicates spanned 195–216, wider than the
  effect, and two of three controls were unhealthy at 5%. With any other control pairing the verdict would have been
  PROMISING; the pre-registered pair stood (ruling P1-R9). The dev set (412 malicious, 952 benign) makes the 8:1 rule
  much harsher than on the full set. Offline predicted +26 TP / +4 FP on these 1,364 units; live gave +31.5 / +13.5.
- **Code status:** rolled back in `5a0bbb04` (code commits `89959bf3`, `a7497284`, `0def3298`; recoverable from
  `89959bf3`..`0def3298`). Flags `SKILLSPECTOR_EXA_SEMANTIC_GATE`, `SKILLSPECTOR_EXA_DOC_MEDIUM_CAP`,
  `SKILLSPECTOR_EXA_GATE_RULES` and `SKILLSPECTOR_EXA_GATE_MIN_SEVERITY` no longer exist. `_score_patches` keeps only
  P6's threshold. Two pieces stay: `_patchlib.intercept_module_callable` from `89959bf3`, which P6 and the lure rules
  use, and `replay`'s gate and cap policies, which are offline benchmark tooling.
- **Takeaway:** the cheapest offline win of the whole analysis (+0.029 recall at flat precision) was never given its
  full-run acceptance test; it lost on a dev-set FP rule that was noisier than the effect.

### P2: text from PDF/office files and hidden-text rules (O2, B2)

- **Hypothesis:** let the analyzers see text inside `.pdf/.docx/.pptx/.xlsx` (stdlib extractor, bounded parsing), and
  flag text hidden from a human reader (white PDF text, zero-width/bidi characters, imperative HTML comments) as
  `EXA-HT1..3`.
- **Dev** (`p2-dev`, 2,154 units, `e5de1bf2`): replicate 1 only. A (extraction) +37 TP / +3 FP; B (A plus hidden-text
  rules) +37 / −13 against control. Control replicate 2 hung (all workers idle, per-scan timeout never fired) and was
  killed. The user moved on to P3, so there is **no verdict**.
- **Caveats:** the focus set's malicious units are 97.5% SkillHarm (one generator), so they fail the spec's two-corpus
  evidence rule. The benign corpus has 6 PDFs, all in one unit, so precision of PDF and hidden-text rules is
  unmeasured.
- **Code status:** rolled back in `68032655` (code commits `ead32f4b`, `7bca8f5a`, `6dc92e6a`, `33125165`,
  `e5de1bf2`; recoverable from `ead32f4b`..`e5de1bf2`). `_doc_text`, `_build_context_patches` and the `EXA-HT1..3`
  analyzer are gone, and flags `SKILLSPECTOR_EXA_DOC_TEXT` and `SKILLSPECTOR_EXA_HIDDEN_TEXT` no longer exist.
  - P5's shipped lure analyzer depended on two pieces of P2's plumbing, so they stay:
    - `_analyzer_registry`, from `33125165`;
    - the shared `static_runner.is_code_example` bypass. It moved out of `_hidden_text` into
      `exaforce/_fork_context.py`, and the lure rules now install it themselves.
  - The registry tests now use the lure analyzer. The root conftest's registry xfail now names
    `exaforce_lure_rules`.
- **Takeaway:** the only targeted fix for B2 (Persistence, part of Data Exfiltration) has a single, promising,
  one-generator replicate and nothing more.

### P3: skill-level context and per-skill instruction flow (O3, B2/B3)

- **Hypothesis:** per-file LLM calls miss payloads whose meaning depends on SKILL.md. Candidates: A1/A2 prepend a
  "referenced by SKILL.md" context header (SSD only / all semantic analyzers); B1 a new per-skill analyzer `EXA-IF1`
  that reads SKILL.md plus referenced files as one bundle and reports instructed actions the purpose does not need;
  B3 = B1 with one prompt revision.
- **Dev** (`p3-dev`, 2,112 units, 2026-11-03; 4 controls, N_TP 98, N_FP 30): A1 +23.2 TP / +9.2 FP, A2 +17.2 / +22.2,
  B1 +99.5 / +30.2, B3 +112.8 / +29.5 (B3 also failed the multi-doc FP guard, +31.25 > 30). All **REJECT**.
- **Why:** N_TP 98 came from one control with 184 ERROR outcomes; without it (N_TP 15, N_FP 19) B1 is +77 / +25 and
  B3 +90 / +24, still about 3–4 TPs per FP against the required 8. 16 of 18 dev runs failed `health` at 5%. B1 raised
  dev precision (0.642 → 0.665) and still failed, because the rule counts raw FPs on an FP-heavy dev set. Of the 458
  units FN in all four B1 replicates, 97 already carried a HIGH IF1: the scoring cap limited those.
- **Code status:** rolled back in `1b950d70` (`src/` and `tests/` restored to `25e5baf3`; recoverable from
  `434e2290`..`f4f65f36`).
- **Takeaway:** a per-skill bundle view does find misses (C02 SkillHarm-redirect recall 0.163 → 0.287), but the
  analyzer's FP sources were never characterised (the written FP classes did not move FP), and its context header put
  attacker-controlled text above the instructions, unfenced.

### P4: necessity audit (O4, B3)

- **Hypothesis:** ask whether each imperative step is needed for the skill's stated purpose. A: an `SSD-5` category in
  the SSD prompt. B: a per-skill necessity analyzer `EXA-NE1` on SKILL.md. B-rev: B with one prompt revision.
- **Dev** (`p4-dev`, 2,393 units, 2026-11-04; 4 controls, N_TP 23, N_FP 27): A +30.5 TP / +20.5 FP (below the
  noise floor); B +79.0 / +48.0 (recall 0.450 → 0.520; fails the FP rule and the setup-language guard, +29.8 > 27);
  B-rev +63.5 / +30.5 (fails ΔFP ≤ 27 by 3.5; its first two replicates had passed). All **REJECT**; 0 of 12 full dev
  runs and 3 of 32 screen batches were healthy at 5%, so nothing could have been PROMISING that day.
- **Why:** NE1 read ordinary setup, output and safety rules as unneeded. 166 of B's 550 dev FNs already carried a HIGH
  NE1 (scoring cap). 7 of 10 sampled FNs put the harm in a script that SKILL.md tells the agent to run, which a
  SKILL.md-only analyzer cannot see. A quarter of SSD-5 findings landed on non-markdown files despite the prompt's
  scope sentence.
- **Code status:** rolled back in `b9354821` (`src/` and `tests/` restored to `1b950d70`; recoverable from
  `80daf70e`..`75f9f822`, measured NE1 prompt at `75f9f822`).
- **Takeaway:** Content Manipulation, the weakest behaviour, moved at most +0.070 on dev and the cost was FPs on
  legitimate setup language. NE1's purpose header was also attacker-controlled and unfenced: a skill can claim every
  step is required. Fence it before any revival.

### P5: lure rules (O5, B5)

- **Hypothesis:** static rules for remote-installer lures catch units whose payload is never in the package.
- **Offline** (`rulelab` over `baseline-v2`): four candidates. Under the amended per-rule bar (benign matches ≤ 12;
  ≥ 15 FNs that one added finding would lift past 50), `EXA-LU1` (16 of 25 matched FNs, 0 benign) and `EXA-LU4`
  (42 of 72, 5 benign security tools quoting attack patterns) were implemented; `EXA-LU2` (archive password, 4) and
  `EXA-LU3` (skip-verification install, 0) dropped. The original third bar would have dropped every rule; it was
  replaced post-hoc with the user's decision (`067cdd0c`) because it wrongly assumed a second HIGH finding adds
  nothing.
- **Dev** (`p5-dev`, 2,296 units): +46 TP / +4 FP, N_TP 4, N_FP 2, **PROMISING**. The fetch-line guard failed as written
  (+4.5 FP > 2), but attribution showed only 2 benign units with an LU finding and at most 0.5 attributable FP per
  replicate; 46 of the 246 guard units flip between two identical controls. On the 305 rule-matched dev units L moved
  +48.5 TP / −0.5 FP.
- **Acceptance (re-registered post-hoc in `21e37201`, before any full run):** judged on `M`, the 301 units with an
  `EXA-LU*` finding in the full treatment run. Full pair control `0e0f9e105cf8` / treatment `93c1faec5bec` at
  `8ab36a84`, both healthy (8.1%, 8.4%): +41 TP on `M` (+0.0064 against a bar of +0.005), 0 FP, `M` has no holdout
  units. Drift-corrected gain about +38 (+0.0059). STB dropper/installer cells +0.142.
- **Final review:** the LU1 regex backtracked cubically on crafted long lines; three fixes (`f8ed9439`, `3433ba97`,
  `8ab36a84`) bounded every gap and window long lines instead of skipping them (skipping was an evasion).
- **Code status:** shipped, on by default from `45fb9511`; `SKILLSPECTOR_EXA_LURE_RULES=off` disables.
- **Takeaway:** judge a static rule on the units it fires on. A whole-set gate measures LLM drift on units the rule
  cannot touch; the first decision ("reject as written") rested partly on an undercount of the dev gain (+28 instead
  of +48.5, from counting only units FN in both controls).

### P6: block threshold (O6, B1)

- **Hypothesis:** scores pile up just under the cut; a lower threshold recovers them cheaply.
- **Offline** (paired replay of the healthy full run `bfa51d835e8b`, T = 31..61, selection rule P6-R2 fixed before any
  data): **T = 49**. Recall 0.7248 → 0.7336 (+0.0087), precision 0.9304 → 0.9264 (−0.0040, against an allowed
  −0.005), +56 TP / +26 FP, holdout +0.0038. T = 47 fails the FP cap and precision clause. Replication on P5's
  `93c1faec5bec` also picks 49 (+0.0069 / −0.0030).
- **What moves:** only units scored 49 or 50 (82 in the source run). The 26 new FPs are all benign-corpus units and
  include mainstream integrations (Asana, Canva, GA4, Snowflake, MS365); `SQP-2` is the most common HIGH rule among them.
- **Clamp** (`33271de5`, final review C1): a blocked score is lifted to at least 51 and an unblocked one capped at 50,
  so the CLI exit code and MCP `safe_to_install` (both keyed on `score > 50`) agree with the recommendation. The
  benchmark reads only the recommendation, so it could not have caught this.
- **Code status:** shipped, 49 by default from `4e6863d1`; `=51` restores upstream; range 21–80. Five upstream
  `tests/nodes/test_report.py` tests are strict xfail while the threshold is ≤ 50 (14 xfailed in the root suite, unchanged after the P1/P2 rollbacks).
- **Takeaway:** paired replay has zero arm-to-arm noise, but the threshold is still fitted on one run's scores; the
  independent replication's smaller gain (+0.69 vs +0.87 points) is the honest estimate of the optimism.

### P7: a stronger model for the SSD slot (O7)

- **Hypothesis:** a stronger model in the per-skill passes finds more. P3 and P4's per-skill nodes were rolled back, so
  the slot was `SKILLSPECTOR_MODEL_SEMANTIC_SECURITY_DISCOVERY` (an upstream per-slot model setting; every other slot
  stayed on `nvidia.nemotron-super-3-120b`). The user chose the three largest open-weight models on the endpoint
  (`910859ed`); all passed a 5-unit probe.
- **Dev** (`p7-dev` = core-dev, 1,364 units, 2026-11-05; controls `7f54de6438ea`, `6822ec3bf3eb`, N_TP 10, N_FP 5, bar
  ΔTP ≥ 20): `deepseek.v3.2` +13.0 TP / −10.0 FP (the only one better on both axes), `mistral.mistral-large-3-675b-instruct`
  +5.5 / +2.5, `qwen.qwen3-235b-a22b-2507` screen FUTILE (+5 / −0.5). All **REJECT**. All passed the cost guard (p95
  ≤ 1.5× control) and the rule-id check.
- **Why:** stronger models add mostly MEDIUM SSD findings (mistral 405 and 389 per replicate against control's 24 and
  27), mostly on units already caught. Caught units carrying a HIGH+ SSD finding rise by about 10–13, matching the TP
  gain. About 90% of missed units carry no HIGH+ SSD finding in any arm; the scoring cap can explain at most the 11–35
  missed units per arm that do, and the control has 23–26 of those too. So the misses are a **detection gap**, not the
  scoring cap.
- **Harness fix kept:** `79176a33`. One scan produced an issue whose `explanation` was an object, and recording it
  aborted the run. SSD findings cannot carry `explanation` (the fork's schema patch removes it); the likely source is
  `mcp_tool_poisoning` TP4 on the default model, so any run can hit it. The harness now stores such values as JSON.
- **Code status:** no classifier code was written. The P7 records (plan amendment, ledger rows, dev evalset, screen
  manifests, report, program summary) were removed in `cb417b57`; recoverable from `910859ed`..`0702a6dd`, for example
  `git show 0702a6dd:benchmark/results/recall-p7-report.md`. This document carries the outcome.
- **Takeaway:** the dev bar (ΔTP ≥ 20 on 412 malicious units, about +4.9 points) cannot see a real +3-point gain like
  deepseek's. The P7 report still recommends no re-test, because the extra findings land on caught units; a model
  change is worth another look only if it raises HIGH+ findings on missed units.

## 5. Cumulative results

Both comparisons cross days and include drift and churn, so they are not causal. The per-plan same-day rows in
Section 4 are the causal estimates. Head run: `60503e65c287`, P6's replay of the full run `bfa51d835e8b` at T = 49 with
the clamp (it carries P5's lure rules, on by default at `c0e4ccaa`). P7 made no full run.

| | original `113b02ab497b` | `baseline-v2` `e16e394f65c3` | current defaults `60503e65c287` | Δ vs original | Δ vs baseline-v2 |
|---|---|---|---|---|---|
| recall | 0.709 | 0.712 | **0.734** | +0.025 | +0.022 |
| precision | 0.928 | 0.931 | **0.926** | −0.002 | −0.005 |
| TP / FP | 4,538 / 352 | 4,557 / 336 | 4,697 / 373 | +159 / +21 | +140 / +37 |
| holdout recall | 0.873 † | 0.873 | 0.879 | † | +0.006 |
| holdout precision | 1.000 † | 0.972 | 0.964 | † | −0.008 |
| non-STB recall | 0.427 | 0.437 | 0.464 | +0.037 | +0.028 |

† **Holdout selection bias.** The dev sets were drawn from the original run's outcomes. Every unit it got wrong on
the benign side went into a dev set, so its holdout precision is 1.000 by construction; 1,355 of its 1,865 FNs (73%)
are in dev although dev holds 37.5% of malicious units, so its holdout recall is inflated. Holdout deltas against the
original are meaningless; use the `baseline-v2` column. The original run also fails today's `health`, so `baseline-v2`
is the cleaner comparator in general.

### Per-behaviour recall

The 11 behaviours below 0.80 recall in the original run (`report` "By behavior"; units without a behaviour label are
left out). Original against current defaults:

| behaviour | n | original | current | Δ | still < 0.80 | boundary that explains the remaining gap |
|---|---|---|---|---|---|---|
| Content Manipulation | 250 | 0.248 | 0.240 | −0.008 | yes | B3 output integrity; only O4 targeted it and P4 was rejected |
| Credential Theft | 154 | 0.299 | 0.305 | +0.006 | yes | B0: MSB units sanitised or redacted; mostly a label problem |
| Role Hijack | 13 | 0.308 | 0.385 | +0.077 | yes | B1 scoring; P1's gate recovered these but was rejected |
| System Prompt Leak | 43 | 0.302 | 0.395 | +0.093 | yes | B1 scoring, as Role Hijack |
| Safety Bypass | 20 | 0.350 | 0.500 | +0.150 | yes | B1 scoring, as Role Hijack |
| Remote Code Execution | 81 | 0.370 | 0.407 | +0.037 | yes | B0 + B5: MSB vendor pipe-to-shell templates; P5 covers part |
| Resource Abuse | 122 | 0.434 | 0.475 | +0.041 | yes | B3: SkillHarm `dos` presented as preflight, plus B0 placeholders |
| Goal Hijacking | 234 | 0.598 | 0.590 | −0.008 | yes | B2/B3, SkillHarm only (STB is 1.00) |
| Persistence | 285 | 0.730 | 0.758 | +0.028 | yes | B2: shell-rc edits in PDFs or auxiliary docs; P2 has no verdict |
| Data Exfiltration | 304 | 0.734 | 0.740 | +0.006 | yes | B0 placeholder hosts plus a SkillHarm detection gap (B2/B3) |
| Privilege Escalation | 1,071 | 0.789 | 0.811 | +0.022 | **no** | crossed 0.80 |

Small slices move a lot by chance (Role Hijack is 13 units, Safety Bypass 20). Against `baseline-v2`, System Prompt
Leak (0.465 → 0.395) and Role Hijack (0.462 → 0.385) went down, so their gains against the original are within
run-to-run noise. Only P5's rules (RCE, STB dropper cells) and P6's threshold (every behaviour, a little) are causal
contributors to this table.

## 6. Lessons

### Methodology

1. **Only same-day, replicated, paired comparisons carry a claim.** Cross-day deltas of a point or more appear with
   no code change (P0: 7.4% of units flipped; P5: about +1 point of drift outside the rule-affected units).
2. **Endpoint health dominated the dev runs.** At the original 5% threshold, 16 of 18 P3 dev runs and 0 of 12 P4 full
   dev runs passed. Replacing unhealthy replicates roughly doubled endpoint time and never produced healthy ones. The
   10% threshold (from P5) let runs pass; it did not fix the drops. Dropped LLM batches drop their findings, so drops
   bias a run toward FN and toward low FP (P1's unhealthy control likely had its FP count biased low this way).
3. **The FP rules bit every LLM-recall change.** P1, P3 and P4 each found real misses and failed on `ΔFP ≤ max(N_FP,
   ΔTP/8)`, a guard, or health. The dev sets are FP-heavy (core-dev: 412 malicious vs 952 benign, 352 known FPs), so
   the raw-count 8:1 rule is much harsher there than on the full set: P3 B1 raised dev precision and still failed.
   Where a dev verdict is close, the spec's full-run acceptance pair is the better arbiter, and no plan ever got one
   for an LLM change.
4. **Judge a static rule on the units it fires on.** A static finding can only raise its own unit's score, so its
   effect and its FPs are attributable. Count every flip in those units, not only units FN in both controls (P5's
   undercount). Pre-register guards as attributable, or against the guard's own control spread.
5. **Scoring cap or detection gap: count before you blame.** For the missed units, count how many carry a HIGH+
   finding of the relevant rule. P3: 97 of 458 always-FN units carried a HIGH IF1. P4: 166 of 550 FNs carried a HIGH
   NE1. P7: about 10% of FNs carried a HIGH+ SSD finding. Where that share is small, no scoring change will help; the
   analyzer has to see the harm. (P7's first draft blamed the cap; the final review disproved it.)
6. **Replay is exact for scoring changes, with two traps.** Replay sources must be recorded at
   `SKILLSPECTOR_EXA_BLOCK_THRESHOLD=51`: at the default the stored score is clamped, so a raw 49 or 50 is stored as 51
   and later replays near the cut are silently wrong. `bfa51d835e8b` predates the default and is safe. Replay also
   gates the stored pre-dedup issues while the classifier scores deduplicated findings (bounded at ≤ 3 units on
   `baseline-v2`).
7. **Pre-register, and label what is post-hoc.** The futility screen, the health amendment and P6's selection rule
   were fixed before data. P5's offline bar and acceptance criteria were changed after results were seen; both are
   recorded as user decisions and called post-hoc in the records.
8. **Flag provenance changes with defaults.** Unset `SKILLSPECTOR_EXA_LURE_RULES` meant off before `45fb9511` and on
   after; unset `SKILLSPECTOR_EXA_BLOCK_THRESHOLD` meant 51 before `4e6863d1` and 49 after. `arms` and resume pinning
   compare env values only, so a control that needs the old behaviour must set `=off` or `=51` explicitly.
9. **The harness needs its own robustness.** The DuckDB file is locked for a whole run: watch log growth, query a
   copy. Runs can hang at the last unit (P2 control r2, P3 B3 r2; root cause unknown): resume with `--run-id`. One
   unrecordable scan still aborts a whole run (`79176a33` fixed one cause). A model whose calls all fail still records
   a normal-looking LLM run, which is why `health` checks for semantic issues and median scan time. A model listed by
   the endpoint is not necessarily routable: probe it first (P7 did).

### Product

1. **One HIGH LLM finding cannot block.** It adds 25·confidence; blocking needs 51 (49 since P6). Any new LLM
   analyzer that reports one HIGH finding per skill needs a scoring path, not prompt work, to turn findings into
   verdicts.
2. **Scores pile up just under the cut.** Score 50 alone held 66 units (43 malicious, 23 benign) in P6's source run, and
   P5's matched units with a HIGH static finding at confidence 0.95–1.0 still landed at risk 43–47. The suspect,
   unverified, is the fork's "meta-analyzer verdict over static severity" patch.
3. **Package size drives both recall and FPs** through the additive scorer, so lowering the threshold costs most on
   large benign packages (P6: benign 21+ FP rate 0.522 → 0.556).
4. **A stronger SSD model is not a recall lever on this data**: more findings, mostly MEDIUM, mostly on caught units.
5. **Attacker-controlled text placed above analyzer instructions** (P3's context header, P4's purpose header) is a
   prompt-injection channel; fence it below the instructions.
6. **Static regexes on attacker-controlled text need bounded quantifiers**, and long lines must be windowed, not
   skipped (P5 final review).
7. **The CLI exit code, MCP `safe_to_install` and the recommendation must agree** whenever the threshold moves (P6
   clamp).
8. **Fork test-failure convention.** Upstream tests that the fork's patches invert by design are never edited, skipped
   or deselected (that would conflict on every upstream sync). The fork-owned root `conftest.py` marks each one
   `xfail(strict=True)` at collection, so an unexpected pass fails too, and `docs/superpowers/EXPECTED_TEST_FAILURES.md`
   lists the same tests; both change in the commit that causes the failure.

## 7. Operational notes

### Flags now

| flag | default | effect |
|---|---|---|
| `SKILLSPECTOR_EXA_LURE_RULES` | on (unset) | `EXA-LU1`, `EXA-LU4` static analyzer, HIGH, confidence 0.9; `=off` disables |
| `SKILLSPECTOR_EXA_BLOCK_THRESHOLD` | 49 (unset) | block cut; `=51` restores upstream; 21–80, out of range raises `ValueError`, non-integer warns and uses the default; the reported score is clamped to the band |

Removed with their rollbacks: `SKILLSPECTOR_EXA_SEMANTIC_GATE`, `SKILLSPECTOR_EXA_DOC_MEDIUM_CAP`,
`SKILLSPECTOR_EXA_GATE_RULES` (P1); `SKILLSPECTOR_EXA_DOC_TEXT`, `SKILLSPECTOR_EXA_HIDDEN_TEXT` (P2);
`SKILLSPECTOR_EXA_SKILL_CONTEXT`, `SKILLSPECTOR_EXA_INSTRUCTION_FLOW` (P3); `SKILLSPECTOR_EXA_SSD5`,
`SKILLSPECTOR_EXA_NECESSITY` (P4). P7 used upstream's `SKILLSPECTOR_MODEL_SEMANTIC_SECURITY_DISCOVERY` and changed no
default.

### Reproducing the headline numbers

From `benchmark/`, against the local `results/recall.duckdb` (not committed; the run ids below are in it):

```bash
# cumulative, against the original and against baseline-v2 (drift-confounded)
uv run report results/recall.duckdb 60503e65c287 --base 113b02ab497b --split-file results/evalsets/splits.tsv
uv run report results/recall.duckdb 60503e65c287 --base e16e394f65c3 --split-file results/evalsets/splits.tsv
# P6 causal: paired replay against its own source run; P5 causal: the full same-day pair
uv run report results/recall.duckdb 60503e65c287 --base bfa51d835e8b --split-file results/evalsets/splits.tsv
uv run report results/recall.duckdb 93c1faec5bec --base 0e0f9e105cf8 --split-file results/evalsets/splits.tsv
# regenerate the P6 head run from its source (writes a new synthetic run id)
uv run replay results/recall.duckdb bfa51d835e8b --policy '{"threshold": 49}'
# health of any run; dev verdicts
uv run health results/recall.duckdb <run_id>
uv run arms results/recall.duckdb --control <c1>,<c2> --treatment <t1>,<t2>
```

P5's acceptance was judged on the rule-affected units `M`, not the whole-set `report`; its computation is described
in `recall-p5-report.md` item 1. `splits.tsv` has been regenerated since the original holdout figures were computed;
the committed file is P5's (4,241 dev / 8,477 holdout).

### State of this PR

- **Root suite:** 2,041 passed, 14 xfailed (strict, by design), 0 failed. **Benchmark suite:** 214 passed. These are
  after the P1/P2/P7 rollbacks.
- **Fork classifier code that ships:**
  - the pre-program patches;
  - `_lure_rules` (P5);
  - the threshold in `_score_patches` (P6);
  - `_analyzer_registry` and `_fork_context`, the plumbing the lure rules need;
  - `_patchlib.intercept_module_callable`.
- **Benchmark harness:** P0's tooling, `rulelab` (P5), `replay`'s threshold support and `decide` (P6), and the
  `explanation` coercion fix `79176a33`.

### Key run ids

| run | what |
|---|---|
| `113b02ab497b` | original baseline (unhealthy, 6.9% dropped) |
| `e16e394f65c3` | `baseline-v2`, P0; replay source for P1 and P5's `rulelab` |
| `0e0f9e105cf8` / `93c1faec5bec` | P5 full control / lure rules on |
| `bfa51d835e8b` | P6 full run on P5 defaults; replay source for the threshold sweep |
| `60503e65c287` | P6 replay at T = 49 with the clamp; head of every cumulative number |
| `7f54de6438ea`, `6822ec3bf3eb` | P7 dev controls (same day as the P7 candidates) |

### Where the records live

- Spec: `docs/superpowers/specs/2026-10-29-recall-improvement-program.md` (goal, protocol, decision rules, screen
  pre-registration and validation).
- Plans: `docs/superpowers/plans/2026-10-29-recall-p0-measurement.md` through `...-p7-model-split.md`, and
  `docs/superpowers/plans/2026-11-04-sequential-screen.md`.
- Run ledger, one row per run with verdict blocks and rulings: `benchmark/results/recall-ledger.md`.
- Reports: `benchmark/results/recall-p0-report.md`, `recall-p1-report.md`, `recall-p1-offline.md`,
  `recall-p3-report.md`, `recall-p4-report.md`, `recall-p5-report.md`, `recall-p5-offline.md` (generated by
  `rulelab`), `recall-p5-offline-notes.md`, `recall-p6-report.md`, `recall-p6-offline.md`. P2's record is the ledger's
  P2 section.
- P7 (removed in `cb417b57`): `git show 0702a6dd:benchmark/results/recall-p7-report.md`,
  `git show 0702a6dd:benchmark/results/recall-program-summary.md`, and the P7 section of
  `git show 0702a6dd:benchmark/results/recall-ledger.md`.
- Evaluation sets and how each was built: `benchmark/results/evalsets/` and its `README.md`. Screen manifests:
  `benchmark/results/screens/<label>/manifest.json`.
- Background analysis: `benchmark/recall-boundaries.md` and `benchmark/recall-boundaries-review.md` (untracked
  working-tree files, not part of this PR).

## 8. Open items and next levers

Ranked by expected value per unit of effort, with the uncertainty stated. None of these has a pre-registered result.

1. **Explain the score-50 mass** (cheap: replay and stored findings only). 66 units sit at exactly 50 and HIGH static
   findings land at 43–47. If the meta-verdict-over-static-severity patch is the cause, fixing it is a scoring change
   that `replay` can quantify exactly before any live run. Upside unknown; it may overlap P6's gain, since P6 already
   took the units at 49–50.
2. **Give P1's gate its full-run acceptance test** (two full runs, about 2 h). Offline it was +0.029 recall at −0.001
   precision on the full set and 11:1 on holdout; the dev REJECT depended on one control pairing. Uncertainty: live dev
   FP was about 3× the offline prediction, the gate targets only units with a HIGH SSD/P2 finding (P7 says that is a
   minority of misses), and its interaction with threshold 49 is unmeasured. Highest single upside on record, but the
   code is now rolled back and would need restoring.
3. **Finish P2** (replicate 2 and full acceptance). One replicate showed +37 TP with flat or lower FP on its dev set,
   aimed at Persistence and part of Data Exfiltration. Uncertainty: one replicate, 97.5% one generator, PDF precision
   unmeasured.
4. **Tier the labels in the headline metric (O0)**: report recall on valid units next to raw recall. It changes no
   verdict but would stop B0 (Credential Theft, much of RCE) from reading as a classifier gap. Policy decision, not
   engineering.
5. **Reduce dropped LLM calls.** Every dev verdict was blurred by 5–13% dropped calls. Finding why calls drop
   (endpoint throttling at 96 workers, or failures the batch path does not recover) would cut both noise and FN bias.
   Any fix in the LLM batch path touches upstream-tracked code, so it needs a fork patch.
6. **Harness robustness:** store the raw score next to the clamped one (removes the replay-at-51 trap); record an
   unrecordable scan as one ERROR unit instead of aborting the run; coerce `mcp_tool_poisoning` TP4's non-string
   `explanation` in a fork patch; find the last-unit hang.
7. **New detection for B3 and scripts SKILL.md runs.** The misses that remain are mostly ones no analyzer flags. P4
   suggests a necessity view finds them but at an FP cost, and that most of its FNs hide the harm in a script
   SKILL.md tells the agent to run. This is the largest pool of misses and the least certain lever.
8. **Not recommended:** further model swaps in the SSD slot (no candidate raised HIGH+ findings on missed units), and
   further threshold moves before item 1 (T = 47 already fails the precision and FP-cap clauses).
