# P5 overview: lure rules (EXA-LU1, EXA-LU4)

**Verdict: ACCEPTED** (Task 4 full runs, 2026-11-04). The verdict uses the acceptance criteria the user re-registered in
`21e37201`, which judge every criterion on the rule-affected units. `SKILLSPECTOR_EXA_LURE_RULES` is on by default from
`45fb9511`, and `=off` disables it.

Candidate L adds two deterministic static rules, both HIGH at confidence 0.9:
- `EXA-LU1`: pipe-to-shell from an IP literal or a public paste service;
- `EXA-LU4`: base64 decode piped into an interpreter or `eval`.

The final pair was run at `8ab36a84`, which includes the final-review fix wave (bounded regexes and windowed long
lines). Both runs cover all 12,718 units and pass `health` at 10%:
- control `0e0f9e105cf8`: 8.1% of scans dropped LLM calls. SSO expired at 9,033 units and the run was resumed with
  `--run-id`.
- treatment `93c1faec5bec`: 8.4% dropped.

1. **Acceptance.** `M` is the set of units with at least one `EXA-LU*` finding in the treatment run. It has 301 units:
   298 malicious, 3 benign, and 0 in the holdout split.

   | criterion (registered in `21e37201`) | measured | needed | result |
   |---|---|---|---|
   | recall: ΔTP over `M`'s malicious units ÷ 6,403 | +41 → **+0.0064** | ≥ +0.005 (+32 TP) | PASS |
   | precision and guard: ΔFP over `M`'s benign units | **0** | ≤ N_FP = 2 | PASS |
   | holdout: ΔTP over `M`'s holdout units | `M` has none | information only | — |
   | health (10%) | 8.1% / 8.4% | both pass | PASS |

   - **Flips inside `M`:** 51 FN→TP and 10 TP→FN.
   - **Why the 10 losses are drift:** a static finding can only add risk, so it cannot cause a loss. The losing units
     still carry their `EXA-LU*` finding, but their LLM findings changed between runs.
   - **Drift-corrected margin:** units outside `M` moved +59 TP across about 6,100 malicious units, about +1%. Applied to
     `M`'s 298 malicious units, that implies about +3 TP of drift inside `M`. The corrected gain is about +38 (+0.0059),
     still above the bar. The margin is 6 to 9 TP from a single run pair (P5-R20).
2. **Whole set (information; spec `report` commands appended below).**

   | scope | TP | FP | recall | precision |
   |---|---|---|---|---|
   | all 12,718 units | 4,522 → 4,622 (+100) | 373 → 362 (−11) | 0.7062 → 0.7218 (+0.0156) | 0.9238 → 0.9274 (+0.0036) |
   | dev split (4,241) | 1,051 → 1,119 (+68) | 249 → 248 (−1) | 0.4376 → 0.4659 (+0.0283) | 0.8085 → 0.8186 (+0.0101) |
   | holdout split (8,477) | 3,471 → 3,503 (+32) | 124 → 114 (−10) | 0.8675 → 0.8755 (+0.0080) | 0.9655 → 0.9685 (+0.0030) |
   | outside `M` (12,417) | 4,313 → 4,372 (+59) | 371 → 360 (−11) | 0.7065 → 0.7161 (+0.0097) | 0.9208 → 0.9239 (+0.0031) |

   The rules cannot change a unit outside `M`. So the whole-set +0.0156 is mostly drift, which favoured the treatment
   run this time, and the holdout gain is all drift. The fetch-line guard (`p5-guard-fetch`, 246 benign units) went from
   FP 86 to 79. Cumulatively against `baseline-v2`, recall is 0.712 → 0.722 and precision 0.931 → 0.927. Both include
   P0–P5 drift.
3. **Slices (malicious units; recall control → L).**

   | slice | n | control | L | Δ |
   |---|---|---|---|---|
   | native wild, `C07_native_wild` | 612 | 0.511 | 0.541 | +0.029 |
   | STB dropper/installer cells | 162 | 0.537 | 0.679 | **+0.142** |
   | MSB-wild, `C05_msb_wild_usenix` | 153 | 0.144 | 0.176 | +0.033 |
   | SkillTrustBench | 3,797 | 0.900 | 0.914 | +0.014 |
   | non-STB | 2,606 | 0.424 | 0.441 | +0.017 |

   - **STB dropper cells:** SkillTrustBench units whose `injection_pattern` contains `dropper` or `installer`.
   - **MSB-wild:** no rule matches its payload style, so its +0.033 is drift. On dev it was −0.013.
4. **Lure-only share of new TPs.** The 51 FN→TP units in `M`:
   - **Annotated:** 11 units, all `CORRECT` (the `working` tier). None are `intent` tier (BROKEN, UNVERIFIABLE), so the
     lure-only share among annotated gains is 0 of 11.
   - **Unannotated:** 40 units.
   - **By source:** SkillTrustBench 30, native-wild malware 19, MaliciousSkillBench/ATR 2.

   The whole-set report shows `intent`-tier recall up +0.120 (BROKEN +6 TP, UNVERIFIABLE +4). None of that gain is in
   `M`, so it is drift.
5. **Benign matches, by unit.** Offline, `EXA-LU4` matched 5 benign units and `EXA-LU1` matched none. All 5 are security
   tools that quote attack patterns:

   | unit | file | live `EXA-LU*` finding | control → L |
   |---|---|---|---|
   | `Skills/benign/skill-security-audit` | `references/vulnerability-patterns.md` | yes | FP → FP |
   | `Skills/benign/ecap-security-auditor` | `FERRET-ADOPTION-PLAN.md` | yes (none on dev) | FP → FP |
   | `Skills/benign/openclaw-skill-vetter` | `SKILL.md` | yes | TN → TN |
   | `Skills/benign/openclaw-defender` | `SKILL.md` | no | TN → TN |
   | `Skills/benign/skillguard-scanner` | `SKILL.md` | no | TN → TN |

   No benign outcome changed. The two FPs are FP without the rule too.
6. **Offline prediction against live.**
   - **Match sets:** the offline regex matched 305 units. Live, `M` is 301 of them. The 4 offline-only units are the 2
     benign units above, `guava-guard__msb-src005-ASB04_001259` and `web-monitor__stb-case_05715`.
   - **Prediction against result:** the replay at `baseline-v2` predicted about 58 FN→TP. In the full pair, 89 matched
     malicious units were FN in the control. 51 of them became TP, with a median risk gain of +26.0 (mean +27.5).
   - **Units that stay FN:** 38. Their median risk goes from 29.5 to 47.0, and 19 of them start at or below 30.
   - **Correction:** the earlier "replay overestimates about 2×" was selection bias, because it looked only at units
     that stayed FN (final review I3). Replay is roughly right on flip count. Its error is per unit: run-to-run LLM drift
     moves the base risk.
7. **How the verdict was reached.**
   - **Dev arms:** PROMISING (+46 TP / +4 FP; N_TP 4, N_FP 2; appendix below). The plan's fetch-line guard failed as
     written (+4.5 FP against N_FP 2).
   - **First decision:** the user chose "reject as written", based partly on my estimate of about +28 TP, roughly +0.45
     recall points.
   - **The estimate was wrong:** the final review (I2) showed it undercounted. It required FN in both controls. On the
     305 matched dev units the gain was +48.5 TP / −0.5 FP, and the units outside the match set moved −2.5 TP / +4.5 FP,
     so the guard rise came from units the rules cannot touch. The expected full-set gain was about +0.76 points.
   - **Re-registration:** after the correction, the user re-registered acceptance on the rule-affected units `M`
     (`21e37201`), before any Task 4 run.
   - **Fix wave:** the final review also found regex backtracking (I1). A fix wave of three commits bounded every
     quantifier and windowed long lines, and a scoped re-check came back clean. The offline match set is unchanged
     (305).
   - **Task 4** then ran the full pair above.
8. **Cost.** No LLM calls added: 4.32 per scan in both runs. Median scan time 13.6 s for control, 13.1 s for L.
9. **Caveats.**
   - **The acceptance criteria are post hoc.** The user set them with the dev results in view. They follow from how a
     static rule can act, but they were not pre-registered before P5 started.
   - **One run pair.** The recall margin is 6 to 9 TP, and drift outside `M` was +59 TP in the same pair.
   - **No holdout units in `M`.** Every rule-matched unit is in the dev split, so the holdout criterion could not be
     tested.
   - **The replay bar was re-registered after the offline results** (`067cdd0c`, a user decision), and LU1 cleared it by
     one unit (16 against 15).

## Handoffs

- **Static HIGH findings lose points downstream.** 10 matched units went TP→FN in L. Most land at risk 43–47 despite a
  HIGH `EXA-LU*` finding at confidence 0.95–1.0. The 38 matched units that stay FN cluster at about 47 too.
  - Hypothesis (unverified): the fork's "trust the meta-analyzer verdict over static severity" patch
    (`src/skillspector/exaforce/__init__.py`) caps static evidence when the LLM verdict is benign.
  - That is the scoring-path lever for P6. Re-measure L under any P6 scoring change.
- **Flag provenance.** Before `45fb9511`, an unset `SKILLSPECTOR_EXA_LURE_RULES` meant off. From `45fb9511` on, it means
  on. `arms` and resume pinning compare env values only, so a run with the flag unset differs by git sha alone. Future
  controls without the rules must set `SKILLSPECTOR_EXA_LURE_RULES=off`.
- **Guards need their own noise floor.** The 246-unit guard flips 46 units between identical dev controls. Pre-register
  future guards as attributable (FPs that carry the candidate's own finding) or against the guard's own control spread.
- **Report attributable numbers next to `arms`.** Count all flips in the units the candidate touches, not only units that
  were FN in both controls.
- **Offline/live match gap.** 2 benign and 2 malicious offline matches get no live finding. The loss happens in an
  LLM-dependent stage (final review M3). It is small, but offline benign counts are an upper bound.
- **Residual code minors (recorded, not fixed):**
  - a lookaround at a window edge can produce an FP (attacker's own file only);
  - a single gap over 256 chars or an option token over 32 chars evades the rule;
  - a crafted 1 MB line takes about 17 s;
  - LU1 also fires on chained unrelated commands and on private IPs (M2; not changed, to avoid altering the measured
    rule);
  - a "disabled" status entry appears in reports when the flag is off (M4);
  - the generalized `[exaforce: ` bypass prefix retains any fork-marked finding;
  - the per-rule, per-file cap of 10 truncates silently;
  - `rulelab` imports the private `report._SEVERITY_POINTS`;
  - an unknown flag value logs a warning on every scan.

<!-- spec report 1: uv run report results/recall.duckdb 93c1faec5bec --base 0e0f9e105cf8 -->
## SkillSpector benchmark: `p5 final control full` → `p5 final L lure=on full`

🟢 **Net +111** classifications improved over the 12718 unit(s) both runs scanned — 535 fixed, 424 regressed.

<sub>base = baseline, head = candidate. Δ = head − base; ▲ better, ▼ worse. Generated 2026-11-04 21:50 UTC from `results/recall.duckdb`.</sub>

### Run configuration

| | base · `p5 final control full` | head · `p5 final L lure=on full` |
|---|---|---|
| run id | `0e0f9e105cf8` | `93c1faec5bec` |
| description | p5 final control full | p5 final L lure=on full |
| model | nvidia.nemotron-super-3-120b | nvidia.nemotron-super-3-120b |
| LLM | on | on |
| units (total) | 12,718 | 12,718 |
| started | 2026-11-04 13:16 | 2026-11-04 14:53 |
| workers | 96 | 96 |

### Health

| run | health |
|---|---|
| base · `p5 final control full` | Health: OK |
| head · `p5 final L lure=on full` | Health: OK |

### Outcomes

Every scanned unit is exactly one of these, so the rows **conserve to the total** —
reducing one bucket (e.g. eliminating timeouts) just moves those units into the
others. Read the two **bold** group rows for the verdict; the indented rows break
them down (a single sub-row moving isn't independently good or bad).

| | base | head | Δ |
|---|---|---|---|
| ✅ **correct** (TP + TN) | 10464 | 10575 | ▲ +111 |
| &emsp;true positives · malware caught | 4522 | 4622 | +100 |
| &emsp;true negatives · benign passed | 5942 | 5953 | +11 |
| 🔴 **incorrect** (FP + FN + errors) | 2254 | 2143 | ▲ -111 |
| &emsp;false positives · benign flagged | 373 | 362 | -11 |
| &emsp;false negatives · malware missed | 1881 | 1781 | -100 |
| &emsp;errors / timeouts | 0 | 0 | 0 |
| total scanned | 12718 | 12718 | 0 |

Overall correctness (correct ÷ scanned, errors counted as wrong): **0.823** → **0.831** (▲ +0.009).

### Detection quality

Rates over units that **produced a verdict** (errors excluded — base scored 12718, head scored 12718). When the two runs' error counts differ these are **not** a like-for-like comparison — use **Outcomes** above for the conserved view.

| metric | base | head | Δ |
|---|---|---|---|
| precision | 0.924 `█████████████████░` | 0.927 `█████████████████░` | ▲ +0.004 |
| recall | 0.706 `█████████████░░░░░` | 0.722 `█████████████░░░░░` | ▲ +0.016 |
| F1 | 0.800 `██████████████░░░░` | 0.812 `███████████████░░░` | ▲ +0.011 |

### Head-to-head: what moved

Over the **12718** unit(s) scanned by both runs:

- 🟢 **535 fixed** (FN→TP, FP→TN, or error→resolved)
- 🔴 **424 regressed** (TP→FN, TN→FP, or →error)
- ⚪ **11759 unchanged**

<details>
<summary>🔴 Regressions (424) — showing first 25</summary>

| unit | base → head | type | malware |
|---|---|---|---|
| `Skills/malware/13f-analyzer__msb-src013-ASB04_002876` | TP → FN | skill / malicious |  Credential Theft |
| `Skills/malware/13f-analyzer__skillharm-fpp-6afc1fe426` | TP → FN | skill / malicious | MIXED |
| `Skills/malware/CodeReview-Automated-Code-Review-Assistant__stb-case_00313` | TP → FN | skill / malicious | CI |
| `Skills/malware/Session-Memory-Summarization__stb-case_00818` | TP → FN | skill / malicious | MIXED Instruction Override |
| `Skills/malware/Skill-Deps-Doctor__stb-case_04441` | TP → FN | skill / malicious | MIXED Privilege Escalation |
| `Skills/malware/Smart-Router__stb-case_03388` | TP → FN | skill / malicious | CI Privilege Escalation |
| `Skills/malware/Test Engineer` | TP → FN | skill / malicious | — |
| `Skills/malware/a-share-dcf-valuation__stb-case_01409` | TP → FN | skill / malicious | CI Privilege Escalation |
| `Skills/malware/ac-branch-pi-model__skillharm-fpp-9fd729a4cc` | TP → FN | skill / malicious | MIXED Data Exfiltration |
| `Skills/malware/agent-browser-stealth__stb-case_00352` | TP → FN | skill / malicious | CI Privilege Escalation |
| `Skills/malware/agent-identifier__skillinject-obvious27-t0` | TP → FN | skill / malicious | PI System Prompt Leak |
| `Skills/malware/agent-self-care__stb-case_03100` | TP → FN | skill / malicious | CI |
| `Skills/malware/agent-task-status__stb-case_02937` | TP → FN | skill / malicious | CI Privilege Escalation |
| `Skills/malware/ai-exposure-analyzer__stb-case_02351` | TP → FN | skill / malicious | CI Privilege Escalation |
| `Skills/malware/ai-writing-humanizer__stb-case_04342` | TP → FN | skill / malicious | CI |
| `Skills/malware/airdrop-hunter__stb-case_05674` | TP → FN | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/alicloud-ai-image-qwen-image-edit__stb-case_03326` | TP → FN | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/alm-processing__PI_B13` | TP → FN | skill / malicious | PI System Prompt Leak |
| `Skills/malware/antigravity-image__msb-src004-ASB04_001417` | TP → FN | skill / malicious |  Remote Code Execution |
| `Skills/malware/arbitrum-dapp-skill__msb-src004-ASB04_002011` | TP → FN | skill / malicious |  Remote Code Execution |
| `Skills/malware/astock-multiagent-research__stb-case_02406` | TP → FN | skill / malicious | MIXED Privilege Escalation |
| `Skills/malware/astropy` | TP → FN | skill / malicious | — |
| `Skills/malware/auth-guardian` | TP → FN | skill / malicious | — |
| `Skills/malware/auto-updater__stb-case_05672` | TP → FN | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/binance-exchange__stb-case_01876` | TP → FN | skill / malicious | CI Privilege Escalation |

<sub>… 399 more not shown (raise `--top`).</sub>

</details>

<details>
<summary>🟢 Fixes (535) — showing first 25</summary>

| unit | base → head | type | malware |
|---|---|---|---|
| `Skills/malware/13f-analyzer__skillharm-fpp-8fba14b675` | FN → TP | skill / malicious | CI Content Manipulation |
| `Skills/malware/13f-analyzer__skillharm-fpp-a0d35c388e` | FN → TP | skill / malicious | CI Resource Abuse |
| `Skills/malware/AI-Cluster-Pre-flight-Check__stb-case_05306` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/ASB04_002647__msb-src002-ASB04_002647` | FN → TP | skill / malicious |  Instruction Override |
| `Skills/malware/Animation Principles - Refresher` | FN → TP | skill / malicious | — |
| `Skills/malware/Personality-Engine__stb-case_04499` | FN → TP | skill / malicious | MIXED Privilege Escalation |
| `Skills/malware/Study-Plan__stb-case_04161` | FN → TP | skill / malicious | CI |
| `Skills/malware/TokenGuard - Blockchain Security Monitor` | FN → TP | skill / malicious | — |
| `Skills/malware/adr-generator` | FN → TP | skill / malicious | — |
| `Skills/malware/agent-radio__stb-case_03635` | FN → TP | skill / malicious | PI Instruction Override |
| `Skills/malware/agent-team-orchestration-v3-public__stb-case_01282` | FN → TP | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/agentledger__stb-case_05158` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/agents` | FN → TP | skill / malicious | — |
| `Skills/malware/ai-clip-maker__stb-case_03440` | FN → TP | skill / malicious | PI Instruction Override |
| `Skills/malware/ai-video-upscale__stb-case_04929` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/airdrop-hunter__stb-case_05607` | FN → TP | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/airdrop-hunter__stb-case_05726` | FN → TP | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/akshare-stock-analysis__stb-case_05347` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/alicloud-ai-audio-cosyvoice-voice-design__stb-case_00165` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/aliyun-wan-r2v__stb-case_00506` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/anthropic-report-format__stb-case_04808` | FN → TP | skill / malicious | CI |
| `Skills/malware/api-cost-optimizer__stb-case_05519` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/api-design-principles__CI_B1` | FN → TP | skill / malicious | CI Data Exfiltration |
| `Skills/malware/api-mock-server__stb-case_05706` | FN → TP | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/aqara-agent__stb-case_02105` | FN → TP | skill / malicious | CI Privilege Escalation |

<sub>… 510 more not shown (raise `--top`).</sub>

</details>

### SkillTrustBench vs rest

Recall over **malicious** units, split by whether `_external_labels.jsonl` attributes the unit to SkillTrustBench.



| subset | base n | head n | base recall | head recall | Δ |
|---|---|---|---|---|---|
| SkillTrustBench | 3797 | 3797 | 0.900 | 0.914 | ▲ +0.014 |
| non-STB | 2606 | 2606 | 0.424 | 0.441 | ▲ +0.017 |


### Label-validity tiers


Raw counts over the annotated malicious units in `_boundary_labels.jsonl` (the 412-unit annotation sample), **unweighted** — not representative of the corpus mix.
`working` = CORRECT; `intent` = BROKEN, UNVERIFIABLE; `not_malicious` = WEAK, MISLABELED.

| tier | base n | head n | base recall | head recall | Δ |
|---|---|---|---|---|---|
| working | 233 | 233 | 0.382 | 0.446 | ▲ +0.064 |
| intent | 83 | 83 | 0.205 | 0.325 | ▲ +0.120 |
| not_malicious | 96 | 96 | 0.427 | 0.438 | ▲ +0.010 |


### SkillHarm attributed recall


A caught SkillHarm unit is **attributed** when at least one MEDIUM+ issue points at a file the attack injected; the rest were flagged for something else.

| metric | base | head | Δ |
|---|---|---|---|
| units (TP + FN) | 890 | 890 | 0 |
| verdict TP | 206 | 211 | +5 |
| attributed TP | 189 | 195 | +6 |
| recall | 0.231 | 0.237 | ▲ +0.006 |
| attributed recall | 0.212 | 0.219 | ▲ +0.007 |

### Benign FP rate by package size

Benign units bucketed by component count; FP rate = FP ÷ (FP + TN), errors excluded. `(none)` = no components recorded (usually a scan that errored).

| components | base n | head n | base FP rate | head FP rate | Δ |
|---|---|---|---|---|---|
| 1 | 826 | 826 | 0.004 | 0.000 | ▲ -0.004 |
| 2-5 | 4453 | 4453 | 0.031 | 0.028 | ▲ -0.002 |
| 6-20 | 946 | 946 | 0.205 | 0.201 | ▲ -0.004 |
| 21+ | 90 | 90 | 0.444 | 0.511 | ▼ +0.067 |


### Timing

Per-scan `run_time` stats. **Total scan time** is the sum (total work across all
scans) — resume-safe, unlike `finished_at − started_at`. **~est. wall** divides
that by the run's worker count to approximate elapsed time; it's an *estimate*
(ignores ramp-up, the under-saturated tail, and auth pauses, so it runs low).

| | scans | avg | median | p95 | max | total scan time | ~est. wall |
|---|---|---|---|---|---|---|---|
| **base** | 12718 | 22s | 13.56s | 78.17s | 300.03s | 77h43m | 48m34s |
| **head** | 12718 | 21.36s | 13.06s | 75.28s | 300.07s | 75h27m | 47m09s |

### Distributions

Per-dimension breakdown across both runs: sample size (`n`), false positives, false negatives, and recall. Recall is `—` where a group has no malicious units.

<details>
<summary>By category</summary>

| category | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| skill | 12667 `██████████████████` | 12667 `██████████████████` | 373 | 362 | 1881 | 1781 | 0.704 | 0.720 |
| code | 51 `░░░░░░░░░░░░░░░░░░` | 51 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 0 | 0 | 1.000 | 1.000 |
</details>

<details>
<summary>By behavior</summary>

| behavior | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| (none) | 8048 `███████████░░░░░░░` | 8048 `███████████░░░░░░░` | 373 | 362 | 638 | 616 | 0.632 | 0.645 |
| Privilege Escalation | 1071 `██░░░░░░░░░░░░░░░░` | 1071 `██░░░░░░░░░░░░░░░░` | 0 | 0 | 233 | 216 | 0.782 | 0.798 |
| Instruction Override | 1024 `█░░░░░░░░░░░░░░░░░` | 1024 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 109 | 91 | 0.894 | 0.911 |
| Malware Delivery | 1005 `█░░░░░░░░░░░░░░░░░` | 1005 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 184 | 154 | 0.817 | 0.847 |
| Data Exfiltration | 304 `░░░░░░░░░░░░░░░░░░` | 304 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 79 | 75 | 0.740 | 0.753 |
| Persistence | 285 `░░░░░░░░░░░░░░░░░░` | 285 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 75 | 79 | 0.737 | 0.723 |
| Content Manipulation | 250 `░░░░░░░░░░░░░░░░░░` | 250 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 189 | 179 | 0.244 | 0.284 |
| Goal Hijacking | 234 `░░░░░░░░░░░░░░░░░░` | 234 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 102 | 97 | 0.564 | 0.585 |
| Credential Theft | 154 `░░░░░░░░░░░░░░░░░░` | 154 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 106 | 104 | 0.312 | 0.325 |
| Resource Abuse | 122 `░░░░░░░░░░░░░░░░░░` | 122 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 62 | 65 | 0.492 | 0.467 |
| Remote Code Execution | 81 `░░░░░░░░░░░░░░░░░░` | 81 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 54 | 53 | 0.333 | 0.346 |
| System Prompt Leak | 43 `░░░░░░░░░░░░░░░░░░` | 43 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 26 | 29 | 0.395 | 0.326 |
| Reverse Shell | 33 `░░░░░░░░░░░░░░░░░░` | 33 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 1 | 0 | 0.970 | 1.000 |
| Ransomware | 31 `░░░░░░░░░░░░░░░░░░` | 31 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 1 | 4 | 0.968 | 0.871 |
| Safety Bypass | 20 `░░░░░░░░░░░░░░░░░░` | 20 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 15 | 11 | 0.250 | 0.450 |
| Role Hijack | 13 `░░░░░░░░░░░░░░░░░░` | 13 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 7 | 8 | 0.462 | 0.385 |
</details>

<details>
<summary>By corpus</summary>

| corpus | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| SkillTrustBench | 5403 `████████░░░░░░░░░░` | 5403 `████████░░░░░░░░░░` | 148 | 148 | 380 | 325 | 0.900 | 0.914 |
| benign | 3988 `██████░░░░░░░░░░░░` | 3988 `██████░░░░░░░░░░░░` | 211 | 202 | 0 | 0 | — | — |
| MaliciousSkillBench | 1153 `██░░░░░░░░░░░░░░░░` | 1153 `██░░░░░░░░░░░░░░░░` | 1 | 0 | 396 | 384 | 0.303 | 0.324 |
| SkillHarm | 975 `█░░░░░░░░░░░░░░░░░` | 975 `█░░░░░░░░░░░░░░░░░` | 4 | 5 | 684 | 679 | 0.231 | 0.237 |
| malware | 938 `█░░░░░░░░░░░░░░░░░` | 938 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 382 | 358 | 0.593 | 0.618 |
| Skill-Inject | 261 `░░░░░░░░░░░░░░░░░░` | 261 `░░░░░░░░░░░░░░░░░░` | 9 | 7 | 39 | 35 | 0.814 | 0.833 |
</details>

<details>
<summary>By attack vector</summary>

| attack vector | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| (none) | 7444 `███████████░░░░░░░` | 7444 `███████████░░░░░░░` | 373 | 362 | 695 | 665 | 0.384 | 0.411 |
| MIXED | 2421 `███░░░░░░░░░░░░░░░` | 2421 `███░░░░░░░░░░░░░░░` | 0 | 0 | 337 | 306 | 0.861 | 0.874 |
| CI | 1865 `███░░░░░░░░░░░░░░░` | 1865 `███░░░░░░░░░░░░░░░` | 0 | 0 | 253 | 230 | 0.864 | 0.877 |
| PI | 988 `█░░░░░░░░░░░░░░░░░` | 988 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 596 | 580 | 0.397 | 0.413 |
</details>


<!-- spec report 2: uv run report results/recall.duckdb 93c1faec5bec --base e16e394f65c3 --split-file results/evalsets/splits.tsv -->
## SkillSpector benchmark: `baseline-v2: P0 tree, tags recorded` → `p5 final L lure=on full`

🟢 **Net +39** classifications improved over the 12718 unit(s) both runs scanned — 499 fixed, 460 regressed.

<sub>base = baseline, head = candidate. Δ = head − base; ▲ better, ▼ worse. Generated 2026-11-04 21:50 UTC from `results/recall.duckdb`.</sub>

### Run configuration

| | base · `baseline-v2: P0 tree, tags recorded` | head · `p5 final L lure=on full` |
|---|---|---|
| run id | `e16e394f65c3` | `93c1faec5bec` |
| description | baseline-v2: P0 tree, tags recorded | p5 final L lure=on full |
| model | nvidia.nemotron-super-3-120b | nvidia.nemotron-super-3-120b |
| LLM | on | on |
| units (total) | 12,718 | 12,718 |
| started | 2026-11-02 08:12 | 2026-11-04 14:53 |
| workers | 96 | 96 |

### Health

| run | health |
|---|---|
| base · `baseline-v2: P0 tree, tags recorded` | Health: OK |
| head · `p5 final L lure=on full` | Health: OK |

### Outcomes

Every scanned unit is exactly one of these, so the rows **conserve to the total** —
reducing one bucket (e.g. eliminating timeouts) just moves those units into the
others. Read the two **bold** group rows for the verdict; the indented rows break
them down (a single sub-row moving isn't independently good or bad).

| | base | head | Δ |
|---|---|---|---|
| ✅ **correct** (TP + TN) | 10536 | 10575 | ▲ +39 |
| &emsp;true positives · malware caught | 4557 | 4622 | +65 |
| &emsp;true negatives · benign passed | 5979 | 5953 | -26 |
| 🔴 **incorrect** (FP + FN + errors) | 2182 | 2143 | ▲ -39 |
| &emsp;false positives · benign flagged | 336 | 362 | +26 |
| &emsp;false negatives · malware missed | 1846 | 1781 | -65 |
| &emsp;errors / timeouts | 0 | 0 | 0 |
| total scanned | 12718 | 12718 | 0 |

Overall correctness (correct ÷ scanned, errors counted as wrong): **0.828** → **0.831** (▲ +0.003).

### Detection quality

Rates over units that **produced a verdict** (errors excluded — base scored 12718, head scored 12718). When the two runs' error counts differ these are **not** a like-for-like comparison — use **Outcomes** above for the conserved view.

| metric | base | head | Δ |
|---|---|---|---|
| precision | 0.931 `█████████████████░` | 0.927 `█████████████████░` | ▼ -0.004 |
| recall | 0.712 `█████████████░░░░░` | 0.722 `█████████████░░░░░` | ▲ +0.010 |
| F1 | 0.807 `███████████████░░░` | 0.812 `███████████████░░░` | ▲ +0.005 |

### Head-to-head: what moved

Over the **12718** unit(s) scanned by both runs:

- 🟢 **499 fixed** (FN→TP, FP→TN, or error→resolved)
- 🔴 **460 regressed** (TP→FN, TN→FP, or →error)
- ⚪ **11759 unchanged**

<details>
<summary>🔴 Regressions (460) — showing first 25</summary>

| unit | base → head | type | malware |
|---|---|---|---|
| `Skills/malware/13f-analyzer__msb-src013-ASB04_001351` | TP → FN | skill / malicious | — |
| `Skills/malware/AI-Cluster-Pre-flight-Check__stb-case_00695` | TP → FN | skill / malicious | CI |
| `Skills/malware/Session-Memory-Summarization__stb-case_00818` | TP → FN | skill / malicious | MIXED Instruction Override |
| `Skills/malware/Skill-Deps-Doctor__stb-case_04441` | TP → FN | skill / malicious | MIXED Privilege Escalation |
| `Skills/malware/Smart-Router__stb-case_03388` | TP → FN | skill / malicious | CI Privilege Escalation |
| `Skills/malware/ab-test-setup__PI_B11` | TP → FN | skill / malicious | PI Safety Bypass |
| `Skills/malware/ac-branch-pi-model__skillharm-fpp-9fd729a4cc` | TP → FN | skill / malicious | MIXED Data Exfiltration |
| `Skills/malware/advanced-agentdb-vector-search-implementation` | TP → FN | skill / malicious | — |
| `Skills/malware/adversary-emulation-toolkit` | TP → FN | skill / malicious | — |
| `Skills/malware/agent-metrics-monitor__stb-case_05214` | TP → FN | skill / malicious | MIXED Instruction Override |
| `Skills/malware/agent-monitor__stb-case_01439` | TP → FN | skill / malicious | MIXED Privilege Escalation |
| `Skills/malware/agent-self-care__stb-case_03100` | TP → FN | skill / malicious | CI |
| `Skills/malware/agentnet__stb-case_02337` | TP → FN | skill / malicious | CI Privilege Escalation |
| `Skills/malware/agentuity-cli-cloud-redis-show` | TP → FN | skill / malicious | — |
| `Skills/malware/ai-it-department-wistec-core` | TP → FN | skill / malicious | — |
| `Skills/malware/ai-rebirth__stb-case_03338` | TP → FN | skill / malicious | CI Privilege Escalation |
| `Skills/malware/ai-writing-humanizer__stb-case_04342` | TP → FN | skill / malicious | CI |
| `Skills/malware/airdrop-hunter__stb-case_05674` | TP → FN | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/alibabacloud-cms-alert-rule-create__stb-case_05518` | TP → FN | skill / malicious | CI Credential Theft |
| `Skills/malware/alicloud-ai-image-qwen-image-edit__stb-case_03326` | TP → FN | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/alm-processing__PI_B13` | TP → FN | skill / malicious | PI System Prompt Leak |
| `Skills/malware/arbitrum-dapp-skill__msb-src004-ASB04_002011` | TP → FN | skill / malicious |  Remote Code Execution |
| `Skills/malware/auto-updater__stb-case_05672` | TP → FN | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/beauty-generation-free__msb-src006-ASB04_005848` | TP → FN | skill / malicious |  Data Exfiltration |
| `Skills/malware/binance-trading-bot__stb-case_05718` | TP → FN | skill / malicious | MIXED Malware Delivery |

<sub>… 435 more not shown (raise `--top`).</sub>

</details>

<details>
<summary>🟢 Fixes (499) — showing first 25</summary>

| unit | base → head | type | malware |
|---|---|---|---|
| `Skills/malware/13f-analyzer__skillharm-fpp-8fba14b675` | FN → TP | skill / malicious | CI Content Manipulation |
| `Skills/malware/13f-analyzer__skillharm-fpp-cff4201b5a` | FN → TP | skill / malicious | CI Content Manipulation |
| `Skills/malware/AI-Cluster-Pre-flight-Check__stb-case_02413` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/AI-Cluster-Pre-flight-Check__stb-case_05306` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/DFCF_StockPick__stb-case_00684` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/Personality-Engine__stb-case_03312` | FN → TP | skill / malicious | CI |
| `Skills/malware/Personality-Engine__stb-case_04499` | FN → TP | skill / malicious | MIXED Privilege Escalation |
| `Skills/malware/Study-Plan__stb-case_04161` | FN → TP | skill / malicious | CI |
| `Skills/malware/Travel-Search-Flight-Train-Scenery__stb-case_01652` | FN → TP | skill / malicious | CI |
| `Skills/malware/Tushare-Pro__stb-case_00926` | FN → TP | skill / malicious | CI |
| `Skills/malware/adversarial-safety-simulator` | FN → TP | skill / malicious | — |
| `Skills/malware/ai-clip-maker__stb-case_03440` | FN → TP | skill / malicious | PI Instruction Override |
| `Skills/malware/airdrop-hunter__stb-case_05607` | FN → TP | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/airdrop-hunter__stb-case_05708` | FN → TP | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/akquant-backtest__stb-case_05219` | FN → TP | skill / malicious | CI |
| `Skills/malware/akshare-stock-analysis__stb-case_05347` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/alicloud-ai-audio-cosyvoice-voice-design__stb-case_00165` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/amp-code__stb-case_00849` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/amp-code__stb-case_04582` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/anachb__stb-case_03127` | FN → TP | skill / malicious | MIXED Privilege Escalation |
| `Skills/malware/api-cost-optimizer__stb-case_05519` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/auto-updater-3miomc4dvir` | FN → TP | skill / malicious | — |
| `Skills/malware/auto-updater-ah1` | FN → TP | skill / malicious | — |
| `Skills/malware/auto-updater-ek1qviijfp1` | FN → TP | skill / malicious | — |
| `Skills/malware/auto-updater__stb-case_05705` | FN → TP | skill / malicious | MIXED Malware Delivery |

<sub>… 474 more not shown (raise `--top`).</sub>

</details>

### SkillTrustBench vs rest

Recall over **malicious** units, split by whether `_external_labels.jsonl` attributes the unit to SkillTrustBench.



| subset | base n | head n | base recall | head recall | Δ |
|---|---|---|---|---|---|
| SkillTrustBench | 3797 | 3797 | 0.900 | 0.914 | ▲ +0.014 |
| non-STB | 2606 | 2606 | 0.437 | 0.441 | ▲ +0.005 |


### Label-validity tiers


Raw counts over the annotated malicious units in `_boundary_labels.jsonl` (the 412-unit annotation sample), **unweighted** — not representative of the corpus mix.
`working` = CORRECT; `intent` = BROKEN, UNVERIFIABLE; `not_malicious` = WEAK, MISLABELED.

| tier | base n | head n | base recall | head recall | Δ |
|---|---|---|---|---|---|
| working | 233 | 233 | 0.395 | 0.446 | ▲ +0.052 |
| intent | 83 | 83 | 0.289 | 0.325 | ▲ +0.036 |
| not_malicious | 96 | 96 | 0.417 | 0.438 | ▲ +0.021 |


### SkillHarm attributed recall


A caught SkillHarm unit is **attributed** when at least one MEDIUM+ issue points at a file the attack injected; the rest were flagged for something else.

| metric | base | head | Δ |
|---|---|---|---|
| units (TP + FN) | 890 | 890 | 0 |
| verdict TP | 208 | 211 | +3 |
| attributed TP | 187 | 195 | +8 |
| recall | 0.234 | 0.237 | ▲ +0.003 |
| attributed recall | 0.210 | 0.219 | ▲ +0.009 |

### Benign FP rate by package size

Benign units bucketed by component count; FP rate = FP ÷ (FP + TN), errors excluded. `(none)` = no components recorded (usually a scan that errored).

| components | base n | head n | base FP rate | head FP rate | Δ |
|---|---|---|---|---|---|
| 1 | 826 | 826 | 0.001 | 0.000 | ▲ -0.001 |
| 2-5 | 4453 | 4453 | 0.028 | 0.028 | ▼ +0.000 |
| 6-20 | 946 | 946 | 0.180 | 0.201 | ▼ +0.021 |
| 21+ | 90 | 90 | 0.456 | 0.511 | ▼ +0.056 |


### Splits

Per-split outcomes, recall and precision from `--split-file`; units not listed there are `unassigned`.

| split | base n | head n | base TP | head TP | base FP | head FP | base TN | head TN | base FN | head FN |
|---|---|---|---|---|---|---|---|---|---|---|
| holdout | 8477 | 8477 | 3494 | 3503 | 99 | 114 | 4377 | 4362 | 507 | 498 |
| dev | 4241 | 4241 | 1063 | 1119 | 237 | 248 | 1602 | 1591 | 1339 | 1283 |

| split | base n | head n | base recall | head recall | Δ |
|---|---|---|---|---|---|
| holdout | 8477 | 8477 | 0.873 | 0.876 | ▲ +0.002 |
| dev | 4241 | 4241 | 0.443 | 0.466 | ▲ +0.023 |


| split | base n | head n | base precision | head precision | Δ |
|---|---|---|---|---|---|
| holdout | 8477 | 8477 | 0.972 | 0.968 | ▼ -0.004 |
| dev | 4241 | 4241 | 0.818 | 0.819 | ▲ +0.001 |


### Timing

Per-scan `run_time` stats. **Total scan time** is the sum (total work across all
scans) — resume-safe, unlike `finished_at − started_at`. **~est. wall** divides
that by the run's worker count to approximate elapsed time; it's an *estimate*
(ignores ramp-up, the under-saturated tail, and auth pauses, so it runs low).

| | scans | avg | median | p95 | max | total scan time | ~est. wall |
|---|---|---|---|---|---|---|---|
| **base** | 12718 | 38.78s | 30.01s | 97.53s | 300.21s | 136h59m | 1h25m |
| **head** | 12718 | 21.36s | 13.06s | 75.28s | 300.07s | 75h27m | 47m09s |

### Distributions

Per-dimension breakdown across both runs: sample size (`n`), false positives, false negatives, and recall. Recall is `—` where a group has no malicious units.

<details>
<summary>By category</summary>

| category | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| skill | 12667 `██████████████████` | 12667 `██████████████████` | 336 | 362 | 1846 | 1781 | 0.709 | 0.720 |
| code | 51 `░░░░░░░░░░░░░░░░░░` | 51 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 0 | 0 | 1.000 | 1.000 |
</details>

<details>
<summary>By behavior</summary>

| behavior | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| (none) | 8048 `███████████░░░░░░░` | 8048 `███████████░░░░░░░` | 336 | 362 | 628 | 616 | 0.638 | 0.645 |
| Privilege Escalation | 1071 `██░░░░░░░░░░░░░░░░` | 1071 `██░░░░░░░░░░░░░░░░` | 0 | 0 | 217 | 216 | 0.797 | 0.798 |
| Instruction Override | 1024 `█░░░░░░░░░░░░░░░░░` | 1024 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 94 | 91 | 0.908 | 0.911 |
| Malware Delivery | 1005 `█░░░░░░░░░░░░░░░░░` | 1005 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 194 | 154 | 0.807 | 0.847 |
| Data Exfiltration | 304 `░░░░░░░░░░░░░░░░░░` | 304 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 77 | 75 | 0.747 | 0.753 |
| Persistence | 285 `░░░░░░░░░░░░░░░░░░` | 285 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 72 | 79 | 0.747 | 0.723 |
| Content Manipulation | 250 `░░░░░░░░░░░░░░░░░░` | 250 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 198 | 179 | 0.208 | 0.284 |
| Goal Hijacking | 234 `░░░░░░░░░░░░░░░░░░` | 234 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 99 | 97 | 0.577 | 0.585 |
| Credential Theft | 154 `░░░░░░░░░░░░░░░░░░` | 154 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 106 | 104 | 0.312 | 0.325 |
| Resource Abuse | 122 `░░░░░░░░░░░░░░░░░░` | 122 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 66 | 65 | 0.459 | 0.467 |
| Remote Code Execution | 81 `░░░░░░░░░░░░░░░░░░` | 81 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 51 | 53 | 0.370 | 0.346 |
| System Prompt Leak | 43 `░░░░░░░░░░░░░░░░░░` | 43 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 23 | 29 | 0.465 | 0.326 |
| Reverse Shell | 33 `░░░░░░░░░░░░░░░░░░` | 33 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 0 | 0 | 1.000 | 1.000 |
| Ransomware | 31 `░░░░░░░░░░░░░░░░░░` | 31 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 1 | 4 | 0.968 | 0.871 |
| Safety Bypass | 20 `░░░░░░░░░░░░░░░░░░` | 20 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 13 | 11 | 0.350 | 0.450 |
| Role Hijack | 13 `░░░░░░░░░░░░░░░░░░` | 13 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 7 | 8 | 0.462 | 0.385 |
</details>

<details>
<summary>By corpus</summary>

| corpus | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| SkillTrustBench | 5403 `████████░░░░░░░░░░` | 5403 `████████░░░░░░░░░░` | 138 | 148 | 378 | 325 | 0.900 | 0.914 |
| benign | 3988 `██████░░░░░░░░░░░░` | 3988 `██████░░░░░░░░░░░░` | 188 | 202 | 0 | 0 | — | — |
| MaliciousSkillBench | 1153 `██░░░░░░░░░░░░░░░░` | 1153 `██░░░░░░░░░░░░░░░░` | 0 | 0 | 383 | 384 | 0.326 | 0.324 |
| SkillHarm | 975 `█░░░░░░░░░░░░░░░░░` | 975 `█░░░░░░░░░░░░░░░░░` | 4 | 5 | 682 | 679 | 0.234 | 0.237 |
| malware | 938 `█░░░░░░░░░░░░░░░░░` | 938 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 360 | 358 | 0.616 | 0.618 |
| Skill-Inject | 261 `░░░░░░░░░░░░░░░░░░` | 261 `░░░░░░░░░░░░░░░░░░` | 6 | 7 | 43 | 35 | 0.795 | 0.833 |
</details>

<details>
<summary>By attack vector</summary>

| attack vector | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| (none) | 7444 `███████████░░░░░░░` | 7444 `███████████░░░░░░░` | 336 | 362 | 671 | 665 | 0.406 | 0.411 |
| MIXED | 2421 `███░░░░░░░░░░░░░░░` | 2421 `███░░░░░░░░░░░░░░░` | 0 | 0 | 328 | 306 | 0.865 | 0.874 |
| CI | 1865 `███░░░░░░░░░░░░░░░` | 1865 `███░░░░░░░░░░░░░░░` | 0 | 0 | 260 | 230 | 0.861 | 0.877 |
| PI | 988 `█░░░░░░░░░░░░░░░░░` | 988 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 587 | 580 | 0.406 | 0.413 |
</details>



## Dev arms (`uv run arms`)

### Arm comparison (recall)

- control: 85b4ac355198, 2b226dac1615 (2 replicates)
- treatment: 9603248b33bf+6cdbc7e18c90+9a1086394679+82b9c8b4024b+57840626e375+aaddcde3a637+48eea52b374b+c52d6a715def+8effb572ce31+3cc1d715b6e2+dffba5e1d1ed+15efae346b20+ce7318e10e07+ca9f97c36aea+e106545d59ff+b2f41de8c746, 3ac394158e63 (2 replicates)

| arm | replicates | TP | FP | FN | TN | recall | precision | attributed recall |
|---|---|---|---|---|---|---|---|---|
| control | 2 replicates | 662.0 | 214.0 | 680.0 | 740.0 | 0.4933 | 0.7557 | 0.2241 |
| treatment | 2 replicates | 708.0 | 218.0 | 633.5 | 736.0 | 0.5278 | 0.7646 | 0.2414 |

- noise floor (control, 2 replicates): N_TP = 4, N_FP = 2
- dTP = +46.0, dFP = +4.0

Run provenance (from runs.config_json; flags relative to the first control, 85b4ac355198):

| arm | run | git sha | started (UTC) | SKILLSPECTOR_EXA_* |
|---|---|---|---|---|
| control | 85b4ac355198 | 7d196c53 | 2026-11-04 | reference: no EXA flags |
| control | 2b226dac1615 | 7d196c53 | 2026-11-04 | same as 85b4ac355198 |
| treatment | 9603248b33bf | 7d196c53 | 2026-11-04 | SKILLSPECTOR_EXA_LURE_RULES: (unset) -> 'on' |
| treatment | 6cdbc7e18c90 | 7d196c53 | 2026-11-04 | SKILLSPECTOR_EXA_LURE_RULES: (unset) -> 'on' |
| treatment | 9a1086394679 | 7d196c53 | 2026-11-04 | SKILLSPECTOR_EXA_LURE_RULES: (unset) -> 'on' |
| treatment | 82b9c8b4024b | 7d196c53 | 2026-11-04 | SKILLSPECTOR_EXA_LURE_RULES: (unset) -> 'on' |
| treatment | 57840626e375 | 7d196c53 | 2026-11-04 | SKILLSPECTOR_EXA_LURE_RULES: (unset) -> 'on' |
| treatment | aaddcde3a637 | 7d196c53 | 2026-11-04 | SKILLSPECTOR_EXA_LURE_RULES: (unset) -> 'on' |
| treatment | 48eea52b374b | 7d196c53 | 2026-11-04 | SKILLSPECTOR_EXA_LURE_RULES: (unset) -> 'on' |
| treatment | c52d6a715def | 7d196c53 | 2026-11-04 | SKILLSPECTOR_EXA_LURE_RULES: (unset) -> 'on' |
| treatment | 8effb572ce31 | 7d196c53 | 2026-11-04 | SKILLSPECTOR_EXA_LURE_RULES: (unset) -> 'on' |
| treatment | 3cc1d715b6e2 | 7d196c53 | 2026-11-04 | SKILLSPECTOR_EXA_LURE_RULES: (unset) -> 'on' |
| treatment | dffba5e1d1ed | 7d196c53 | 2026-11-04 | SKILLSPECTOR_EXA_LURE_RULES: (unset) -> 'on' |
| treatment | 15efae346b20 | 7d196c53 | 2026-11-04 | SKILLSPECTOR_EXA_LURE_RULES: (unset) -> 'on' |
| treatment | ce7318e10e07 | 7d196c53 | 2026-11-04 | SKILLSPECTOR_EXA_LURE_RULES: (unset) -> 'on' |
| treatment | ca9f97c36aea | 7d196c53 | 2026-11-04 | SKILLSPECTOR_EXA_LURE_RULES: (unset) -> 'on' |
| treatment | e106545d59ff | 7d196c53 | 2026-11-04 | SKILLSPECTOR_EXA_LURE_RULES: (unset) -> 'on' |
| treatment | b2f41de8c746 | 7d196c53 | 2026-11-04 | SKILLSPECTOR_EXA_LURE_RULES: (unset) -> 'on' |
| treatment | 3ac394158e63 | 7d196c53 | 2026-11-04 | SKILLSPECTOR_EXA_LURE_RULES: (unset) -> 'on' |

VERDICT: PROMISING

