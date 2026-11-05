# P6 overview: re-tuned block threshold

**Verdict: ACCEPTED at T = 49.** Units scoring 49 or 50 now block. `SKILLSPECTOR_EXA_BLOCK_THRESHOLD` is 49 by default
from `4e6863d1`, and `=51` restores upstream behaviour. From `33271de5`, a blocked unit's reported score is lifted to at
least 51, and an unblocked one is capped at 50. So the CLI exit code and the MCP `safe_to_install` field, which both
key on `score > 50`, agree with the recommendation (final review C1).

| T | Δrecall | Δprecision | ΔTP | ΔFP | holdout Δrecall |
|---|---|---|---|---|---|
| 51 → 49 | **+0.0087** (0.7248 → 0.7336) | **−0.0040** (0.9304 → 0.9264) | +56 | +26 | +0.0038 |

**Paired replay: zero nondeterminism; findings identical.**
- **Source:** the full run `bfa51d835e8b` on current defaults (2026-11-05, `c0e4ccaa`, healthy: 8.1% dropped, 0 errors).
- **Treatment:** `60503e65c287`, a replay of the same run at T = 49 with the final P6 semantics (clamped score). It matches the sweep run
  `5f4044b8e40a` in TP and FP.

1. **Selection (pre-registered; P6-R2).** The sweep over T ∈ {31, 33, ..., 61} is in `results/recall-p6-offline.md`.
   - **Filters:** the plan's (precision ≥ 0.92, precision ≥ P(51) − 0.01, FP ≤ 1.15 × FP(51)), plus the spec's
     final-acceptance clauses (precision ≥ P(51) − 0.005, holdout Δrecall ≥ 0).
   - **Result:** T = 49 has the highest recall that passes, under both the plan's rule as written and P6-R2. It clears
     the +0.5-point minimum.
   - **Nearest rejects:** T = 47 fails the FP cap (406 > 399) and P6-R2's precision clause (0.9212 < 0.9254), and T ≤ 45 fails precision 0.92.
2. **What moves.** Only units scored 49 or 50, 82 in this run: 56 malicious (FN→TP) and 26 benign (TN→FP). That is about
   2.2 TP per FP.
   - **Slices:** non-STB recall +0.017; SkillTrustBench +0.003; label tiers `working` +0.021, `intent` +0.012,
     `not_malicious` +0.021.
   - **Benign FP rate by package size:** it rises in every bucket, most in 6–20 components (+0.012) and 21+ (0.522 →
     0.556).
3. **The 26 new FPs.** All are `Skills/benign`. The most common HIGH rule among them is `SQP-2`, on 13 units, then
   `PE3` on 8. Units:
   - `aap-passport`, `aliyun-qwen-image-edit__stb-case_03555`, `asana`, `brainstorming__msb-src011-ASB04_008478`,
     `canva`, `clauditor`;
   - `elevenlabs-voices`, `flyai-japan-travel__stb-case_01214`, `ga4-analytics`, `lark-integration`,
     `linux-desktop__stb-case_02250`, `ms365-tenant-manager__stb-case_00892`;
   - `note-taker`, `openclaw-skill-vetter`, `orf`, `poetry-daily-art__stb-case_03145`, `polymarket-kalshi-divergence__stb-case_0…`,
     `polymarket-mert-sniper`;
   - `skill-vetting`, `smsf-document-creator__stb-case_00770`, `snowflake-mcp`, `tinyfish-web-agent`, `transcriptapi`,
     `unibase-membase`, `web-search-plus`, `zettel-brainstormer__stb-case_04741`.

   Several are mainstream integrations (Asana, Canva, GA4, Snowflake, MS365), so this is a real user-facing cost, not
   label noise.
4. **Replication (P6-R6, information only).** The same sweep over P5's full run `93c1faec5bec`, an independent LLM
   sample, also picks T = 49: +0.0069 recall, −0.0030 precision, +44 TP / +20 FP.
5. **Live smoke check (Step 4): not reproduced.**
   - **Runs:** `11f8b4ab54ce` and `2d55e4add55e`, with `SKILLSPECTOR_EXA_BLOCK_THRESHOLD=49`, each scanned malicious
     units that scored 49–50 in the source run. Both runs were healthy with no errors, so the flag is wired into the live
     pipeline.
   - **Result:** no live score landed in [49, 51). The 8 units scored 0, 25, 48, 23, 61, 21, 100 and 58, so a unit's
     score near the cut moves 2–51 points (median 26) from run to run.
   - **Coverage:** the logic is covered by unit and parity tests. Replay at T = 49 lifts all 82 units scored
     49–50 to score 51, band `HIGH`, `DO_NOT_INSTALL`, and no unit is left at 49 or 50.
6. **Cumulative against `baseline-v2`** (P0, confounded by drift): recall 0.712 → 0.734 (+0.022), precision 0.931 →
   0.926 (−0.005), holdout recall 0.873 → 0.879.
7. **Caveats.**
   - **The threshold is fitted and judged on one run's scores.** Paired replay removes arm-to-arm noise, not selection
     optimism. The replication on an independent run picks the same T with a smaller gain (+0.69 vs +0.87 points).
   - **Units at the cut are not stable.** Which units sit at 49–50 changes every run (item 5). The gain is a property of
     the score distribution, not of particular units.
   - **The precision clause binds closely.** −0.0040 against an allowed −0.005.
   - **P6-R2 added the spec's clauses to the plan's rule before any data.** Both rules pick T = 49.

## Handoffs

- **Flag provenance.** Unset `SKILLSPECTOR_EXA_BLOCK_THRESHOLD` means 51 before `4e6863d1` and 49 from it. `arms` and
  resume pinning compare env values only. Controls that need the old cut must set `=51` explicitly. Replay's `Policy()`
  stays 51, the upstream scorer, so replaying a run made at the new default needs `{"threshold": 49}` to reproduce
  its verdicts. `rulelab` also keeps its 51 cut (`RISK_THRESHOLD = 50`), so P5's offline results stay reproducible. A
  plan that replays at the shipped default must pass the cut explicitly.
- **Replay sources must be recorded at `SKILLSPECTOR_EXA_BLOCK_THRESHOLD=51`** (final re-review I1, P6-R11). At the
  default, the stored score is clamped, so a raw 49 or 50 is stored as 51. Replay builds on stored scores, so
  replaying such a run at another threshold, or under a policy that moves scores near the cut, gives wrong verdicts
  without warning. At 51 the clamp changes nothing, so those runs store raw scores. `bfa51d835e8b` predates the
  default and is safe. Longer term, the harness should store the raw score.
- **Five upstream tests are inverted by design.** In `tests/nodes/test_report.py`:
  - `TestReportNode::test_report_critical_finding_medium_band` and `test_report_doc_findings_no_multiplier` expect a
    score of 50 to band MEDIUM;
  - `TestComputeRiskScoreBasic::test_single_finding_full_confidence_scores_base_points[CRITICAL-50]`,
    `test_report_baseline_keeps_unmatched_finding` and `test_report_no_baseline_unchanged` expect a raw score of 50,
    which the clamp now lifts to 51.

  All five are strict xfail in the fork's root `conftest.py` while the effective threshold is 50 or below, calibrated
  for 49 and 51. They are documented in `docs/superpowers/EXPECTED_TEST_FAILURES.md` (P6-R9). The root suite now
  reports 14 xfailed.
- **The score-50 mass is a scoring artefact worth explaining.** Score 50 alone holds 43 malicious and 23 benign units in
  the source run, the biggest single-score mass between 41 and 52. P5 found static HIGH findings landing at 43–47. A plan
  that finds why scores pile up just under 51 (the fork's "meta-analyzer verdict over static severity" patch is the
  suspect) may beat a threshold move.
- **Deferred minors (replay/test):**
  - `replay.decide` maps a non-blocked score ≥ 81 under `Policy.threshold` > 81 to `DO_NOT_INSTALL` with
    `is_malicious` false (no range check on `Policy.threshold`; outside the grid);
  - no direct test at score == T for T > 51;
  - parity never combines the threshold with the doc-MEDIUM cap;
  - the parity test has duplicate helpers;
  - small cleanups in `_apply_threshold`.

<!-- spec report 1: uv run report results/recall.duckdb 60503e65c287 --base bfa51d835e8b -->
## SkillSpector benchmark: `p6 full control (current defaults)` → `p6 replay of bfa51d835e8b at T=49 (final, clamped)`

🟢 **Net +30** classifications improved over the 12718 unit(s) both runs scanned — 56 fixed, 26 regressed.

<sub>base = baseline, head = candidate. Δ = head − base; ▲ better, ▼ worse. Generated 2026-11-05 17:37 UTC from `results/recall.duckdb`.</sub>

### Run configuration

| | base · `p6 full control (current defaults)` | head · `p6 replay of bfa51d835e8b at T=49 (final, clamped)` |
|---|---|---|
| run id | `bfa51d835e8b` | `60503e65c287` |
| description | p6 full control (current defaults) | p6 replay of bfa51d835e8b at T=49 (final, clamped) |
| model | nvidia.nemotron-super-3-120b | nvidia.nemotron-super-3-120b |
| LLM | on | on |
| units (total) | 12,718 | 12,718 |
| started | 2026-11-05 09:53 | 2026-11-05 11:37 |
| workers | 96 | 96 |

### Health

| run | health |
|---|---|
| base · `p6 full control (current defaults)` | Health: OK |
| head · `p6 replay of bfa51d835e8b at T=49 (final, clamped)` | Health: OK |

### Outcomes

Every scanned unit is exactly one of these, so the rows **conserve to the total** —
reducing one bucket (e.g. eliminating timeouts) just moves those units into the
others. Read the two **bold** group rows for the verdict; the indented rows break
them down (a single sub-row moving isn't independently good or bad).

| | base | head | Δ |
|---|---|---|---|
| ✅ **correct** (TP + TN) | 10609 | 10639 | ▲ +30 |
| &emsp;true positives · malware caught | 4641 | 4697 | +56 |
| &emsp;true negatives · benign passed | 5968 | 5942 | -26 |
| 🔴 **incorrect** (FP + FN + errors) | 2109 | 2079 | ▲ -30 |
| &emsp;false positives · benign flagged | 347 | 373 | +26 |
| &emsp;false negatives · malware missed | 1762 | 1706 | -56 |
| &emsp;errors / timeouts | 0 | 0 | 0 |
| total scanned | 12718 | 12718 | 0 |

Overall correctness (correct ÷ scanned, errors counted as wrong): **0.834** → **0.837** (▲ +0.002).

### Detection quality

Rates over units that **produced a verdict** (errors excluded — base scored 12718, head scored 12718). When the two runs' error counts differ these are **not** a like-for-like comparison — use **Outcomes** above for the conserved view.

| metric | base | head | Δ |
|---|---|---|---|
| precision | 0.930 `█████████████████░` | 0.926 `█████████████████░` | ▼ -0.004 |
| recall | 0.725 `█████████████░░░░░` | 0.734 `█████████████░░░░░` | ▲ +0.009 |
| F1 | 0.815 `███████████████░░░` | 0.819 `███████████████░░░` | ▲ +0.004 |

### Head-to-head: what moved

Over the **12718** unit(s) scanned by both runs:

- 🟢 **56 fixed** (FN→TP, FP→TN, or error→resolved)
- 🔴 **26 regressed** (TP→FN, TN→FP, or →error)
- ⚪ **12636 unchanged**

<details>
<summary>🔴 Regressions (26) — showing first 25</summary>

| unit | base → head | type | malware |
|---|---|---|---|
| `Skills/benign/aap-passport` | TN → FP | skill / benign | — |
| `Skills/benign/aliyun-qwen-image-edit__stb-case_03555` | TN → FP | skill / benign | — |
| `Skills/benign/asana` | TN → FP | skill / benign | — |
| `Skills/benign/brainstorming__msb-src011-ASB04_008478` | TN → FP | skill / benign | — |
| `Skills/benign/canva` | TN → FP | skill / benign | — |
| `Skills/benign/clauditor` | TN → FP | skill / benign | — |
| `Skills/benign/elevenlabs-voices` | TN → FP | skill / benign | — |
| `Skills/benign/flyai-japan-travel__stb-case_01214` | TN → FP | skill / benign | — |
| `Skills/benign/ga4-analytics` | TN → FP | skill / benign | — |
| `Skills/benign/lark-integration` | TN → FP | skill / benign | — |
| `Skills/benign/linux-desktop__stb-case_02250` | TN → FP | skill / benign | — |
| `Skills/benign/ms365-tenant-manager__stb-case_00892` | TN → FP | skill / benign | — |
| `Skills/benign/note-taker` | TN → FP | skill / benign | — |
| `Skills/benign/openclaw-skill-vetter` | TN → FP | skill / benign | — |
| `Skills/benign/orf` | TN → FP | skill / benign | — |
| `Skills/benign/poetry-daily-art__stb-case_03145` | TN → FP | skill / benign | — |
| `Skills/benign/polymarket-kalshi-divergence__stb-case_01781` | TN → FP | skill / benign | — |
| `Skills/benign/polymarket-mert-sniper` | TN → FP | skill / benign | — |
| `Skills/benign/skill-vetting` | TN → FP | skill / benign | — |
| `Skills/benign/smsf-document-creator__stb-case_00770` | TN → FP | skill / benign | — |
| `Skills/benign/snowflake-mcp` | TN → FP | skill / benign | — |
| `Skills/benign/tinyfish-web-agent` | TN → FP | skill / benign | — |
| `Skills/benign/transcriptapi` | TN → FP | skill / benign | — |
| `Skills/benign/unibase-membase` | TN → FP | skill / benign | — |
| `Skills/benign/web-search-plus` | TN → FP | skill / benign | — |

<sub>… 1 more not shown (raise `--top`).</sub>

</details>

<details>
<summary>🟢 Fixes (56) — showing first 25</summary>

| unit | base → head | type | malware |
|---|---|---|---|
| `Skills/malware/TypeScript Conventions__PI_B15` | FN → TP | skill / malicious | PI Content Manipulation |
| `Skills/malware/adversary-emulation-toolkit` | FN → TP | skill / malicious | — |
| `Skills/malware/agent-browser-fopzsipap75u` | FN → TP | skill / malicious | — |
| `Skills/malware/agent-radio__stb-case_03635` | FN → TP | skill / malicious | PI Instruction Override |
| `Skills/malware/akshare-stock-analysis__stb-case_05347` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/analyze-ci__msb-src013-ASB04_000917` | FN → TP | skill / malicious |  Remote Code Execution |
| `Skills/malware/auto-updater-3miomc4dvir` | FN → TP | skill / malicious | — |
| `Skills/malware/cc-skill-project-guidelines-example` | FN → TP | skill / malicious | — |
| `Skills/malware/cert-checker__msb-src012-ASB04_005402` | FN → TP | skill / malicious |  Privilege Escalation |
| `Skills/malware/china-consumer-electronics-factory__stb-case_01859` | FN → TP | skill / malicious | CI |
| `Skills/malware/ci-pipeline-builder__stb-case_05653` | FN → TP | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/coding-agent__msb-src011-ASB04_003380` | FN → TP | skill / malicious |  Remote Code Execution |
| `Skills/malware/copilot__PI_B13` | FN → TP | skill / malicious | PI System Prompt Leak |
| `Skills/malware/d3-visualization__skillharm-fpp-e318e0aec4` | FN → TP | skill / malicious | PI |
| `Skills/malware/deployment-validator` | FN → TP | skill / malicious | — |
| `Skills/malware/docx__skillinject-contextual31-t0` | FN → TP | skill / malicious | PI Content Manipulation |
| `Skills/malware/docx__skillinject-contextual5-t5` | FN → TP | skill / malicious | PI Privilege Escalation |
| `Skills/malware/docx__skillinject-obvious35-t2` | FN → TP | skill / malicious | PI Goal Hijacking |
| `Skills/malware/ecommerce-email-quote__stb-case_02328` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/fuzzing-python__skillharm-fpp-db34ff9233` | FN → TP | skill / malicious | PI Privilege Escalation |
| `Skills/malware/glm-calibration__skillharm-fpp-39f2b1d47f` | FN → TP | skill / malicious | MIXED |
| `Skills/malware/gmail-skill__msb-src013-ASB04_007410` | FN → TP | skill / malicious |  Remote Code Execution |
| `Skills/malware/gog-5w7zvby` | FN → TP | skill / malicious | — |
| `Skills/malware/gradle-expert` | FN → TP | skill / malicious | — |
| `Skills/malware/graphics-api-hooking__msb-src002-ASB04_003374` | FN → TP | skill / malicious |  Instruction Override |

<sub>… 31 more not shown (raise `--top`).</sub>

</details>

### SkillTrustBench vs rest

Recall over **malicious** units, split by whether `_external_labels.jsonl` attributes the unit to SkillTrustBench.



| subset | base n | head n | base recall | head recall | Δ |
|---|---|---|---|---|---|
| SkillTrustBench | 3797 | 3797 | 0.915 | 0.918 | ▲ +0.003 |
| non-STB | 2606 | 2606 | 0.447 | 0.464 | ▲ +0.017 |


### Label-validity tiers


Raw counts over the annotated malicious units in `_boundary_labels.jsonl` (the 412-unit annotation sample), **unweighted** — not representative of the corpus mix.
`working` = CORRECT; `intent` = BROKEN, UNVERIFIABLE; `not_malicious` = WEAK, MISLABELED.

| tier | base n | head n | base recall | head recall | Δ |
|---|---|---|---|---|---|
| working | 233 | 233 | 0.459 | 0.481 | ▲ +0.021 |
| intent | 83 | 83 | 0.277 | 0.289 | ▲ +0.012 |
| not_malicious | 96 | 96 | 0.406 | 0.427 | ▲ +0.021 |


### SkillHarm attributed recall


A caught SkillHarm unit is **attributed** when at least one MEDIUM+ issue points at a file the attack injected; the rest were flagged for something else.

| metric | base | head | Δ |
|---|---|---|---|
| units (TP + FN) | 890 | 890 | 0 |
| verdict TP | 210 | 219 | +9 |
| attributed TP | 191 | 200 | +9 |
| recall | 0.236 | 0.246 | ▲ +0.010 |
| attributed recall | 0.215 | 0.225 | ▲ +0.010 |

### Benign FP rate by package size

Benign units bucketed by component count; FP rate = FP ÷ (FP + TN), errors excluded. `(none)` = no components recorded (usually a scan that errored).

| components | base n | head n | base FP rate | head FP rate | Δ |
|---|---|---|---|---|---|
| 1 | 826 | 826 | 0.002 | 0.004 | ▼ +0.001 |
| 2-5 | 4453 | 4453 | 0.031 | 0.033 | ▼ +0.002 |
| 6-20 | 946 | 946 | 0.171 | 0.183 | ▼ +0.012 |
| 21+ | 90 | 90 | 0.522 | 0.556 | ▼ +0.033 |


### Timing

Per-scan `run_time` stats. **Total scan time** is the sum (total work across all
scans) — resume-safe, unlike `finished_at − started_at`. **~est. wall** divides
that by the run's worker count to approximate elapsed time; it's an *estimate*
(ignores ramp-up, the under-saturated tail, and auth pauses, so it runs low).

| | scans | avg | median | p95 | max | total scan time | ~est. wall |
|---|---|---|---|---|---|---|---|
| **base** | 12718 | 23.47s | 13.98s | 85.49s | 288.96s | 82h54m | 51m48s |
| **head** | 12718 | 23.47s | 13.98s | 85.49s | 288.96s | 82h54m | 51m48s |

### Distributions

Per-dimension breakdown across both runs: sample size (`n`), false positives, false negatives, and recall. Recall is `—` where a group has no malicious units.

<details>
<summary>By category</summary>

| category | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| skill | 12667 `██████████████████` | 12667 `██████████████████` | 347 | 373 | 1762 | 1706 | 0.723 | 0.731 |
| code | 51 `░░░░░░░░░░░░░░░░░░` | 51 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 0 | 0 | 1.000 | 1.000 |
</details>

<details>
<summary>By behavior</summary>

| behavior | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| (none) | 8048 `███████████░░░░░░░` | 8048 `███████████░░░░░░░` | 347 | 373 | 598 | 572 | 0.655 | 0.670 |
| Privilege Escalation | 1071 `██░░░░░░░░░░░░░░░░` | 1071 `██░░░░░░░░░░░░░░░░` | 0 | 0 | 212 | 202 | 0.802 | 0.811 |
| Instruction Override | 1024 `█░░░░░░░░░░░░░░░░░` | 1024 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 87 | 85 | 0.915 | 0.917 |
| Malware Delivery | 1005 `█░░░░░░░░░░░░░░░░░` | 1005 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 153 | 150 | 0.848 | 0.851 |
| Data Exfiltration | 304 `░░░░░░░░░░░░░░░░░░` | 304 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 81 | 79 | 0.734 | 0.740 |
| Persistence | 285 `░░░░░░░░░░░░░░░░░░` | 285 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 71 | 69 | 0.751 | 0.758 |
| Content Manipulation | 250 `░░░░░░░░░░░░░░░░░░` | 250 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 192 | 190 | 0.232 | 0.240 |
| Goal Hijacking | 234 `░░░░░░░░░░░░░░░░░░` | 234 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 98 | 96 | 0.581 | 0.590 |
| Credential Theft | 154 `░░░░░░░░░░░░░░░░░░` | 154 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 108 | 107 | 0.299 | 0.305 |
| Resource Abuse | 122 `░░░░░░░░░░░░░░░░░░` | 122 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 64 | 64 | 0.475 | 0.475 |
| Remote Code Execution | 81 `░░░░░░░░░░░░░░░░░░` | 81 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 52 | 48 | 0.358 | 0.407 |
| System Prompt Leak | 43 `░░░░░░░░░░░░░░░░░░` | 43 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 27 | 26 | 0.372 | 0.395 |
| Reverse Shell | 33 `░░░░░░░░░░░░░░░░░░` | 33 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 0 | 0 | 1.000 | 1.000 |
| Ransomware | 31 `░░░░░░░░░░░░░░░░░░` | 31 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 0 | 0 | 1.000 | 1.000 |
| Safety Bypass | 20 `░░░░░░░░░░░░░░░░░░` | 20 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 11 | 10 | 0.450 | 0.500 |
| Role Hijack | 13 `░░░░░░░░░░░░░░░░░░` | 13 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 8 | 8 | 0.385 | 0.385 |
</details>

<details>
<summary>By corpus</summary>

| corpus | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| SkillTrustBench | 5403 `████████░░░░░░░░░░` | 5403 `████████░░░░░░░░░░` | 136 | 144 | 321 | 310 | 0.915 | 0.918 |
| benign | 3988 `██████░░░░░░░░░░░░` | 3988 `██████░░░░░░░░░░░░` | 196 | 213 | 0 | 0 | — | — |
| MaliciousSkillBench | 1153 `██░░░░░░░░░░░░░░░░` | 1153 `██░░░░░░░░░░░░░░░░` | 1 | 2 | 389 | 379 | 0.315 | 0.333 |
| SkillHarm | 975 `█░░░░░░░░░░░░░░░░░` | 975 `█░░░░░░░░░░░░░░░░░` | 4 | 4 | 680 | 671 | 0.236 | 0.246 |
| malware | 938 `█░░░░░░░░░░░░░░░░░` | 938 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 337 | 314 | 0.641 | 0.665 |
| Skill-Inject | 261 `░░░░░░░░░░░░░░░░░░` | 261 `░░░░░░░░░░░░░░░░░░` | 10 | 10 | 35 | 32 | 0.833 | 0.848 |
</details>

<details>
<summary>By attack vector</summary>

| attack vector | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| (none) | 7444 `███████████░░░░░░░` | 7444 `███████████░░░░░░░` | 347 | 373 | 648 | 618 | 0.426 | 0.453 |
| MIXED | 2421 `███░░░░░░░░░░░░░░░` | 2421 `███░░░░░░░░░░░░░░░` | 0 | 0 | 299 | 294 | 0.876 | 0.879 |
| CI | 1865 `███░░░░░░░░░░░░░░░` | 1865 `███░░░░░░░░░░░░░░░` | 0 | 0 | 241 | 233 | 0.871 | 0.875 |
| PI | 988 `█░░░░░░░░░░░░░░░░░` | 988 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 574 | 561 | 0.419 | 0.432 |
</details>


<!-- spec report 2: uv run report results/recall.duckdb 60503e65c287 --base e16e394f65c3 --split-file results/evalsets/splits.tsv -->
## SkillSpector benchmark: `baseline-v2: P0 tree, tags recorded` → `p6 replay of bfa51d835e8b at T=49 (final, clamped)`

🟢 **Net +103** classifications improved over the 12718 unit(s) both runs scanned — 552 fixed, 449 regressed.

<sub>base = baseline, head = candidate. Δ = head − base; ▲ better, ▼ worse. Generated 2026-11-05 17:37 UTC from `results/recall.duckdb`.</sub>

### Run configuration

| | base · `baseline-v2: P0 tree, tags recorded` | head · `p6 replay of bfa51d835e8b at T=49 (final, clamped)` |
|---|---|---|
| run id | `e16e394f65c3` | `60503e65c287` |
| description | baseline-v2: P0 tree, tags recorded | p6 replay of bfa51d835e8b at T=49 (final, clamped) |
| model | nvidia.nemotron-super-3-120b | nvidia.nemotron-super-3-120b |
| LLM | on | on |
| units (total) | 12,718 | 12,718 |
| started | 2026-11-02 08:12 | 2026-11-05 11:37 |
| workers | 96 | 96 |

### Health

| run | health |
|---|---|
| base · `baseline-v2: P0 tree, tags recorded` | Health: OK |
| head · `p6 replay of bfa51d835e8b at T=49 (final, clamped)` | Health: OK |

### Outcomes

Every scanned unit is exactly one of these, so the rows **conserve to the total** —
reducing one bucket (e.g. eliminating timeouts) just moves those units into the
others. Read the two **bold** group rows for the verdict; the indented rows break
them down (a single sub-row moving isn't independently good or bad).

| | base | head | Δ |
|---|---|---|---|
| ✅ **correct** (TP + TN) | 10536 | 10639 | ▲ +103 |
| &emsp;true positives · malware caught | 4557 | 4697 | +140 |
| &emsp;true negatives · benign passed | 5979 | 5942 | -37 |
| 🔴 **incorrect** (FP + FN + errors) | 2182 | 2079 | ▲ -103 |
| &emsp;false positives · benign flagged | 336 | 373 | +37 |
| &emsp;false negatives · malware missed | 1846 | 1706 | -140 |
| &emsp;errors / timeouts | 0 | 0 | 0 |
| total scanned | 12718 | 12718 | 0 |

Overall correctness (correct ÷ scanned, errors counted as wrong): **0.828** → **0.837** (▲ +0.008).

### Detection quality

Rates over units that **produced a verdict** (errors excluded — base scored 12718, head scored 12718). When the two runs' error counts differ these are **not** a like-for-like comparison — use **Outcomes** above for the conserved view.

| metric | base | head | Δ |
|---|---|---|---|
| precision | 0.931 `█████████████████░` | 0.926 `█████████████████░` | ▼ -0.005 |
| recall | 0.712 `█████████████░░░░░` | 0.734 `█████████████░░░░░` | ▲ +0.022 |
| F1 | 0.807 `███████████████░░░` | 0.819 `███████████████░░░` | ▲ +0.012 |

### Head-to-head: what moved

Over the **12718** unit(s) scanned by both runs:

- 🟢 **552 fixed** (FN→TP, FP→TN, or error→resolved)
- 🔴 **449 regressed** (TP→FN, TN→FP, or →error)
- ⚪ **11717 unchanged**

<details>
<summary>🔴 Regressions (449) — showing first 25</summary>

| unit | base → head | type | malware |
|---|---|---|---|
| `Skills/malware/13f-analyzer__msb-src013-ASB04_001351` | TP → FN | skill / malicious | — |
| `Skills/malware/adr-generator` | TP → FN | skill / malicious | — |
| `Skills/malware/advanced-agentdb-vector-search-implementation` | TP → FN | skill / malicious | — |
| `Skills/malware/agent-metrics-monitor__stb-case_05214` | TP → FN | skill / malicious | MIXED Instruction Override |
| `Skills/malware/agent-monitor__stb-case_01439` | TP → FN | skill / malicious | MIXED Privilege Escalation |
| `Skills/malware/agents` | TP → FN | skill / malicious | — |
| `Skills/malware/ai-it-department-wistec-core` | TP → FN | skill / malicious | — |
| `Skills/malware/ai-prompt-gen__stb-case_01689` | TP → FN | skill / malicious | CI |
| `Skills/malware/ai-writing-humanizer__stb-case_04342` | TP → FN | skill / malicious | CI |
| `Skills/malware/alibabacloud-cms-alert-rule-create__stb-case_05518` | TP → FN | skill / malicious | CI Credential Theft |
| `Skills/malware/alm-processing__PI_B13` | TP → FN | skill / malicious | PI System Prompt Leak |
| `Skills/malware/ambient-audio__stb-case_02543` | TP → FN | skill / malicious | CI Malware Delivery |
| `Skills/malware/api-design-principles__CI_B1` | TP → FN | skill / malicious | CI Data Exfiltration |
| `Skills/malware/auto-updater__stb-case_05672` | TP → FN | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/auto-updater__stb-case_05731` | TP → FN | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/bank-recon__stb-case_02585` | TP → FN | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/beauty-generation-free__msb-src006-ASB04_005848` | TP → FN | skill / malicious |  Data Exfiltration |
| `Skills/malware/bestseller-writer__stb-case_00865` | TP → FN | skill / malicious | CI Privilege Escalation |
| `Skills/malware/binance-trading-bot__stb-case_05741` | TP → FN | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/book-of-answers-skill__stb-case_00554` | TP → FN | skill / malicious | CI Privilege Escalation |
| `Skills/malware/bytesagain-cc-switch__stb-case_00703` | TP → FN | skill / malicious | CI |
| `Skills/malware/causal-inference-analyzer` | TP → FN | skill / malicious | — |
| `Skills/malware/changelog-automation__PI_B4` | TP → FN | skill / malicious | PI Malware Delivery |
| `Skills/malware/china-briefing__stb-case_05183` | TP → FN | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/china-industrial-machinery-suppliers__stb-case_01514` | TP → FN | skill / malicious | CI Privilege Escalation |

<sub>… 424 more not shown (raise `--top`).</sub>

</details>

<details>
<summary>🟢 Fixes (552) — showing first 25</summary>

| unit | base → head | type | malware |
|---|---|---|---|
| `Skills/malware/13f-analyzer__msb-src013-ASB04_003346` | FN → TP | skill / malicious |  Instruction Override |
| `Skills/malware/13f-analyzer__skillharm-fpp-6afc1fe426` | FN → TP | skill / malicious | MIXED |
| `Skills/malware/13f-analyzer__skillharm-fpp-cff4201b5a` | FN → TP | skill / malicious | CI Content Manipulation |
| `Skills/malware/AI-Cluster-Pre-flight-Check__stb-case_02413` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/Branch Orchestration__PI_B4` | FN → TP | skill / malicious | PI Malware Delivery |
| `Skills/malware/CacheLint__stb-case_05513` | FN → TP | skill / malicious | CI Malware Delivery |
| `Skills/malware/CodeReview-Automated-Code-Review-Assistant__stb-case_00313` | FN → TP | skill / malicious | CI |
| `Skills/malware/Council__PI_B12` | FN → TP | skill / malicious | PI Instruction Override |
| `Skills/malware/DFCF_StockPick__stb-case_00684` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/FlowCrawl__stb-case_00949` | FN → TP | skill / malicious | PI Instruction Override |
| `Skills/malware/Managing Database Testing` | FN → TP | skill / malicious | — |
| `Skills/malware/Personality-Engine__stb-case_03312` | FN → TP | skill / malicious | CI |
| `Skills/malware/Personality-Engine__stb-case_04499` | FN → TP | skill / malicious | MIXED Privilege Escalation |
| `Skills/malware/Study-Plan__stb-case_04161` | FN → TP | skill / malicious | CI |
| `Skills/malware/academic-pdf-redaction__msb-src013-ASB04_001945` | FN → TP | skill / malicious |  Instruction Override |
| `Skills/malware/adversarial-safety-simulator` | FN → TP | skill / malicious | — |
| `Skills/malware/agent-browser-fopzsipap75u` | FN → TP | skill / malicious | — |
| `Skills/malware/agent-browser-stealth__stb-case_00352` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/agent-task-status__stb-case_02937` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/agentx-news__stb-case_02122` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/ai-clip-maker__stb-case_03440` | FN → TP | skill / malicious | PI Instruction Override |
| `Skills/malware/airdrop-hunter__stb-case_05607` | FN → TP | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/airdrop-hunter__stb-case_05708` | FN → TP | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/akquant-backtest__stb-case_05219` | FN → TP | skill / malicious | CI |
| `Skills/malware/akshare-stock-analysis__stb-case_05347` | FN → TP | skill / malicious | CI Privilege Escalation |

<sub>… 527 more not shown (raise `--top`).</sub>

</details>

### SkillTrustBench vs rest

Recall over **malicious** units, split by whether `_external_labels.jsonl` attributes the unit to SkillTrustBench.



| subset | base n | head n | base recall | head recall | Δ |
|---|---|---|---|---|---|
| SkillTrustBench | 3797 | 3797 | 0.900 | 0.918 | ▲ +0.018 |
| non-STB | 2606 | 2606 | 0.437 | 0.464 | ▲ +0.028 |


### Label-validity tiers


Raw counts over the annotated malicious units in `_boundary_labels.jsonl` (the 412-unit annotation sample), **unweighted** — not representative of the corpus mix.
`working` = CORRECT; `intent` = BROKEN, UNVERIFIABLE; `not_malicious` = WEAK, MISLABELED.

| tier | base n | head n | base recall | head recall | Δ |
|---|---|---|---|---|---|
| working | 233 | 233 | 0.395 | 0.481 | ▲ +0.086 |
| intent | 83 | 83 | 0.289 | 0.289 | ▬ 0 |
| not_malicious | 96 | 96 | 0.417 | 0.427 | ▲ +0.010 |


### SkillHarm attributed recall


A caught SkillHarm unit is **attributed** when at least one MEDIUM+ issue points at a file the attack injected; the rest were flagged for something else.

| metric | base | head | Δ |
|---|---|---|---|
| units (TP + FN) | 890 | 890 | 0 |
| verdict TP | 208 | 219 | +11 |
| attributed TP | 187 | 200 | +13 |
| recall | 0.234 | 0.246 | ▲ +0.012 |
| attributed recall | 0.210 | 0.225 | ▲ +0.015 |

### Benign FP rate by package size

Benign units bucketed by component count; FP rate = FP ÷ (FP + TN), errors excluded. `(none)` = no components recorded (usually a scan that errored).

| components | base n | head n | base FP rate | head FP rate | Δ |
|---|---|---|---|---|---|
| 1 | 826 | 826 | 0.001 | 0.004 | ▼ +0.002 |
| 2-5 | 4453 | 4453 | 0.028 | 0.033 | ▼ +0.005 |
| 6-20 | 946 | 946 | 0.180 | 0.183 | ▼ +0.003 |
| 21+ | 90 | 90 | 0.456 | 0.556 | ▼ +0.100 |


### Splits

Per-split outcomes, recall and precision from `--split-file`; units not listed there are `unassigned`.

| split | base n | head n | base TP | head TP | base FP | head FP | base TN | head TN | base FN | head FN |
|---|---|---|---|---|---|---|---|---|---|---|
| holdout | 8477 | 8477 | 3494 | 3518 | 99 | 130 | 4377 | 4346 | 507 | 483 |
| dev | 4241 | 4241 | 1063 | 1179 | 237 | 243 | 1602 | 1596 | 1339 | 1223 |

| split | base n | head n | base recall | head recall | Δ |
|---|---|---|---|---|---|
| holdout | 8477 | 8477 | 0.873 | 0.879 | ▲ +0.006 |
| dev | 4241 | 4241 | 0.443 | 0.491 | ▲ +0.048 |


| split | base n | head n | base precision | head precision | Δ |
|---|---|---|---|---|---|
| holdout | 8477 | 8477 | 0.972 | 0.964 | ▼ -0.008 |
| dev | 4241 | 4241 | 0.818 | 0.829 | ▲ +0.011 |


### Timing

Per-scan `run_time` stats. **Total scan time** is the sum (total work across all
scans) — resume-safe, unlike `finished_at − started_at`. **~est. wall** divides
that by the run's worker count to approximate elapsed time; it's an *estimate*
(ignores ramp-up, the under-saturated tail, and auth pauses, so it runs low).

| | scans | avg | median | p95 | max | total scan time | ~est. wall |
|---|---|---|---|---|---|---|---|
| **base** | 12718 | 38.78s | 30.01s | 97.53s | 300.21s | 136h59m | 1h25m |
| **head** | 12718 | 23.47s | 13.98s | 85.49s | 288.96s | 82h54m | 51m48s |

### Distributions

Per-dimension breakdown across both runs: sample size (`n`), false positives, false negatives, and recall. Recall is `—` where a group has no malicious units.

<details>
<summary>By category</summary>

| category | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| skill | 12667 `██████████████████` | 12667 `██████████████████` | 336 | 373 | 1846 | 1706 | 0.709 | 0.731 |
| code | 51 `░░░░░░░░░░░░░░░░░░` | 51 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 0 | 0 | 1.000 | 1.000 |
</details>

<details>
<summary>By behavior</summary>

| behavior | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| (none) | 8048 `███████████░░░░░░░` | 8048 `███████████░░░░░░░` | 336 | 373 | 628 | 572 | 0.638 | 0.670 |
| Privilege Escalation | 1071 `██░░░░░░░░░░░░░░░░` | 1071 `██░░░░░░░░░░░░░░░░` | 0 | 0 | 217 | 202 | 0.797 | 0.811 |
| Instruction Override | 1024 `█░░░░░░░░░░░░░░░░░` | 1024 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 94 | 85 | 0.908 | 0.917 |
| Malware Delivery | 1005 `█░░░░░░░░░░░░░░░░░` | 1005 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 194 | 150 | 0.807 | 0.851 |
| Data Exfiltration | 304 `░░░░░░░░░░░░░░░░░░` | 304 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 77 | 79 | 0.747 | 0.740 |
| Persistence | 285 `░░░░░░░░░░░░░░░░░░` | 285 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 72 | 69 | 0.747 | 0.758 |
| Content Manipulation | 250 `░░░░░░░░░░░░░░░░░░` | 250 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 198 | 190 | 0.208 | 0.240 |
| Goal Hijacking | 234 `░░░░░░░░░░░░░░░░░░` | 234 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 99 | 96 | 0.577 | 0.590 |
| Credential Theft | 154 `░░░░░░░░░░░░░░░░░░` | 154 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 106 | 107 | 0.312 | 0.305 |
| Resource Abuse | 122 `░░░░░░░░░░░░░░░░░░` | 122 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 66 | 64 | 0.459 | 0.475 |
| Remote Code Execution | 81 `░░░░░░░░░░░░░░░░░░` | 81 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 51 | 48 | 0.370 | 0.407 |
| System Prompt Leak | 43 `░░░░░░░░░░░░░░░░░░` | 43 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 23 | 26 | 0.465 | 0.395 |
| Reverse Shell | 33 `░░░░░░░░░░░░░░░░░░` | 33 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 0 | 0 | 1.000 | 1.000 |
| Ransomware | 31 `░░░░░░░░░░░░░░░░░░` | 31 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 1 | 0 | 0.968 | 1.000 |
| Safety Bypass | 20 `░░░░░░░░░░░░░░░░░░` | 20 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 13 | 10 | 0.350 | 0.500 |
| Role Hijack | 13 `░░░░░░░░░░░░░░░░░░` | 13 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 7 | 8 | 0.462 | 0.385 |
</details>

<details>
<summary>By corpus</summary>

| corpus | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| SkillTrustBench | 5403 `████████░░░░░░░░░░` | 5403 `████████░░░░░░░░░░` | 138 | 144 | 378 | 310 | 0.900 | 0.918 |
| benign | 3988 `██████░░░░░░░░░░░░` | 3988 `██████░░░░░░░░░░░░` | 188 | 213 | 0 | 0 | — | — |
| MaliciousSkillBench | 1153 `██░░░░░░░░░░░░░░░░` | 1153 `██░░░░░░░░░░░░░░░░` | 0 | 2 | 383 | 379 | 0.326 | 0.333 |
| SkillHarm | 975 `█░░░░░░░░░░░░░░░░░` | 975 `█░░░░░░░░░░░░░░░░░` | 4 | 4 | 682 | 671 | 0.234 | 0.246 |
| malware | 938 `█░░░░░░░░░░░░░░░░░` | 938 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 360 | 314 | 0.616 | 0.665 |
| Skill-Inject | 261 `░░░░░░░░░░░░░░░░░░` | 261 `░░░░░░░░░░░░░░░░░░` | 6 | 10 | 43 | 32 | 0.795 | 0.848 |
</details>

<details>
<summary>By attack vector</summary>

| attack vector | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| (none) | 7444 `███████████░░░░░░░` | 7444 `███████████░░░░░░░` | 336 | 373 | 671 | 618 | 0.406 | 0.453 |
| MIXED | 2421 `███░░░░░░░░░░░░░░░` | 2421 `███░░░░░░░░░░░░░░░` | 0 | 0 | 328 | 294 | 0.865 | 0.879 |
| CI | 1865 `███░░░░░░░░░░░░░░░` | 1865 `███░░░░░░░░░░░░░░░` | 0 | 0 | 260 | 233 | 0.861 | 0.875 |
| PI | 988 `█░░░░░░░░░░░░░░░░░` | 988 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 587 | 561 | 0.406 | 0.432 |
</details>


