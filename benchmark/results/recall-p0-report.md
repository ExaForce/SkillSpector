# P0 overview: baseline-v2 against the original baseline

P0 changed no classifier code, so the difference between `baseline-v2` (`e16e394f65c3`) and the original run
(`113b02ab497b`) measures endpoint drift plus per-unit nondeterminism. It is not an effect of any change.

- **Recall:** 0.709 → 0.712 (+0.003). **Precision:** 0.928 → 0.931 (+0.003). STB recall 0.902 → 0.900. Non-STB recall
  0.427 → 0.437.
- **Fixed 492, regressed 449.** This is **noise**: about 7.4% of units changed outcome with identical classifier
  code. The near-zero net (+43) is the expected run-to-run churn. It is why the spec requires same-day,
  replicated arms.
- **`llm-unconfirmed` share:** 7.9% of SSD HIGH/CRITICAL findings (198 of 2,509) carry the tag. These findings were
  kept by the severity floor and not confirmed by the meta-analyzer. P1's `confirmed` gate mode drops them.
- **Health:** `baseline-v2` passes all four checks: 530/12,718 = 4.2% of scans dropped LLM calls, 0 errors. The
  original run **fails** the dropped-calls check, at 6.9% (878/12,718). Do not cite it as a healthy comparator.
- **Provenance:**
  - The run started at `4c2a59fe`, which has the same `src/` tree as P0's final commit, since P0 touches only
    `benchmark/`.
  - At unit 10,638 it crashed on an out-of-range issue line number.
  - A harness fix landed (`1db355d1`, `e2023f4e`: NULL out-of-range lines, atomic `record_result`). The one
    partially written unit was deleted, and the run was resumed with `--run-id`. All 12,718 units are scored.

---

# SkillSpector benchmark: `original` → `baseline-v2`

🟢 **Net +43** classifications improved over the 12718 unit(s) both runs scanned — 492 fixed, 449 regressed.

<sub>base = baseline, head = candidate. Δ = head − base; ▲ better, ▼ worse. Generated 2026-11-02 15:57 UTC from `results/recall.duckdb`.</sub>

## Run configuration

| | base · `original` | head · `baseline-v2` |
|---|---|---|
| run id | `113b02ab497b` | `e16e394f65c3` |
| description | Full run with expanded benchmark dataset | baseline-v2: P0 tree, tags recorded |
| model | nvidia.nemotron-super-3-120b | nvidia.nemotron-super-3-120b |
| LLM | on | on |
| units (total) | 12,718 | 12,718 |
| started | 2026-10-28 09:59 | 2026-11-02 08:12 |
| workers | 96 | 96 |

## Health

| run | health |
|---|---|
| base · `original` | ⚠️ UNHEALTHY: dropped LLM calls in 6.9% of scans (878/12718) > 5% |
| head · `baseline-v2` | Health: OK |

## Outcomes

Every scanned unit is exactly one of these, so the rows **conserve to the total** —
reducing one bucket (e.g. eliminating timeouts) just moves those units into the
others. Read the two **bold** group rows for the verdict; the indented rows break
them down (a single sub-row moving isn't independently good or bad).

| | base | head | Δ |
|---|---|---|---|
| ✅ **correct** (TP + TN) | 10493 | 10536 | ▲ +43 |
| &emsp;true positives · malware caught | 4538 | 4557 | +19 |
| &emsp;true negatives · benign passed | 5955 | 5979 | +24 |
| 🔴 **incorrect** (FP + FN + errors) | 2225 | 2182 | ▲ -43 |
| &emsp;false positives · benign flagged | 352 | 336 | -16 |
| &emsp;false negatives · malware missed | 1865 | 1846 | -19 |
| &emsp;errors / timeouts | 8 | 0 | -8 |
| total scanned | 12718 | 12718 | 0 |

Overall correctness (correct ÷ scanned, errors counted as wrong): **0.825** → **0.828** (▲ +0.003).

## Detection quality

Rates over units that **produced a verdict** (errors excluded — base scored 12710, head scored 12718). When the two runs' error counts differ these are **not** a like-for-like comparison — use **Outcomes** above for the conserved view.

| metric | base | head | Δ |
|---|---|---|---|
| precision | 0.928 `█████████████████░` | 0.931 `█████████████████░` | ▲ +0.003 |
| recall | 0.709 `█████████████░░░░░` | 0.712 `█████████████░░░░░` | ▲ +0.003 |
| F1 | 0.804 `██████████████░░░░` | 0.807 `███████████████░░░` | ▲ +0.003 |

## Head-to-head: what moved

Over the **12718** unit(s) scanned by both runs:

- 🟢 **492 fixed** (FN→TP, FP→TN, or error→resolved)
- 🔴 **449 regressed** (TP→FN, TN→FP, or →error)
- ⚪ **11773 unchanged**, 4 other moves

<details>
<summary>🔴 Regressions (449) — showing first 25</summary>

| unit | base → head | type | malware |
|---|---|---|---|
| `Skills/malware/13f-analyzer__skillharm-fpp-b571a0c90e` | TP → FN | skill / malicious | MIXED Goal Hijacking |
| `Skills/malware/AI-Cluster-Pre-flight-Check__stb-case_02413` | TP → FN | skill / malicious | CI Privilege Escalation |
| `Skills/malware/AI-Cluster-Pre-flight-Check__stb-case_05306` | TP → FN | skill / malicious | CI Privilege Escalation |
| `Skills/malware/CacheLint__stb-case_05513` | TP → FN | skill / malicious | CI Malware Delivery |
| `Skills/malware/ComplianceAudit` | TP → FN | skill / malicious | — |
| `Skills/malware/PantryPilot__stb-case_02252` | TP → FN | skill / malicious | MIXED Instruction Override |
| `Skills/malware/Personality-Engine__stb-case_03312` | TP → FN | skill / malicious | CI |
| `Skills/malware/Study-Plan__stb-case_04161` | TP → FN | skill / malicious | CI |
| `Skills/malware/Travel-Search-Flight-Train-Scenery__stb-case_01652` | TP → FN | skill / malicious | CI |
| `Skills/malware/Tushare-Pro__stb-case_00926` | TP → FN | skill / malicious | CI |
| `Skills/malware/a-share-dcf-valuation__stb-case_01409` | TP → FN | skill / malicious | CI Privilege Escalation |
| `Skills/malware/agentx-news__stb-case_02122` | TP → FN | skill / malicious | CI Privilege Escalation |
| `Skills/malware/ai-clip-maker__stb-case_03440` | TP → FN | skill / malicious | PI Instruction Override |
| `Skills/malware/airdrop-hunter__stb-case_05607` | TP → FN | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/airdrop-hunter__stb-case_05708` | TP → FN | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/amp-code__stb-case_00849` | TP → FN | skill / malicious | CI Privilege Escalation |
| `Skills/malware/antigravity-image__msb-src004-ASB04_001417` | TP → FN | skill / malicious |  Remote Code Execution |
| `Skills/malware/auth-guardian` | TP → FN | skill / malicious | — |
| `Skills/malware/auto-updater__stb-case_05705` | TP → FN | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/backend-migrations__PI_B11` | TP → FN | skill / malicious | PI Safety Bypass |
| `Skills/malware/backtester__stb-case_05297` | TP → FN | skill / malicious | CI Privilege Escalation |
| `Skills/malware/bilibili-transcript__stb-case_04205` | TP → FN | skill / malicious | PI Instruction Override |
| `Skills/malware/biorxiv-database__PI_B14` | TP → FN | skill / malicious | PI Goal Hijacking |
| `Skills/malware/bitwarden-credential__stb-case_02999` | TP → FN | skill / malicious | CI Privilege Escalation |
| `Skills/malware/blrd` | TP → FN | skill / malicious | — |

<sub>… 424 more not shown (raise `--top`).</sub>

</details>

<details>
<summary>🟢 Fixes (492) — showing first 25</summary>

| unit | base → head | type | malware |
|---|---|---|---|
| `Skills/malware/13f-analyzer__msb-src013-ASB04_001351` | FN → TP | skill / malicious | — |
| `Skills/malware/13f-analyzer__skillharm-fpp-a0d35c388e` | FN → TP | skill / malicious | CI Resource Abuse |
| `Skills/malware/13f-analyzer__skillharm-fpp-c1dc9e681a` | FN → TP | skill / malicious | CI Resource Abuse |
| `Skills/malware/Allergy__stb-case_00395` | FN → TP | skill / malicious | CI |
| `Skills/malware/Einstein-Research-Portfolio-Risk-Analyzer__stb-case_04762` | FN → TP | skill / malicious | PI Instruction Override |
| `Skills/malware/Smart-Router__stb-case_03388` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/ZeeLin__stb-case_01764` | FN → TP | skill / malicious | CI Malware Delivery |
| `Skills/malware/ab-test-setup__PI_B11` | FN → TP | skill / malicious | PI Safety Bypass |
| `Skills/malware/ac-branch-pi-model__skillharm-fpp-9fd729a4cc` | FN → TP | skill / malicious | MIXED Data Exfiltration |
| `Skills/malware/advanced-agentdb-vector-search-implementation` | FN → TP | skill / malicious | — |
| `Skills/malware/adversary-emulation-toolkit` | FN → TP | skill / malicious | — |
| `Skills/malware/agent-metrics-monitor__stb-case_04321` | FN → TP | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/agent-metrics-monitor__stb-case_05214` | FN → TP | skill / malicious | MIXED Instruction Override |
| `Skills/malware/agent-radio__stb-case_03635` | FN → TP | skill / malicious | PI Instruction Override |
| `Skills/malware/agent-team-orchestration-v3-public__stb-case_01282` | FN → TP | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/agents` | FN → TP | skill / malicious | — |
| `Skills/malware/agentuity-cli-cloud-redis-show` | FN → TP | skill / malicious | — |
| `Skills/malware/ai-it-department-wistec-core` | FN → TP | skill / malicious | — |
| `Skills/malware/ai-rebirth__stb-case_03338` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/ai-writing-humanizer__stb-case_04342` | FN → TP | skill / malicious | CI |
| `Skills/malware/airdrop-hunter__stb-case_05674` | FN → TP | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/airdrop-hunter__stb-case_05726` | FN → TP | skill / malicious | MIXED Malware Delivery |
| `Skills/malware/alibabacloud-cms-alert-rule-create__stb-case_05518` | FN → TP | skill / malicious | CI Credential Theft |
| `Skills/malware/aliyun-wan-r2v__stb-case_00506` | FN → TP | skill / malicious | CI Privilege Escalation |
| `Skills/malware/alm-processing__PI_B13` | FN → TP | skill / malicious | PI System Prompt Leak |

<sub>… 467 more not shown (raise `--top`).</sub>

</details>

## SkillTrustBench vs rest

Recall over **malicious** units, split by whether `_external_labels.jsonl` attributes the unit to SkillTrustBench.



| subset | base n | head n | base recall | head recall | Δ |
|---|---|---|---|---|---|
| SkillTrustBench | 3797 | 3797 | 0.902 | 0.900 | ▼ -0.002 |
| non-STB | 2606 | 2606 | 0.427 | 0.437 | ▲ +0.010 |


## Label-validity tiers


Raw counts over the annotated malicious units in `_boundary_labels.jsonl` (the 412-unit annotation sample), **unweighted** — not representative of the corpus mix.
`working` = CORRECT; `intent` = BROKEN, UNVERIFIABLE; `not_malicious` = WEAK, MISLABELED.

| tier | base n | head n | base recall | head recall | Δ |
|---|---|---|---|---|---|
| working | 233 | 233 | 0.326 | 0.395 | ▲ +0.069 |
| intent | 83 | 83 | 0.277 | 0.289 | ▲ +0.012 |
| not_malicious | 96 | 96 | 0.344 | 0.417 | ▲ +0.073 |


## SkillHarm attributed recall


A caught SkillHarm unit is **attributed** when at least one MEDIUM+ issue points at a file the attack injected; the rest were flagged for something else.

| metric | base | head | Δ |
|---|---|---|---|
| units (TP + FN) | 890 | 890 | 0 |
| verdict TP | 199 | 208 | +9 |
| attributed TP | 182 | 187 | +5 |
| recall | 0.224 | 0.234 | ▲ +0.010 |
| attributed recall | 0.204 | 0.210 | ▲ +0.006 |

## Benign FP rate by package size

Benign units bucketed by component count; FP rate = FP ÷ (FP + TN), errors excluded. `(none)` = no components recorded (usually a scan that errored).

| components | base n | head n | base FP rate | head FP rate | Δ |
|---|---|---|---|---|---|
| 1 | 826 | 826 | 0.004 | 0.001 | ▲ -0.002 |
| 2-5 | 4452 | 4453 | 0.031 | 0.028 | ▲ -0.003 |
| 6-20 | 943 | 946 | 0.178 | 0.180 | ▼ +0.002 |
| 21+ | 86 | 90 | 0.488 | 0.456 | ▲ -0.033 |
| (none) | 8 | 0 | — | — | — |


## Timing

Per-scan `run_time` stats. **Total scan time** is the sum (total work across all
scans) — resume-safe, unlike `finished_at − started_at`. **~est. wall** divides
that by the run's worker count to approximate elapsed time; it's an *estimate*
(ignores ramp-up, the under-saturated tail, and auth pauses, so it runs low).

| | scans | avg | median | p95 | max | total scan time | ~est. wall |
|---|---|---|---|---|---|---|---|
| **base** | 12718 | 27.93s | 14.39s | 110.11s | 300.05s | 98h40m | 1h01m |
| **head** | 12718 | 38.78s | 30.01s | 97.53s | 300.21s | 136h59m | 1h25m |

## Distributions

Per-dimension breakdown across both runs: sample size (`n`), false positives, false negatives, and recall. Recall is `—` where a group has no malicious units.

<details>
<summary>By category</summary>

| category | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| skill | 12667 `██████████████████` | 12667 `██████████████████` | 352 | 336 | 1864 | 1846 | 0.707 | 0.709 |
| code | 51 `░░░░░░░░░░░░░░░░░░` | 51 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 1 | 0 | 0.980 | 1.000 |
</details>

<details>
<summary>By behavior</summary>

| behavior | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| (none) | 8048 `███████████░░░░░░░` | 8048 `███████████░░░░░░░` | 352 | 336 | 632 | 628 | 0.635 | 0.638 |
| Privilege Escalation | 1071 `██░░░░░░░░░░░░░░░░` | 1071 `██░░░░░░░░░░░░░░░░` | 0 | 0 | 226 | 217 | 0.789 | 0.797 |
| Instruction Override | 1024 `█░░░░░░░░░░░░░░░░░` | 1024 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 98 | 94 | 0.904 | 0.908 |
| Malware Delivery | 1005 `█░░░░░░░░░░░░░░░░░` | 1005 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 188 | 194 | 0.813 | 0.807 |
| Data Exfiltration | 304 `░░░░░░░░░░░░░░░░░░` | 304 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 81 | 77 | 0.734 | 0.747 |
| Persistence | 285 `░░░░░░░░░░░░░░░░░░` | 285 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 77 | 72 | 0.730 | 0.747 |
| Content Manipulation | 250 `░░░░░░░░░░░░░░░░░░` | 250 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 188 | 198 | 0.248 | 0.208 |
| Goal Hijacking | 234 `░░░░░░░░░░░░░░░░░░` | 234 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 94 | 99 | 0.598 | 0.577 |
| Credential Theft | 154 `░░░░░░░░░░░░░░░░░░` | 154 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 108 | 106 | 0.299 | 0.312 |
| Resource Abuse | 122 `░░░░░░░░░░░░░░░░░░` | 122 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 69 | 66 | 0.434 | 0.459 |
| Remote Code Execution | 81 `░░░░░░░░░░░░░░░░░░` | 81 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 51 | 51 | 0.370 | 0.370 |
| System Prompt Leak | 43 `░░░░░░░░░░░░░░░░░░` | 43 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 30 | 23 | 0.302 | 0.465 |
| Reverse Shell | 33 `░░░░░░░░░░░░░░░░░░` | 33 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 1 | 0 | 0.970 | 1.000 |
| Ransomware | 31 `░░░░░░░░░░░░░░░░░░` | 31 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 0 | 1 | 1.000 | 0.968 |
| Safety Bypass | 20 `░░░░░░░░░░░░░░░░░░` | 20 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 13 | 13 | 0.350 | 0.350 |
| Role Hijack | 13 `░░░░░░░░░░░░░░░░░░` | 13 `░░░░░░░░░░░░░░░░░░` | 0 | 0 | 9 | 7 | 0.308 | 0.462 |
</details>

<details>
<summary>By corpus</summary>

| corpus | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| SkillTrustBench | 5403 `████████░░░░░░░░░░` | 5403 `████████░░░░░░░░░░` | 141 | 138 | 372 | 378 | 0.902 | 0.900 |
| benign | 3988 `██████░░░░░░░░░░░░` | 3988 `██████░░░░░░░░░░░░` | 199 | 188 | 0 | 0 | — | — |
| MaliciousSkillBench | 1153 `██░░░░░░░░░░░░░░░░` | 1153 `██░░░░░░░░░░░░░░░░` | 2 | 0 | 389 | 383 | 0.315 | 0.326 |
| SkillHarm | 975 `█░░░░░░░░░░░░░░░░░` | 975 `█░░░░░░░░░░░░░░░░░` | 3 | 4 | 691 | 682 | 0.224 | 0.234 |
| malware | 938 `█░░░░░░░░░░░░░░░░░` | 938 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 375 | 360 | 0.600 | 0.616 |
| Skill-Inject | 261 `░░░░░░░░░░░░░░░░░░` | 261 `░░░░░░░░░░░░░░░░░░` | 7 | 6 | 38 | 43 | 0.819 | 0.795 |
</details>

<details>
<summary>By attack vector</summary>

| attack vector | base n | head n | base FP | head FP | base FN | head FN | base recall | head recall |
|---|---|---|---|---|---|---|---|---|
| (none) | 7444 `███████████░░░░░░░` | 7444 `███████████░░░░░░░` | 352 | 336 | 680 | 671 | 0.398 | 0.406 |
| MIXED | 2421 `███░░░░░░░░░░░░░░░` | 2421 `███░░░░░░░░░░░░░░░` | 0 | 0 | 349 | 328 | 0.856 | 0.865 |
| CI | 1865 `███░░░░░░░░░░░░░░░` | 1865 `███░░░░░░░░░░░░░░░` | 0 | 0 | 244 | 260 | 0.869 | 0.861 |
| PI | 988 `█░░░░░░░░░░░░░░░░░` | 988 `█░░░░░░░░░░░░░░░░░` | 0 | 0 | 592 | 587 | 0.401 | 0.406 |
</details>

