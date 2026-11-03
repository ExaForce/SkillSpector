# P3 overview: skill-context header and per-skill instruction flow

**Verdict: REJECTED.** None of the four candidates was PROMISING on the dev set:
- A1 `SKILLSPECTOR_EXA_SKILL_CONTEXT=ssd`;
- A2 `SKILLSPECTOR_EXA_SKILL_CONTEXT=semantic`;
- B1 `SKILLSPECTOR_EXA_INSTRUCTION_FLOW=on`;
- B3, which is B1 with one prompt revision.

So no final full runs were made and no default was changed. Both flags ship committed with their defaults off.

All numbers are dev-set means on `results/evalsets/p3-dev.txt` (2,112 units: 1,078 malicious, 1,034 benign), from
same-day runs on 2026-11-03. Full-set and holdout numbers do not exist, because the spec's final-acceptance runs are
made only for PROMISING candidates.

1. **Δrecall against same-day control** (recall from `arms`, which counts TP / (TP+FN)), with precision:

   | arm | recall | Δrecall | precision |
   |---|---|---|---|
   | control | 0.353 | | 0.642 |
   | A1 | 0.372 | +0.019 | 0.646 |
   | A2 | 0.364 | +0.011 | 0.629 |
   | B1 | 0.437 | +0.085 | 0.665 |
   | B3 | 0.449 | +0.097 | 0.672 |

   - **C02 SkillHarm-redirect units** (423): control 0.163; A1 0.175; A2 0.155; B1 0.262; B3 0.287.
   - **`cross_file`-annotated units** (148): control 0.439; A1 0.488; A2 0.464; B1 0.551; B3 0.561.
2. **SkillHarm attributed recall:** control 0.166; A1 0.176; A2 0.161; B1 0.271; B3 0.287.
3. **Scan time** (`classifications.run_time`, pooled per arm):

   | arm | median (s) | ratio to control | p95 (s) | guard |
   |---|---|---|---|---|
   | control | 26.9 | | 205.1 | |
   | A1 | 25.7 | 0.96× | 161.2 | ≤1.25× ✓ |
   | A2 | 26.0 | 0.97× | 156.0 | ≤1.25× ✓ |
   | B1 | 27.8 | 1.03× | 149.2 | ≤1.40× ✓ |
   | B3 | 31.2 | 1.16× | 137.0 | ≤1.40× ✓ |

   Control's p95 is inflated by control r1's 184 timed-out scans.
4. **LLM calls per scan:** control 4.39; A1 4.40; A2 4.40; B1 5.09; B3 5.09. IF1 adds one call per applicable
   skill; the context header adds none.
5. **Why REJECTED** (`arms` against 4 controls, N_TP = 98, N_FP = 30):
   - A1: +23 TP / +9 FP.
   - A2: +17 TP / +22 FP.
   - B1: +99.5 TP / +30.2 FP. Fails both the noise floor and the 8:1 FP rule.
   - B3: +112.8 TP / +29.5 FP. Fails the noise floor (ΔTP < 196), its r2 is unhealthy, and it fails the multi-doc
     FP guard (+31.25 > 30). It passes the 8:1 rule at N_FP = 30 (+29.5 ≤ 30).
6. **Caveats:**
   - **Every run but two failed `health`.** 16 of 18 dev runs dropped 5.0–10.7% of scans' LLM calls. The drops are
     scattered: 459 units dropped in only 1 of 16 runs. That points to the endpoint, not a flag.
   - **The noise floor comes from one bad control.** Control r1 had 184 ERROR outcomes, and N_TP = 98 is set by that
     run alone. Under the pre-registered rule (P3-R12) every replicate was used. Without r1, N_TP = 15 and N_FP = 19;
     B1 (+77/+25) and B3 (+90/+24) are then still REJECT, on FP cost alone (about 3–4 TPs per FP, against 8). The
     verdict does not depend on the outlier.
   - **The 8:1 rule versus precision.** The dev set is FP-heavy: 208 of its 1,034 benign units were FPs at baseline-v2.
     B1 and B3 *raise* dev precision (0.642 → 0.665 / 0.672) and still fail the 8:1 rule, which counts raw FPs. The
     marginal precision of B3's additions is about 0.79 (90 / 114, without r1). That is below the full-set baseline
     precision of 0.931, so full-set precision would fall by some amount; the dev data cannot say whether it would
     stay within the −0.005 bar. A human can overrule with the spec's full-run test: one full control plus one full B1
     run, same day.
   - **IF1 is capped by the scoring.** One HIGH `EXA-IF1` at confidence c adds 25·c points, and the malicious
     threshold is 50. 458 malicious units are FN in all four B1 replicates; 97 of them carry a HIGH IF1 finding in at least one replicate. Most of
     the remaining recall headroom therefore needs a scoring path (for example the B2 idea: IF1 in P1's semantic gate),
     not prompt work. B2 was not run, because P1's gate was rejected.

## Dev arms (`uv run arms`)

### A1 ctx=ssd

#### Arm comparison (recall)

- control: 820f4e4e4e32, e89e74415880, bfcbcbe585e5, 2e6e81859349 (4 replicates)
- treatment: 64f64351fcc3, 81b9efffe9c3, a88091f5b7bc, df2855f770be (4 replicates)

| arm | replicates | TP | FP | FN | TN | recall | precision | attributed recall |
|---|---|---|---|---|---|---|---|---|
| control | 4 replicates | 371.8 | 207.5 | 682.2 | 803.5 | 0.3527 | 0.6418 | 0.1656 |
| treatment | 4 replicates | 395.0 | 216.8 | 667.8 | 816.8 | 0.3717 | 0.6457 | 0.1763 |

- noise floor (control, 4 replicates): N_TP = 98, N_FP = 30
- dTP = +23.2, dFP = +9.2

Run provenance (from runs.config_json; flags relative to the first control, 820f4e4e4e32):

| arm | run | git sha | started (UTC) | SKILLSPECTOR_EXA_* |
|---|---|---|---|---|
| control | 820f4e4e4e32 | d22fc89c | 2026-11-03 | reference: no EXA flags |
| control | e89e74415880 | d22fc89c | 2026-11-03 | same as 820f4e4e4e32 |
| control | bfcbcbe585e5 | d22fc89c | 2026-11-03 | same as 820f4e4e4e32 |
| control | 2e6e81859349 | d22fc89c | 2026-11-03 | same as 820f4e4e4e32 |
| treatment | 64f64351fcc3 | d22fc89c | 2026-11-03 | SKILLSPECTOR_EXA_SKILL_CONTEXT: (unset) -> 'ssd' |
| treatment | 81b9efffe9c3 | d22fc89c | 2026-11-03 | SKILLSPECTOR_EXA_SKILL_CONTEXT: (unset) -> 'ssd' |
| treatment | a88091f5b7bc | d22fc89c | 2026-11-03 | SKILLSPECTOR_EXA_SKILL_CONTEXT: (unset) -> 'ssd' |
| treatment | df2855f770be | d22fc89c | 2026-11-03 | SKILLSPECTOR_EXA_SKILL_CONTEXT: (unset) -> 'ssd' |

Reasons:
- dTP +23.2 < 2*N_TP = 196
- treatment run 64f64351fcc3 failed health: dropped LLM calls in 7.9% of scans (166/2112) > 5%; ERROR outcomes in 2.9% of scans (62/2112) > 1%
- treatment run 81b9efffe9c3 failed health: dropped LLM calls in 5.3% of scans (111/2112) > 5%
- treatment run a88091f5b7bc failed health: dropped LLM calls in 5.1% of scans (107/2112) > 5%
- treatment run df2855f770be failed health: dropped LLM calls in 5.4% of scans (115/2112) > 5%

VERDICT: REJECT


### A2 ctx=semantic

#### Arm comparison (recall)

- control: 820f4e4e4e32, e89e74415880, bfcbcbe585e5, 2e6e81859349 (4 replicates)
- treatment: 397dcabd6f82, 40a9a3b9c46c, 4d56e7b6db30 (3 replicates)

| arm | replicates | TP | FP | FN | TN | recall | precision | attributed recall |
|---|---|---|---|---|---|---|---|---|
| control | 4 replicates | 371.8 | 207.5 | 682.2 | 803.5 | 0.3527 | 0.6418 | 0.1656 |
| treatment | 3 replicates | 389.0 | 229.7 | 680.0 | 804.0 | 0.3639 | 0.6288 | 0.1612 |

- noise floor (control, 4 replicates): N_TP = 98, N_FP = 30
- dTP = +17.2, dFP = +22.2

Run provenance (from runs.config_json; flags relative to the first control, 820f4e4e4e32):

| arm | run | git sha | started (UTC) | SKILLSPECTOR_EXA_* |
|---|---|---|---|---|
| control | 820f4e4e4e32 | d22fc89c | 2026-11-03 | reference: no EXA flags |
| control | e89e74415880 | d22fc89c | 2026-11-03 | same as 820f4e4e4e32 |
| control | bfcbcbe585e5 | d22fc89c | 2026-11-03 | same as 820f4e4e4e32 |
| control | 2e6e81859349 | d22fc89c | 2026-11-03 | same as 820f4e4e4e32 |
| treatment | 397dcabd6f82 | d22fc89c | 2026-11-03 | SKILLSPECTOR_EXA_SKILL_CONTEXT: (unset) -> 'semantic' |
| treatment | 40a9a3b9c46c | d22fc89c | 2026-11-03 | SKILLSPECTOR_EXA_SKILL_CONTEXT: (unset) -> 'semantic' |
| treatment | 4d56e7b6db30 | d22fc89c | 2026-11-03 | SKILLSPECTOR_EXA_SKILL_CONTEXT: (unset) -> 'semantic' |

Reasons:
- dTP +17.2 < 2*N_TP = 196
- treatment run 397dcabd6f82 failed health: dropped LLM calls in 9.3% of scans (196/2112) > 5%; ERROR outcomes in 1.3% of scans (28/2112) > 1%
- treatment run 40a9a3b9c46c failed health: dropped LLM calls in 5.4% of scans (115/2112) > 5%

VERDICT: REJECT


### B1 if=on

#### Arm comparison (recall)

- control: 820f4e4e4e32, e89e74415880, bfcbcbe585e5, 2e6e81859349 (4 replicates)
- treatment: 9b07fabc029c, 836df5d8b1f9, a9949fa84c95, 2a94f96eb7c8 (4 replicates)

| arm | replicates | TP | FP | FN | TN | recall | precision | attributed recall |
|---|---|---|---|---|---|---|---|---|
| control | 4 replicates | 371.8 | 207.5 | 682.2 | 803.5 | 0.3527 | 0.6418 | 0.1656 |
| treatment | 4 replicates | 471.2 | 237.8 | 606.8 | 796.2 | 0.4372 | 0.6647 | 0.2706 |

- noise floor (control, 4 replicates): N_TP = 98, N_FP = 30
- dTP = +99.5, dFP = +30.2

Run provenance (from runs.config_json; flags relative to the first control, 820f4e4e4e32):

| arm | run | git sha | started (UTC) | SKILLSPECTOR_EXA_* |
|---|---|---|---|---|
| control | 820f4e4e4e32 | d22fc89c | 2026-11-03 | reference: no EXA flags |
| control | e89e74415880 | d22fc89c | 2026-11-03 | same as 820f4e4e4e32 |
| control | bfcbcbe585e5 | d22fc89c | 2026-11-03 | same as 820f4e4e4e32 |
| control | 2e6e81859349 | d22fc89c | 2026-11-03 | same as 820f4e4e4e32 |
| treatment | 9b07fabc029c | d22fc89c | 2026-11-03 | SKILLSPECTOR_EXA_INSTRUCTION_FLOW: (unset) -> 'on' |
| treatment | 836df5d8b1f9 | d22fc89c | 2026-11-03 | SKILLSPECTOR_EXA_INSTRUCTION_FLOW: (unset) -> 'on' |
| treatment | a9949fa84c95 | d22fc89c | 2026-11-03 | SKILLSPECTOR_EXA_INSTRUCTION_FLOW: (unset) -> 'on' |
| treatment | 2a94f96eb7c8 | d22fc89c | 2026-11-03 | SKILLSPECTOR_EXA_INSTRUCTION_FLOW: (unset) -> 'on' |

Reasons:
- dTP +99.5 < 2*N_TP = 196
- dFP +30.2 > max(N_FP=30, dTP/8=12.44) = 30.00: FP cost exceeds 8:1 extra TPs per extra FP
- treatment run 9b07fabc029c failed health: dropped LLM calls in 6.9% of scans (145/2112) > 5%
- treatment run 836df5d8b1f9 failed health: dropped LLM calls in 5.5% of scans (116/2112) > 5%
- treatment run a9949fa84c95 failed health: dropped LLM calls in 5.6% of scans (118/2112) > 5%
- treatment run 2a94f96eb7c8 failed health: dropped LLM calls in 5.4% of scans (113/2112) > 5%

VERDICT: REJECT


### B3 if=on, prompt revision

#### Arm comparison (recall)

- control: 820f4e4e4e32, e89e74415880, bfcbcbe585e5, 2e6e81859349 (4 replicates)
- treatment: e8688634c909, 09b9a0110cf8 (2 replicates)

| arm | replicates | TP | FP | FN | TN | recall | precision | attributed recall |
|---|---|---|---|---|---|---|---|---|
| control | 4 replicates | 371.8 | 207.5 | 682.2 | 803.5 | 0.3527 | 0.6418 | 0.1656 |
| treatment | 2 replicates | 484.5 | 237.0 | 593.5 | 797.0 | 0.4494 | 0.6715 | 0.2867 |

- noise floor (control, 4 replicates): N_TP = 98, N_FP = 30
- dTP = +112.8, dFP = +29.5

Run provenance (from runs.config_json; flags relative to the first control, 820f4e4e4e32):

| arm | run | git sha | started (UTC) | SKILLSPECTOR_EXA_* |
|---|---|---|---|---|
| control | 820f4e4e4e32 | d22fc89c | 2026-11-03 | reference: no EXA flags |
| control | e89e74415880 | d22fc89c | 2026-11-03 | same as 820f4e4e4e32 |
| control | bfcbcbe585e5 | d22fc89c | 2026-11-03 | same as 820f4e4e4e32 |
| control | 2e6e81859349 | d22fc89c | 2026-11-03 | same as 820f4e4e4e32 |
| treatment | e8688634c909 | 0c580f30 | 2026-11-03 | SKILLSPECTOR_EXA_INSTRUCTION_FLOW: (unset) -> 'on' |
| treatment | 09b9a0110cf8 | 0c580f30 | 2026-11-03 | SKILLSPECTOR_EXA_INSTRUCTION_FLOW: (unset) -> 'on' |

Reasons:
- dTP +112.8 < 2*N_TP = 196
- treatment run 09b9a0110cf8 failed health: dropped LLM calls in 5.8% of scans (122/2112) > 5%

VERDICT: REJECT



## Decision

- **P3: REJECTED.** No candidate was PROMISING, so there was no combined arm, no full runs and no default flip, as in
  P1-R8. Code ships with defaults off:
  - `SKILLSPECTOR_EXA_SKILL_CONTEXT` (unset = off; values `ssd`, `semantic`): `_skill_refs.py`, `_context_patches.py`.
  - `SKILLSPECTOR_EXA_INSTRUCTION_FLOW` (unset = off; `on`): `_instruction_flow.py`, with the measured B1 prompt
    restored after the final review (P3-R18): B3 was not better than B1 on FP, and its added wording names words that
    in this corpus are mostly file-naming habits of one attack generator (222 malicious vs 8 benign units have a
    component path containing them).
- **Where the signal is:** B1/B3 is the largest recall gain any program candidate has shown on dev: +8.5 to +9.7
  recall points, C02 +10 to +12 points, SkillHarm attributed +0.10 to +0.12. Its cost is FPs at about 3–4:1. The A
  arms (context header) are within noise.
- **Evidence:** ledger section "P3" in `results/recall-ledger.md`; per-run rows in its table.
