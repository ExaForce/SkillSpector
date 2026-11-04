# P4 overview: necessity audit (SSD-5 and the per-skill necessity analyzer)

**Verdict: REJECTED.** None of the three candidates was PROMISING on the dev set:
- A `SKILLSPECTOR_EXA_SSD5=on`: an SSD-5 "instruction the stated purpose does not need" category in the SSD prompt;
- B `SKILLSPECTOR_EXA_NECESSITY=on`: a per-skill necessity analyzer over SKILL.md (`EXA-NE1`, HIGH or MEDIUM);
- B-rev: B with the plan's one prompt revision (`6825fa30` + `75f9f822`).

A+gate and B+gate were not run, because P1's gate was rejected (P4-R8). No final full runs were made and no default
changed. Both flags ship with their defaults off.

All numbers are dev-set means on `results/evalsets/p4-dev.txt` (2,393 units: 1,122 malicious, 1,271 benign), from
same-day runs on 2026-11-04. Full-set and holdout numbers do not exist, because the spec's final-acceptance runs are
made only for PROMISING candidates, so the spec's two `report` commands were not run. Recall slices below are
per-replicate recalls averaged over replicates.

1. **Δrecall against same-day control**, with precision (from `arms`):

   | arm | replicates | recall | Δrecall | precision |
   |---|---|---|---|---|
   | control | 4 | 0.450 | | 0.690 |
   | A | 4 | 0.477 | +0.027 | 0.684 |
   | B | 2 | 0.520 | +0.070 | 0.680 |
   | B-rev | 4 | 0.506 | +0.057 | 0.688 |

   By target behaviour (dev units per slice in brackets):

   | slice | control | A | B | B-rev |
   |---|---|---|---|---|
   | Content Manipulation (249) | 0.252 | 0.286 (+0.034) | 0.322 (+0.070) | 0.300 (+0.048) |
   | Goal Hijacking (234) | 0.595 | 0.594 (−0.001) | 0.620 (+0.025) | 0.626 (+0.031) |
   | Resource Abuse (122) | 0.469 | 0.498 (+0.029) | 0.533 (+0.064) | 0.502 (+0.033) |
   | SkillHarm no-code (182) | 0.124 | 0.151 (+0.027) | 0.173 (+0.049) | 0.169 (+0.045) |

   SkillHarm no-code = malicious units whose `_external_labels.jsonl` `native_categories` include `anti_forensics`,
   `output_manipulation` or `poisoning` (182 of the 239 such units are in p4-dev).
2. **Guard FP** (benign dev units; allowed rise `max(N_FP = 27, 0.5% of the guard)`):

   | guard | units | control | A | B | B-rev |
   |---|---|---|---|---|---|
   | setup language | 663 | 125.8 | 138.2 (+12.5) | 155.5 (**+29.8, fail**) | 144.2 (+18.5) |
   | Skill-Inject clean | 49 | 7.2 | 7.0 (−0.2) | 8.0 (+0.8) | 7.2 (+0.0) |
   | 21+ files | 90 | 43.8 | 43.5 (−0.2) | 45.5 (+1.8) | 45.5 (+1.8) |

3. **LLM calls per scan:** control 4.39; A 4.39; B 5.48; B-rev 5.47. SSD-5 rides in the existing SSD call. NE1 adds
   one call per skill with a root SKILL.md. Median scan time: control 14.7 s; A 14.2 s; B 20.2 s; B-rev 17.2 s.
4. **Content Manipulation is still the weakest behaviour.** Among behaviours with at least 20 dev units, it has the
   lowest recall in every arm (B-rev 0.300; the next lowest is Persistence at 0.476).
5. **Why REJECTED** (`arms` against 4 controls, N_TP = 23, N_FP = 27, so ΔTP ≥ 46 and ΔFP ≤ max(27, ΔTP/8)):
   - A: +30.5 TP / +20.5 FP. Below the noise floor.
   - B: +79.0 TP / +48.0 FP. Fails the 8:1 FP rule and the setup-language guard.
   - B-rev: +63.5 TP / +30.5 FP. Fails the 8:1 FP rule by 3.5 FP.
   - Every treatment replicate also failed `health`, which the spec requires.
6. **Caveats:**
   - **No run was healthy.** All 12 full dev runs dropped LLM calls in 6.6–9.4% of scans, and only 3 of 32 screen
     batches passed. Under the spec's health clause no candidate could be PROMISING on 2026-11-04. All replicates were
     replaced once and then all were used (P4-R10, P4-R17).
   - **B-rev is a boundary case.** On its first two replicates it was +62.0 / +23.5, which passes the numeric rule.
     Its two replacements (both also unhealthy) raised the mean ΔFP to +30.5. Its four FP totals span 248–271, about
     the control spread (215–242). So the numeric part of the verdict is within noise of the bar; the health clause
     and the 4-replicate mean decide it.
   - **The scoring cap limits NE1, as it limited P3's IF1.** One HIGH `EXA-NE1` at confidence c adds 25·c risk points;
     the threshold is 50. 166 of B's 550 dev FNs (screen union) carry a HIGH NE1. The Task 2 E2E unit
     (`calendar__skillinject-contextual23-t0`) got HIGH 0.9 and stayed FN at risk 22.
   - **NE1's remaining FNs are mostly out of scope.** In a sample of 10, 7 put the harm in a script or config file that
     SKILL.md tells the agent to run; a SKILL.md-only analyzer sees only "run X".
   - **SSD-5 leaks out of its scope.** 25.5% of arm A's `SSD-5` findings (112.8 of 441.5 per run) land on files that are
     not markdown or text, despite the prompt's natural-language-only sentence (Review Focus 5).
   - **Run provenance.** Other sessions committed harness-only changes while runs were in progress, so runs record
     different shas; `src/` and the scan code are identical across them (P4-R13).

## Dev arms (`uv run arms`)

### A ssd5=on

#### Arm comparison (recall)

- control: 54ce3a6bbe59, 01d373aebd37, 92149d37b0d8, 354e5a84e14a (4 replicates)
- treatment: daed644651be, a753a1ba2c6c, 7c4a288e3a9d, 26b4d0c04b6f (4 replicates)

| arm | replicates | TP | FP | FN | TN | recall | precision | attributed recall |
|---|---|---|---|---|---|---|---|---|
| control | 4 replicates | 504.5 | 226.5 | 617.2 | 1044.5 | 0.4497 | 0.6902 | 0.1548 |
| treatment | 4 replicates | 535.0 | 247.0 | 587.0 | 1024.0 | 0.4768 | 0.6841 | 0.1753 |

- noise floor (control, 4 replicates): N_TP = 23, N_FP = 27
- dTP = +30.5, dFP = +20.5

Run provenance (from runs.config_json; flags relative to the first control, 54ce3a6bbe59):

| arm | run | git sha | started (UTC) | SKILLSPECTOR_EXA_* |
|---|---|---|---|---|
| control | 54ce3a6bbe59 | 6d093d72 | 2026-11-04 | reference: no EXA flags |
| control | 01d373aebd37 | 6d093d72 | 2026-11-04 | same as 54ce3a6bbe59 |
| control | 92149d37b0d8 | 6d093d72 | 2026-11-04 | same as 54ce3a6bbe59 |
| control | 354e5a84e14a | dd69e346 | 2026-11-04 | same as 54ce3a6bbe59 |
| treatment | daed644651be | 6d093d72 | 2026-11-04 | SKILLSPECTOR_EXA_SSD5: (unset) -> 'on' |
| treatment | a753a1ba2c6c | 6d093d72 | 2026-11-04 | SKILLSPECTOR_EXA_SSD5: (unset) -> 'on' |
| treatment | 7c4a288e3a9d | 8fbdfa84 | 2026-11-04 | SKILLSPECTOR_EXA_SSD5: (unset) -> 'on' |
| treatment | 26b4d0c04b6f | 065bd3ae | 2026-11-04 | SKILLSPECTOR_EXA_SSD5: (unset) -> 'on' |

Reasons:
- dTP +30.5 < 2*N_TP = 46
- treatment run daed644651be failed health: dropped LLM calls in 6.6% of scans (158/2393) > 5%
- treatment run a753a1ba2c6c failed health: dropped LLM calls in 7.9% of scans (190/2393) > 5%
- treatment run 7c4a288e3a9d failed health: dropped LLM calls in 9.3% of scans (222/2393) > 5%
- treatment run 26b4d0c04b6f failed health: dropped LLM calls in 8.9% of scans (213/2393) > 5%

VERDICT: REJECT

### B necessity=on

#### Arm comparison (recall)

- control: 54ce3a6bbe59, 01d373aebd37, 92149d37b0d8, 354e5a84e14a (4 replicates)
- treatment: f85f1be60ffd+62b0ffd7ef0b+667ffa2bd396+b68d62e8f2b1+fb74a2ff11b9+6a885ee1aa1f+d156c625000c+1e22c7af9c3c+934fa0f297bb+7de7cbf12157+7d384953bad8+4b41df745432+2b57f1d168c3+86f511d6db0a+bde68e0f300e+075504935411, e00694743a1e (2 replicates)

| arm | replicates | TP | FP | FN | TN | recall | precision | attributed recall |
|---|---|---|---|---|---|---|---|---|
| control | 4 replicates | 504.5 | 226.5 | 617.2 | 1044.5 | 0.4497 | 0.6902 | 0.1548 |
| treatment | 2 replicates | 583.5 | 274.5 | 538.5 | 996.5 | 0.5201 | 0.6801 | 0.2110 |

- noise floor (control, 4 replicates): N_TP = 23, N_FP = 27
- dTP = +79.0, dFP = +48.0

Run provenance (from runs.config_json; flags relative to the first control, 54ce3a6bbe59):

| arm | run | git sha | started (UTC) | SKILLSPECTOR_EXA_* |
|---|---|---|---|---|
| control | 54ce3a6bbe59 | 6d093d72 | 2026-11-04 | reference: no EXA flags |
| control | 01d373aebd37 | 6d093d72 | 2026-11-04 | same as 54ce3a6bbe59 |
| control | 92149d37b0d8 | 6d093d72 | 2026-11-04 | same as 54ce3a6bbe59 |
| control | 354e5a84e14a | dd69e346 | 2026-11-04 | same as 54ce3a6bbe59 |
| treatment | f85f1be60ffd | 5580e7a9 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 62b0ffd7ef0b | 5580e7a9 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 667ffa2bd396 | 5580e7a9 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | b68d62e8f2b1 | 5580e7a9 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | fb74a2ff11b9 | 5580e7a9 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 6a885ee1aa1f | 5580e7a9 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | d156c625000c | 5580e7a9 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 1e22c7af9c3c | 5580e7a9 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 934fa0f297bb | 5580e7a9 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 7de7cbf12157 | 5580e7a9 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 7d384953bad8 | 80891a8b | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 4b41df745432 | 80891a8b | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 2b57f1d168c3 | 80891a8b | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 86f511d6db0a | 80891a8b | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | bde68e0f300e | 71c440f5 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 075504935411 | 71c440f5 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | e00694743a1e | ff6a41e2 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |

Reasons:
- dFP +48.0 > max(N_FP=27, dTP/8=9.88) = 27.00: FP cost exceeds 8:1 extra TPs per extra FP
- treatment replicate f85f1be60ffd+62b0ffd7ef0b+667ffa2bd396+b68d62e8f2b1+fb74a2ff11b9+6a885ee1aa1f+d156c625000c+1e22c7af9c3c+934fa0f297bb+7de7cbf12157+7d384953bad8+4b41df745432+2b57f1d168c3+86f511d6db0a+bde68e0f300e+075504935411 (pooled over f85f1be60ffd, 62b0ffd7ef0b, 667ffa2bd396, b68d62e8f2b1, fb74a2ff11b9, 6a885ee1aa1f, d156c625000c, 1e22c7af9c3c, 934fa0f297bb, 7de7cbf12157, 7d384953bad8, 4b41df745432, 2b57f1d168c3, 86f511d6db0a, bde68e0f300e, 075504935411) failed health: dropped LLM calls in 7.7% of scans (184/2393) > 5%
- treatment run e00694743a1e failed health: dropped LLM calls in 8.1% of scans (195/2393) > 5%

VERDICT: REJECT

### B-rev necessity=on (revised prompt)

#### Arm comparison (recall)

- control: 54ce3a6bbe59, 01d373aebd37, 92149d37b0d8, 354e5a84e14a (4 replicates)
- treatment: f5ee327c52b1+cc58fe812b84+44fc96bfffea+0663eec2d1c2+ed7109c166f1+3a097f9e9f1d+c07749d4deef+a1500eb0aab3+885fdc393c06+a44075866eb8+7fdb941ace36+425087d0f98f+20309b14e741+ba97e4109215+496dbdfba81b+417e2f5a5444, 42a3e8b7a72c, 2cf05e51e07e, 1fe745793100 (4 replicates)

| arm | replicates | TP | FP | FN | TN | recall | precision | attributed recall |
|---|---|---|---|---|---|---|---|---|
| control | 4 replicates | 504.5 | 226.5 | 617.2 | 1044.5 | 0.4497 | 0.6902 | 0.1548 |
| treatment | 4 replicates | 568.0 | 257.0 | 554.0 | 1014.0 | 0.5062 | 0.6885 | 0.1943 |

- noise floor (control, 4 replicates): N_TP = 23, N_FP = 27
- dTP = +63.5, dFP = +30.5

Run provenance (from runs.config_json; flags relative to the first control, 54ce3a6bbe59):

| arm | run | git sha | started (UTC) | SKILLSPECTOR_EXA_* |
|---|---|---|---|---|
| control | 54ce3a6bbe59 | 6d093d72 | 2026-11-04 | reference: no EXA flags |
| control | 01d373aebd37 | 6d093d72 | 2026-11-04 | same as 54ce3a6bbe59 |
| control | 92149d37b0d8 | 6d093d72 | 2026-11-04 | same as 54ce3a6bbe59 |
| control | 354e5a84e14a | dd69e346 | 2026-11-04 | same as 54ce3a6bbe59 |
| treatment | f5ee327c52b1 | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | cc58fe812b84 | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 44fc96bfffea | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 0663eec2d1c2 | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | ed7109c166f1 | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 3a097f9e9f1d | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | c07749d4deef | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | a1500eb0aab3 | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 885fdc393c06 | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | a44075866eb8 | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 7fdb941ace36 | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 425087d0f98f | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 20309b14e741 | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | ba97e4109215 | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 496dbdfba81b | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 417e2f5a5444 | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 42a3e8b7a72c | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 2cf05e51e07e | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |
| treatment | 1fe745793100 | 75f9f822 | 2026-11-04 | SKILLSPECTOR_EXA_NECESSITY: (unset) -> 'on' |

Reasons:
- dFP +30.5 > max(N_FP=27, dTP/8=7.94) = 27.00: FP cost exceeds 8:1 extra TPs per extra FP
- treatment replicate f5ee327c52b1+cc58fe812b84+44fc96bfffea+0663eec2d1c2+ed7109c166f1+3a097f9e9f1d+c07749d4deef+a1500eb0aab3+885fdc393c06+a44075866eb8+7fdb941ace36+425087d0f98f+20309b14e741+ba97e4109215+496dbdfba81b+417e2f5a5444 (pooled over f5ee327c52b1, cc58fe812b84, 44fc96bfffea, 0663eec2d1c2, ed7109c166f1, 3a097f9e9f1d, c07749d4deef, a1500eb0aab3, 885fdc393c06, a44075866eb8, 7fdb941ace36, 425087d0f98f, 20309b14e741, ba97e4109215, 496dbdfba81b, 417e2f5a5444) failed health: dropped LLM calls in 7.7% of scans (184/2393) > 5%
- treatment run 42a3e8b7a72c failed health: dropped LLM calls in 7.6% of scans (181/2393) > 5%
- treatment run 2cf05e51e07e failed health: dropped LLM calls in 9.4% of scans (224/2393) > 5%
- treatment run 1fe745793100 failed health: dropped LLM calls in 7.9% of scans (188/2393) > 5%

VERDICT: REJECT

