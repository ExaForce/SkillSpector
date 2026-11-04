# P5 overview: lure rules (EXA-LU1, EXA-LU4)

**Verdict: REJECTED** (user decision, 2026-11-04). The `arms` verdict was PROMISING, but the plan's guard failed as written.
Overriding a pre-registered guard after seeing the results was declined. No final full runs were made and no default
changed. `SKILLSPECTOR_EXA_LURE_RULES` ships default-off.

Candidate L, `SKILLSPECTOR_EXA_LURE_RULES=on`, adds two deterministic static rules, both HIGH at confidence 0.9:
- `EXA-LU1`: pipe-to-shell from an IP literal or a public paste service;
- `EXA-LU4`: base64 decode piped into an interpreter or `eval`.

All numbers are dev-set means on `results/evalsets/p5-dev.txt` (2,296 units: 1,342 malicious, 954 benign), from four
same-day runs on 2026-11-04, all healthy at the 10% threshold. Full-set and holdout numbers do not exist, because
final-acceptance runs are made only for an arm that passes Step 3, so the spec's two `report` commands were not run.

1. **Offline prediction against live** (rulelab, `results/recall-p5-offline.md`):
   - **Offline:** LU1 and LU4 pass the re-registered per-rule bar. Their replay at baseline-v2 predicts about 58 FN→TP
     flips and 1 TN→FP on the full set. Every rule-matched unit is in p5-dev, so this is also the dev prediction.
   - **Live:** 25 (screen union) and 32 (r2) units went from FN in both controls to TP with an `EXA-LU*` finding; 40
     distinct units across the two.
   - **Why live is lower:** the 38 matched malicious units that stay FN in r2 gain a median of about 11 risk points over
     the control mean (36.3 → 47.0), not the 20 the replay assumed, and 16 of them start at or below 30. Why a HIGH
     finding at confidence ≥ 0.9 adds only about 11 points there is unverified (see Handoffs).
2. **Δrecall against same-day control** (from `arms`: N_TP 4, N_FP 2):

   | arm | replicates | TP | FP | recall | precision |
   |---|---|---|---|---|---|
   | control | 2 | 662.0 | 214.0 | 0.4933 | 0.7557 |
   | L | 2 | 708.0 | 218.0 | 0.5278 | 0.7646 |

   ΔTP +46.0, ΔFP +4.0: PROMISING. About 28 of the +46 are attributable to the rules (item 1). The rest is
   run-to-run drift.

   By slice (malicious dev units per slice in brackets):

   | slice | control | L | Δ |
   |---|---|---|---|
   | native wild, `C07_native_wild` (612) | 0.545 | 0.568 | +0.023 |
   | STB dropper/installer cells (162) | 0.509 | 0.710 | **+0.201** |
   | MSB-wild, `C05_msb_wild_usenix` (153) | 0.186 | 0.173 | −0.013 |
   | SkillTrustBench (301) / non-STB (1,041) | 0.689 / 0.437 | 0.781 / 0.454 | +0.091 / +0.018 |

   - **STB dropper cells:** SkillTrustBench units whose `injection_pattern` contains `dropper` or `installer`.
   - **MSB-wild:** no rule matched its payload style, so the −0.013 there is drift.
3. **Lure-only share of new TPs.** Of the 40 rule-attributable new TPs:
   - 8 are annotated, all `CORRECT` (the `working` tier), so none are `intent` tier or `UNVERIFIABLE`;
   - 32 are unannotated.

   By source:
   - SkillTrustBench: 21, all Malware Delivery;
   - native-wild malware: 16;
   - MaliciousSkillBench: 3.

   Δ TP by validity tier over all units (means): `working` +7.5, `intent` +3.0, `not_malicious` −4.0, unannotated +39.5.
   The `intent` gain is not rule-attributable: no attributable unit is in that tier.
4. **Benign matches, by unit.** Offline, `EXA-LU4` matched 5 benign units and `EXA-LU1` matched none. All 5 are security
   tools quoting attack patterns, as Review Focus 5 expected:

   | unit | file (offline match) | baseline-v2 | live `EXA-LU*` finding |
   |---|---|---|---|
   | `Skills/benign/skill-security-audit` | `references/vulnerability-patterns.md` | TN | yes. FP in the union, TN in r2; also FP in control r2 |
   | `Skills/benign/openclaw-skill-vetter` | `SKILL.md` | TN | yes. TN in both replicates |
   | `Skills/benign/ecap-security-auditor` | `FERRET-ADOPTION-PLAN.md` | FP | no |
   | `Skills/benign/openclaw-defender` | `SKILL.md` | TN | no |
   | `Skills/benign/skillguard-scanner` | `SKILL.md` | TN | no |

   L's attributable FP cost is at most 0.5 per replicate. Why three offline matches produced no live finding is
   unverified.
5. **Why REJECTED.** Plan Step 3 picks "the best PROMISING arm whose guard passes", and the guard failed as written:

   | guard | units | control | L | rise | allowed |
   |---|---|---|---|---|---|
   | fetch line (`p5-guard-fetch`, benign `curl\|wget\|iwr\|Invoke-WebRequest`) | 246 | 75.0 | 79.5 | +4.5 | N_FP = 2 |

   Per-unit attribution says this is LLM drift, not the rule:
   - 46 of the 246 guard units change outcome between the two identical controls, and 80 change across the four
     replicates;
   - only 2 guard units ever carry an `EXA-LU*` finding (item 4);
   - the controls' total FP matched (214, 214) by chance, so N_FP sits at its floor of 2.

   The user kept the pre-registered guard rather than re-register it. A second reason supports that choice: even with an
   attributable guard, the rule's expected full-set gain is about 28 of 6,403 malicious units, roughly +0.45 recall
   points. That is under the spec's +0.5 acceptance minimum, so Task 4's two full runs would have been decided by noise.
6. **Cost.** LLM calls per scan: control 4.26, L 4.27 (static rules add none). Median scan time: control 13.2 s, L 17.7 s.
   The L figure pools the 16 screen batches, run at different times of day, and a regex pass is not 4 s, so treat the
   difference as endpoint load, not rule cost.
7. **Caveats:**
   - **The re-registered bar was set after the offline results were seen.** It was a user decision, recorded in
     `067cdd0c` before any dependent run. LU1 cleared it by one unit (16 against 15).
   - **The screen union is judged pooled** for health (5.6%). One of its 16 batches, b07, dropped 10.4% on its own
     (P5-R15).

## Handoffs

- **Near miss worth revisiting under a scoring plan.** L gives about +28 TP on dev at ≤ 0.5 FP, concentrated in STB
  dropper cells (+20 pts) and native-wild droppers. It fails on noise-limited gates, not on precision. A plan that
  changes how static HIGH findings combine (P6-style scoring) should re-measure it. The code is recoverable from
  `553b7d0d..7d196c53` if it is rolled back.
- **Replay overestimates static-rule gains by about 2×.** Matched FNs that stay FN gain a median of about 11 risk points
  from a HIGH finding at confidence ≥ 0.9, not the 20 the replay assumed. Find where the points go (downstream
  confidence adjustment, meta-analyzer, or report scoring) before trusting `rulelab` replay for P6.
- **Guards need their own noise floor.** A 246-unit benign guard flips 46 units between identical controls, but its
  allowed rise was the dev-wide N_FP (2 here, by coincidence). Future guards should be attributable (FPs carrying the
  candidate's own finding) or use the guard's own control spread, and be pre-registered that way.
- **Three offline benign matches got no live finding** (`ecap-security-auditor`, `openclaw-defender`,
  `skillguard-scanner`). The live path drops some matches the offline regex sees; find out why before relying on
  offline benign counts.
- **Deferred code minors (latent; flag off):**
  - the generalized `[exaforce: ` bypass prefix in `_hidden_text.py` retains any fork-marked finding;
  - the per-rule, per-file cap of 10 truncates silently;
  - LU1 and LU4 match single lines only;
  - `rulelab` imports the private `report._SEVERITY_POINTS`.

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

