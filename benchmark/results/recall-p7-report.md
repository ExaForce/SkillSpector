# P7 overview: a stronger model for the SSD slot

**Verdict: REJECTED.** None of the three pre-registered candidates was PROMISING on the dev set. So no final full
runs were made, no default changed, and no code was written (Task 3 skipped). The only code change on the branch is a
benchmark harness fix (`79176a33`).

- **What was tested:** `SKILLSPECTOR_MODEL_SEMANTIC_SECURITY_DISCOVERY=<model>`. It routes the semantic security
  discovery (SSD) pass to another model; every other slot stays on `nvidia.nemotron-super-3-120b`.
  - The spec targets "the per-skill passes". Those were P3's and P4's nodes, which were rejected and rolled back. So
    the plan's fallback slot is SSD, a per-file batch pass, not a per-skill one.
- **Candidates:** the user chose the largest open-weight models on the endpoint (`910859ed`). All three passed the
  Task 1 probe, so the backups were not used.

All numbers are dev-set results on `results/evalsets/p7-dev.txt` (1,364 units: 412 malicious, 952 benign), from same-day
runs on 2026-11-05. Full-set and holdout numbers do not exist, because the spec's final-acceptance runs are made only for
PROMISING candidates. So the spec's two `report` commands were not run.

## Verdict block

| candidate | dev verdict | recall (Δ) | precision (Δ) | ΔTP / ΔFP | p95 time ratio | ERROR-rate change | rule_id violations |
|---|---|---|---|---|---|---|---|
| control (2 replicates) | | 0.420 | 0.429 | | 90.4 s | 0.00% | 1 / 422 SSD issues |
| `deepseek.v3.2` | REJECT (ΔTP < 2·N_TP = 20) | 0.452 (+0.032) | 0.458 (+0.029) | +13.0 / −10.0 | 1.11× | +0.00 pt | 2 / 659 (0.30%) |
| `qwen.qwen3-235b-a22b-2507` | REJECT (screen FUTILE) | 0.432 (+0.012) | 0.436 (+0.008) | +5 / −0.5 | 0.89× | +0.00 pt | 0 / 268 |
| `mistral.mistral-large-3-675b-instruct` | REJECT (ΔTP < 20) | 0.433 (+0.013) | 0.434 (+0.005) | +5.5 / +2.5 | 0.95× | +0.04 pt | 0 / 1,352 |

- **Recall and precision:** from `arms`, as means over 2 replicates per arm. Qwen's numbers come from its single screen
  replicate, because a FUTILE screen ends the candidate with no second run.
- **Noise floor:** N_TP = 10, N_FP = 5, from the same-day controls `7f54de6438ea` and `6822ec3bf3eb`.
- **Guards:** every candidate passes the cost guard (p95 ≤ 1.5× control, ERROR ≤ control + 0.5 pt) and the rule_id
  check (≤ 2% of `SSD*` issues outside SSD-1..SSD-4). Mistral has one ERROR unit in 2,728 scans.

## What this shows

1. **A stronger SSD model finds more, but the verdicts barely move.**
   - Mistral raised the number of `SSD-*` findings 3× (703 and 649 per replicate, against 224 and 198), and TP by only
     5.5.
   - Deepseek raised findings by about 55% (659 against 422) and TP by 13.
   - This is the same scoring ceiling P3 and P4 hit (`recall-boundaries.md` B1): one HIGH semantic finding scores about
     25 of the 50 needed to block.
   - A model change in the SSD slot cannot get past a scoring rule.
2. **Deepseek is the only candidate that improves both recall and precision** (+13 TP, −10 FP). It is still below the
   pre-registered bar of twice the noise floor. If a later plan opens a scoring path for semantic findings, deepseek in
   the SSD slot is the first combination worth re-testing.
3. **Cost is not the obstacle.** All three models run at or below the default's p95 on the dev set. The Task 1 probe
   suggested mistral was 1.74× slower on 5 units, but that did not hold at scale.
4. **Schema compliance.** No candidate emits meaningfully more off-schema rule ids than the default.
   - Qwen once returned an object instead of a string for an SSD `explanation`. That crashed the benchmark's result
     writer, though not the classifier.
   - The harness now stores such values as JSON (`79176a33`). The re-run produced none.

## Dev arms

### Controls

| replicate | run | TP | FP | FN | TN | dropped calls |
|---|---|---|---|---|---|---|
| r1 | `7f54de6438ea` | 168 | 228 | 244 | 724 | 8.8% (120/1,364) |
| r2 | `6822ec3bf3eb` | 178 | 233 | 234 | 719 | 8.1% (111/1,364) |

### deepseek.v3.2 (`arms`, kind recall)

| arm | replicates | TP | FP | FN | TN | recall | precision | attributed recall |
|---|---|---|---|---|---|---|---|---|
| control | 2 | 173.0 | 230.5 | 239.0 | 721.5 | 0.4199 | 0.4287 | 0.2759 |
| treatment | 2 | 186.0 | 220.5 | 226.0 | 731.5 | 0.4515 | 0.4576 | 0.2974 |

- **Treatment replicate 1:** the union of screen `p7-ds`, 10 batches `4fa60cf4e5b0` .. `811e11367658`. The screen
  PASSED, with union ΔTP +9 / ΔFP −11.5.
- **Treatment replicate 2:** `fd442519a30a`.
- `arms` verdict: **REJECT** (dTP +13.0 < 2·N_TP = 20).

### mistral.mistral-large-3-675b-instruct (`arms`, kind recall)

| arm | replicates | TP | FP | FN | TN | recall | precision | attributed recall |
|---|---|---|---|---|---|---|---|---|
| control | 2 | 173.0 | 230.5 | 239.0 | 721.5 | 0.4199 | 0.4287 | 0.2759 |
| treatment | 2 | 178.5 | 233.0 | 233.5 | 718.5 | 0.4333 | 0.4338 | 0.2672 |

- **Treatment replicate 1:** the union of screen `p7-ml`, 10 batches `9084f8036a80` .. `4ab9f4813acb`. The screen
  PASSED, with union ΔTP +10 / ΔFP +8.5.
- **Treatment replicate 2:** `4892f4b08e30`.
- `arms` verdict: **REJECT** (dTP +5.5 < 20). Attributed recall is lower than control.

### qwen.qwen3-235b-a22b-2507 (`screen`)

- **The first screen, `p7-qw`, crashed** in batch 1. Its run `96091f800126` stopped at 122 of 137 units. The cause was
  the harness bug above; the run is not used.
- **The re-run, `p7-qw2`** (P7-R6), ran 10 batches `6a2aba23c12e` .. `248c43c3c49e` at `79176a33`:

  | batch | units | ΔTP | ΔFP | F_ΔTP ± SD | F_ΔTP + 2.8·SD (TP: < 20) | stop |
  |---|---|---|---|---|---|---|
  | 10 | 1,364 | +5.0 | −0.5 | +5.0 ± 5.1 | +19.3 | FUTILE (TP) |

  The screen ends FUTILE at the last batch, so the dev verdict is **REJECT**.
- **Health (P7-R7):** 4 of the 10 batches dropped calls in 10.3–11.7% of scans. As one union replicate, the screen
  drops 8.8% (120/1,364), which is control r1's figure. The dropped scans hold 17 FN, against 17 and 16 in the controls.

## Caveats

- **The dev set is small for this question:** 412 malicious units. The bar of twice the noise floor (ΔTP ≥ 20) is
  about +4.9 recall points. A real +2–3 point gain, the size deepseek shows, cannot clear it on this set.
- **One model per slot was tested, in one slot.** Ensembles and multi-slot routing were out of scope.
- **The model list is the endpoint's on 2026-11-05.** It is not stable: the listing order is random, and the
  catalogue is not the same as what can actually be routed.

## Handoffs

- **The harness fix `79176a33` changes `benchmark/` only.** Any model that returns structured `explanation` values can
  now be recorded.
- **Re-test candidate:** deepseek in the SSD slot, after any plan that lets corroborated semantic findings block.
