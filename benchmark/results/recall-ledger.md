# Recall improvement program: run ledger

Program DB: `benchmark/results/recall.duckdb`, created as a copy of `malskillbench_agentguard_seed.duckdb`, so it holds
the original run `113b02ab497b`. Spec: `docs/superpowers/specs/2026-10-29-recall-improvement-program.md`. Append one
row per run, and one decision block per plan below the table.

| plan | iteration | arm | replicate | run_id | git sha | flags | units | health | note |
|---|---|---|---|---|---|---|---|---|---|
| P0 | ref | original | - | `113b02ab497b` | unrecorded | none | 12,718 | UNHEALTHY: dropped LLM calls 6.9% | seed DB; no `issues.tags`; recall 0.709, precision 0.928 |
| P0 | preflight | control | 1 | `6505da99b6a6` | 4c2a59fe | none | 1 | OK | `pptx__skillharm-fpp-a4db25e26d`: TP, SDI-1/SQP-3 HIGH, tags recorded |
| P0 | baseline | control | 1 | `e16e394f65c3` | 4c2a59fe (src = P0 final) | none | 12,718 | OK (dropped 4.2%, 0 errors) | baseline-v2; crashed at 10,638 on an INT32 line number, fixed in `1db355d1`/`e2023f4e`, resumed with `--run-id`; recall 0.712, precision 0.931 |
| P1 | offline | replay gate=any | - | `5f9fefc7f1f6` | be5bb791 | `{"gate_rules":["SSD-1","SSD-2","SSD-3","SSD-4","P2"],"gate_mode":"any"}` | 12,718 | OK | ΔTP +210 / ΔFP +24 |
| P1 | offline | replay gate=confirmed | - | `b1933d090aa7` | be5bb791 | `{"gate_rules":["SSD-1","SSD-2","SSD-3","SSD-4","P2"],"gate_mode":"confirmed"}` | 12,718 | OK | ΔTP +185 / ΔFP +18 |
| P1 | offline | replay cap=2 | - | `89c73f98af88` | be5bb791 | `{"doc_medium_cap":2}` | 12,718 | OK | ΔTP -3 / ΔFP -1 |
| P1 | offline | replay cap=3 | - | `4a8049d56816` | be5bb791 | `{"doc_medium_cap":3}` | 12,718 | OK | ΔTP -1 / ΔFP 0 |
| P1 | offline | replay cap=5 | - | `e671c607a9e7` | be5bb791 | `{"doc_medium_cap":5}` | 12,718 | OK | ΔTP 0 / ΔFP 0 |
| P1 | preflight | control | 1 | `91a3ea818a76` | a7497284 | none | 1 | OK | `pptx__skillharm-fpp-a4db25e26d`: TP |
| P1 | dev | control | 1 | `ce0668313941` | a7497284 | none | 1,364 (p1-dev) | UNHEALTHY: dropped 5.6% | TP 155 / FP 195 |
| P1 | dev | control | 2 | `ad146b917438` | a7497284 | none | 1,364 (p1-dev) | OK (4.8%) | TP 153 / FP 203 |
| P1 | dev | gate=confirmed | 1 | `46bf363f7145` | a7497284 | `SKILLSPECTOR_EXA_SEMANTIC_GATE=confirmed` | 1,364 (p1-dev) | OK (4.8%) | TP 188 / FP 210 |
| P1 | dev | gate=confirmed | 2 | `4952d46c49a0` | a7497284 | `SKILLSPECTOR_EXA_SEMANTIC_GATE=confirmed` | 1,364 (p1-dev) | OK (4.8%) | TP 183 / FP 215 |
| P1 | dev | control | 3 | `2271319bfae5` | a7497284 | none | 1,364 (p1-dev) | UNHEALTHY: dropped 6.1% | TP 153 / FP 216; replacement for control 1, also unhealthy, so not used |
| P2 | preflight | B | 1 | `44839f58f160` | e5de1bf2 | `SKILLSPECTOR_EXA_DOC_TEXT=on SKILLSPECTOR_EXA_HIDDEN_TEXT=on` | 1 | OK | `pptx__skillharm-fpp-a4db25e26d`: TP |
| P2 | dev | control | 1 | `dec8d72989b3` | e5de1bf2 | none | 2,154 (p2-dev) | OK | TP 176 / FP 223 |
| P2 | dev | A doc_text | 1 | `ab0a8478cbe9` | e5de1bf2 | `SKILLSPECTOR_EXA_DOC_TEXT=on` | 2,154 (p2-dev) | OK | TP 213 / FP 226 |
| P2 | dev | B doc_text+hidden | 1 | `d05bd241b62a` | e5de1bf2 | `SKILLSPECTOR_EXA_DOC_TEXT=on SKILLSPECTOR_EXA_HIDDEN_TEXT=on` | 2,154 (p2-dev) | OK | TP 213 / FP 210 |
| P2 | dev | control | 2 | `6f4afaba94e5` | e5de1bf2 | none | 261 of 2,154 | UNHEALTHY: hung; dropped 6.1% | harness deadlock: no progress after 2026-11-02 19:46, all workers idle in `sem_wait`, per-scan timeout never fired; killed 2026-11-03; not usable |
| P3 | e2e | B1 if=on | 1 | `c8b5173f1bd8` | 5439b4ef + uncommitted Task 3 | `SKILLSPECTOR_EXA_INSTRUCTION_FLOW=on` | 1 | OK | Task 3 E2E: no crash, LLM 6/6, 0 EXA-IF1 in the report |
| P3 | e2e | B1 if=on | 2 | `28f86fe1f857` | 5439b4ef + uncommitted Task 3 | `SKILLSPECTOR_EXA_INSTRUCTION_FLOW=on` | 1 | OK | Task 3 E2E repeat: 0 EXA-IF1 (a direct node call emitted HIGH IF1) |
| P3 | preflight | all flags | 1 | `f226e1b6ec3b` | d22fc89c | `SKILLSPECTOR_EXA_SKILL_CONTEXT=semantic SKILLSPECTOR_EXA_INSTRUCTION_FLOW=on` | 1 | OK | `pptx__skillharm-fpp-a4db25e26d`: TP, LLM 6/6, 1 EXA-IF1 |
| P3 | dev | control | 1 | `820f4e4e4e32` | d22fc89c | none | 2,112 (p3-dev) | UNHEALTHY: dropped 10.7%, ERROR 8.7% (184) | TP 304 / FP 191; used (P3-R12) |
| P3 | dev | A1 ctx=ssd | 1 | `64f64351fcc3` | d22fc89c | `SKILLSPECTOR_EXA_SKILL_CONTEXT=ssd` | 2,112 (p3-dev) | UNHEALTHY: dropped 7.9%, ERROR 2.9% (62) | TP 342 / FP 208; used (P3-R12) |
| P3 | dev | A2 ctx=semantic | 1 | `397dcabd6f82` | d22fc89c | `SKILLSPECTOR_EXA_SKILL_CONTEXT=semantic` | 2,112 (p3-dev) | UNHEALTHY: dropped 9.3%, ERROR 1.3% (28) | TP 367 / FP 224; used (P3-R12) |
| P3 | dev | B1 if=on | 1 | `9b07fabc029c` | d22fc89c | `SKILLSPECTOR_EXA_INSTRUCTION_FLOW=on` | 2,112 (p3-dev) | UNHEALTHY: dropped 6.9% | TP 464 / FP 236; used (P3-R12) |
| P3 | dev | control | 2 | `e89e74415880` | d22fc89c | none | 2,112 (p3-dev) | UNHEALTHY: dropped 5.8% | TP 394 / FP 221; used (P3-R12) |
| P3 | dev | A1 ctx=ssd | 2 | `81b9efffe9c3` | d22fc89c | `SKILLSPECTOR_EXA_SKILL_CONTEXT=ssd` | 2,112 (p3-dev) | UNHEALTHY: dropped 5.3% | TP 413 / FP 222; used (P3-R12) |
| P3 | dev | A2 ctx=semantic | 2 | `c4b4583ff458` | d22fc89c | `SKILLSPECTOR_EXA_SKILL_CONTEXT=semantic` | 2,112 (p3-dev) | UNHEALTHY: dropped 5.2% | TP 385 / FP 229; replaced by healthy r2b `4d56e7b6db30`, not used |
| P3 | dev | B1 if=on | 2 | `836df5d8b1f9` | d22fc89c | `SKILLSPECTOR_EXA_INSTRUCTION_FLOW=on` | 2,112 (p3-dev) | UNHEALTHY: dropped 5.5% | TP 480 / FP 235; used (P3-R12) |
| P3 | dev | control | 1b | `bfcbcbe585e5` | d22fc89c | none | 2,112 (p3-dev) | UNHEALTHY: dropped 5.0% | TP 402 / FP 216; replacement for r1, also unhealthy; used |
| P3 | dev | A1 ctx=ssd | 1b | `a88091f5b7bc` | d22fc89c | `SKILLSPECTOR_EXA_SKILL_CONTEXT=ssd` | 2,112 (p3-dev) | UNHEALTHY: dropped 5.1% | TP 404 / FP 215; used |
| P3 | dev | A2 ctx=semantic | 1b | `40a9a3b9c46c` | d22fc89c | `SKILLSPECTOR_EXA_SKILL_CONTEXT=semantic` | 2,112 (p3-dev) | UNHEALTHY: dropped 5.4% | TP 394 / FP 223; used |
| P3 | dev | B1 if=on | 1b | `a9949fa84c95` | d22fc89c | `SKILLSPECTOR_EXA_INSTRUCTION_FLOW=on` | 2,112 (p3-dev) | UNHEALTHY: dropped 5.6% | TP 471 / FP 249; used |
| P3 | dev | control | 2b | `2e6e81859349` | d22fc89c | none | 2,112 (p3-dev) | UNHEALTHY: dropped 5.3% | TP 387 / FP 202; used |
| P3 | dev | A1 ctx=ssd | 2b | `df2855f770be` | d22fc89c | `SKILLSPECTOR_EXA_SKILL_CONTEXT=ssd` | 2,112 (p3-dev) | UNHEALTHY: dropped 5.4% | TP 421 / FP 222; used |
| P3 | dev | A2 ctx=semantic | 2b | `4d56e7b6db30` | d22fc89c | `SKILLSPECTOR_EXA_SKILL_CONTEXT=semantic` | 2,112 (p3-dev) | OK (4.0%) | TP 406 / FP 242; replaces r2 |
| P3 | dev | B1 if=on | 2b | `2a94f96eb7c8` | d22fc89c | `SKILLSPECTOR_EXA_INSTRUCTION_FLOW=on` | 2,112 (p3-dev) | UNHEALTHY: dropped 5.4% | TP 470 / FP 231; used |
| P3 | dev | B3 if=on prompt rev | 1 | `e8688634c909` | 0c580f30 | `SKILLSPECTOR_EXA_INSTRUCTION_FLOW=on` | 2,112 (p3-dev) | OK (4.5%) | TP 489 / FP 244 |
| P3 | dev | B3 if=on prompt rev | 2 | `09b9a0110cf8` | 0c580f30 | `SKILLSPECTOR_EXA_INSTRUCTION_FLOW=on` | 2,112 (p3-dev) | UNHEALTHY: dropped 5.8% | TP 480 / FP 230; hung at 2,111/2,112 from 15:07 (watchdog bug, see P3-R17), killed 17:10 and resumed with `--run-id` for the last unit |

## P0

- **Verdict:** tooling complete (no classifier change, so there is no accept or reject).
- **`baseline-v2` = `e16e394f65c3`.** Every later plan uses it as the `replay` source and the cumulative base
  (`export BV2=e16e394f65c3`).
- **Evaluation sets:**
  - `results/evalsets/core-dev.txt`: 1,364 units (412 annotated, 352 FP, 600 TN), selected from `113b02ab497b`'s
    outcomes with seed 29.
  - `results/evalsets/splits.tsv`: 1,364 dev and 11,354 holdout.
- **Drift against the original:**
  - recall +0.003, precision +0.003;
  - 492 fixed against 449 regressed, which is noise;
  - details in `results/recall-p0-report.md`.
- **Tags:** 7.9% of SSD HIGH/CRITICAL findings in `baseline-v2` are `llm-unconfirmed`.
- **Handoffs to P1:**
  - `replay`'s `doc_medium_cap` and gate already implement P1's pre-registered cap semantics: sort by
    `(rule_id, file, start_line)`, drop before scoring, unknown file counts as executable, and a gate hit gives
    `max(score, 51)`.
  - P1's parity test should pass without changing `replay`.
  - The original run fails `health`; do not cite it as a healthy comparator.

## P1

### Offline (Task 1)

Replay over `baseline-v2` (`e16e394f65c3`); detail in `results/recall-p1-offline.md`. Δ = synthetic − BV2.

**Gate** (keep `ΔTP ≥ 8·ΔFP` and `ΔTP ≥ 32`; pick the higher `ΔTP − 8·ΔFP`):

| mode | ΔTP | ΔFP | 8·ΔFP | ΔTP ≥ 8·ΔFP | ΔTP ≥ 32 | ΔTP − 8·ΔFP |
|---|---|---|---|---|---|---|
| any | 210 | 24 | 192 | yes (210 ≥ 192) | yes | 18 |
| confirmed | 185 | 18 | 144 | yes (185 ≥ 144) | yes | 41 |

Both qualify; confirmed has the higher score (41 > 18).

**Cap** (keep `−ΔFP ≥ 10`, `−ΔTP ≤ −ΔFP/2`, SkillHarm attributed recall not lower than BV2's 0.210):

| N | ΔTP | ΔFP | −ΔFP ≥ 10 | −ΔTP ≤ −ΔFP/2 | attributed recall |
|---|---|---|---|---|---|
| 2 | -3 | -1 | no (1) | n/a | 0.210 (equal) |
| 3 | -1 | 0 | no (0) | n/a | 0.210 (equal) |
| 5 | 0 | 0 | no (0) | n/a | 0.210 (equal) |

No N removes 10 FPs, so none qualifies.

**Result: `GATE=confirmed`, `CAP=none`.**

- Gate gain split: STB +35 TP (recall 0.900 to 0.910) and non-STB +150 TP (0.437 to 0.494); added FPs 4 STB, 14 non-STB.
- `any` takes 25 of its 210 added TPs (6 of 24 added FPs) from `llm-unconfirmed`-only units; none for `confirmed`.

### Dev arms (Task 4)

Gate `confirmed` on `p1-dev.txt` (a copy of `core-dev.txt`: 1,364 units), same tree `a7497284`, same day. The cap was
not run, because `CAP=none` offline.

| arm | replicates | TP | FP | recall | precision | SkillHarm attributed recall |
|---|---|---|---|---|---|---|
| control (`ce0668313941`, `ad146b917438`) | 2 | 154.0 | 199.0 | 0.374 | 0.436 | 0.233 |
| gate=confirmed (`46bf363f7145`, `4952d46c49a0`) | 2 | 185.5 | 212.5 | 0.450 | 0.466 | 0.211 |

- **Noise floors:** N_TP = 3, N_FP = 8. **Deltas:** ΔTP = +31.5, ΔFP = +13.5.
- **Rule:** ΔTP ≥ 6 holds. ΔFP ≤ max(8, 3.94) = 8 fails. Both treatment runs are healthy.
- **`uv run arms`: REJECT** (FP cost exceeds 8:1).
- **Unhealthy control:** control 1 failed `health`, with 5.6% dropped calls. Under rule P1-R7, a replacement
  replicate (`2271319bfae5`) was run. It was also unhealthy (6.1%), so the original controls stand.
- **Rule P1-R7** (kept in the SDD progress log, not in this ledger; copied here): "An arm replicate that fails health
  is replaced once by a fresh replicate in the same arm, same tree, same day; if the replacement is also unhealthy, the
  original replicates stand. (Written after the first arms verdict was seen, before the replacement ran.)"
- **Offline prediction for the same 1,364 units:** replay `b1933d090aa7` against BV2 predicted +26 TP / +4 FP. Live
  matched it on TP (+31.5) but not on FP (+13.5). Control FP across the three replicates spans 195 to 216, which is
  larger than the effect being judged.

### Decision (Task 5)

- **P1: REJECTED.** No candidate was PROMISING, so no final full runs were made: the plan pre-registers its
  candidates, non-PROMISING changes are dropped, and full runs are final acceptance for PROMISING candidates (P1-R8).
- **What ships:** the gate and cap are committed (`a7497284`) with their defaults off: `SKILLSPECTOR_EXA_SEMANTIC_GATE`
  unset means off, and `SKILLSPECTOR_EXA_DOC_MEDIUM_CAP` unset means off.
- **REJECT holds only for the first control pair** (r1 `ce0668313941` + r2 `ad146b917438`). With r2+r3 (N_FP 13,
  ΔFP +3), r1+r3 (N_FP 21, ΔFP ≈ +7), or all three controls (mean FP ≈ 204.7, ΔFP ≈ +7.8 ≤ 8), the verdict would be
  PROMISING. The unhealthy control r1 (5.6% dropped) likely biases control FP low (dropped LLM batches drop LLM
  findings), so the recorded REJECT is probably pessimistic. The pre-registered outcome stands (ruling P1-R9:
  re-pairing after seeing the replacement would be post-hoc selection). A human can overrule with the spec's full-run
  acceptance test (one full control + one full `gate=confirmed` run, same day).
- **Evidence:** the dev arms above; offline in `results/recall-p1-offline.md`; overview in `results/recall-p1-report.md`.
- **Caveat for the program:**
  - Offline, the gate's holdout split is +159 TP / +14 FP (11:1, recall +0.027, precision −0.002). That would pass the
    8:1 rule.
  - The dev set is FP-heavy: 412 malicious units against 952 benign, of which 352 are known FPs. That makes the 8:1
    dev rule much harsher than the full-set rule.
  - Later plans share this dev set.

### Handoffs to P2+

- The gate/cap code is in `src/skillspector/exaforce/_score_patches.py`, flags default off.
  `SKILLSPECTOR_EXA_GATE_RULES` defaults to `SSD-1,SSD-2,SSD-3,SSD-4,P2`; P2-P5 may extend it.
- Replay vs classifier known difference: replay gates/caps the stored pre-dedup `issues`, while the classifier scores
  `deduplicate(active_findings)`. Bounded on BV2: at most 1 unit at risk in `confirmed`, at most 3 in `any`.
- The dev set is FP-heavy (412 malicious / 952 benign), so the 8:1 dev rule is harsher than the full-set ratio. Control
  FP spread across same-day replicates was 21 (195–216), and dev LLM drop rates sat at 4.8–6.1%, right at the 5%
  health threshold.
- Suggestion (spec unchanged): pre-register a rule for unhealthy control replicates in the spec.

## P2

### Status: INCOMPLETE (no verdict)

- Code (Tasks 1-3) is committed with both flags default off: `SKILLSPECTOR_EXA_DOC_TEXT`, `SKILLSPECTOR_EXA_HIDDEN_TEXT`
  (commits `ead32f4b`..`e5de1bf2`).
- Evaluation sets (from `baseline-v2`):
  - `results/evalsets/p2-focus.txt`: 900 units; all 283 malicious kept (SkillHarm 276, MSB 7), 617 benign sampled.
  - `results/evalsets/p2-dev.txt` = core-dev ∪ focus: 2,154 units (672 malicious / 1,482 benign); `splits.tsv`
    regenerated: 2,154 dev / 10,564 holdout.
  - `results/evalsets/p2-guard-md-comment.txt`: 208 benign units with `<!--` in a `.md` file (44 in p2-dev).
  - The focus malicious units are 97.5% SkillHarm (one generator), so they do not meet the ≥2-corpora evidence rule.
- Dev arms: only replicate 1 of each arm completed (rows above). Single replicates cannot be judged with the
  pre-registered rule, so there is no PROMISING/REJECT verdict. Replicate-1 deltas against control, for orientation
  only: A +37 TP / +3 FP; B +37 TP / −13 FP.
- Control replicate 2 hung (harness deadlock, see its row). The user chose to move to P3 instead of re-running; P2's
  dev arms and final acceptance remain to be done.

## P3

### Evaluation sets (Task 4)

- `results/evalsets/p3-focus.txt`: 900 units from baseline-v2 (`e16e394f65c3`): every unit in clusters C02 (423),
  C06 (149) and C11 (210), plus 118 benign multi-doc units. The plan's `--where` clause would have selected 900
  malicious units and no benign ones; the focus was instead built as cluster clause OR benign multi-doc, cap 900
  (ruling P3-R3). The exact command is in `results/evalsets/README.md`.
- `results/evalsets/p3-dev.txt` = core-dev ∪ focus: 2,112 units. Of these, 1,078 are malicious (FN 673 / TP 405 at
  baseline-v2) and 1,034 benign (FP 208 / TN 826). `splits.tsv` was regenerated: 2,650 dev / 10,068 holdout.
- Multi-doc guard: the 534 benign p3-dev units that have a non-SKILL `.md` component at baseline-v2 (FP 138 / TN 396
  there). SQL:
  ```sql
  CREATE TEMP TABLE dev AS SELECT column0 AS unit_path FROM read_csv('results/evalsets/p3-dev.txt', header=false, columns={'column0':'VARCHAR'});
  CREATE TEMP TABLE guard AS
    SELECT DISTINCT e.unit_path FROM evaluation e JOIN dev USING (unit_path)
    WHERE e.run_id='e16e394f65c3' AND NOT e.truth_malicious
      AND e.unit_path IN (SELECT unit_path FROM components WHERE run_id='e16e394f65c3'
                          AND path ILIKE '%.md' AND path NOT ILIKE '%SKILL.md');
  -- guard FP of run R:
  SELECT count(*) FROM evaluation e JOIN guard USING (unit_path) WHERE e.run_id = R AND e.predicted_malicious;
  ```

### Dev arms (Task 4)

All 18 dev runs were made on 2026-11-03 on `p3-dev.txt`. Every run except B3 used tree `d22fc89c`; B3 used
`0c580f30`, which changes only the IF1 prompt. Candidates:
- A1: `SKILL_CONTEXT=ssd`;
- A2: `SKILL_CONTEXT=semantic`;
- B1: `INSTRUCTION_FLOW=on`;
- B3: B1 with one prompt revision.

B2 was not run, because P1's gate was rejected (P3-R5).

**Unhealthy replicates (P3-R12, the same rule as P2-R7).** All 8 first replicates failed `health`. Each was replaced
once, on the same tree and the same day. Only A2 r2b was healthy, so it replaces A2 r2. Every other arm uses all its
replicates: means, with noise floors from the range.

The drops come from the endpoint: across 16 runs, 459 units dropped calls in only 1 run and 1 unit dropped in all 16.
They were not caused by any flag. Control r1 also had 184 ERROR outcomes, and it alone sets N_TP.

| arm | runs | TP | FP | recall | precision | C02 recall (423) | cross_file recall (148) | SkillHarm attributed | median s | p95 s | LLM calls/scan | guard FP |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| control | 4 | 371.8 | 207.5 | 0.352 | 0.641 | 0.163 | 0.439 | 0.166 | 26.9 | 205.1 | 4.39 | 132.75 |
| A1 ctx=ssd | 4 | 395.0 | 216.8 | 0.371 | 0.645 | 0.175 | 0.488 | 0.176 | 25.7 (0.96×) | 161.2 | 4.40 | 145.5 (+12.8) |
| A2 ctx=semantic | 3 | 389.0 | 229.7 | 0.364 | 0.629 | 0.155 | 0.464 | 0.161 | 26.0 (0.97×) | 156.0 | 4.40 | 155.3 (+22.6) |
| B1 if=on | 4 | 471.2 | 237.8 | 0.437 | 0.665 | 0.262 | 0.551 | 0.271 | 27.8 (1.03×) | 149.2 | 5.09 | 154.75 (+22.0) |
| B3 if=on, rev | 2 | 484.5 | 237.0 | 0.449 | 0.672 | 0.287 | 0.561 | 0.287 | 31.2 (1.16×) | 137.0 | 5.09 | 164.0 (+31.25) |

Columns are means over the runs; recall and precision here are per-run means over all scans (an ERROR scan counts as
not predicted), so they differ in the third decimal from the pooled `arms` values the report uses. Scan times are pooled over all scans of the arm (`classifications.run_time`). The
recall slices use `_boundary_features.jsonl` (`boundary_cluster`) and `_boundary_labels.jsonl` (`cross_file`).

`uv run arms` against the four controls (N_TP = 98, N_FP = 30):

| arm | ΔTP | ΔFP | rule | time guard | guard FP ≤ N_FP | verdict |
|---|---|---|---|---|---|---|
| A1 | +23.2 | +9.2 | ΔTP < 196 | pass (≤1.25×) | pass | **REJECT** |
| A2 | +17.2 | +22.2 | ΔTP < 196 | pass (≤1.25×) | pass | **REJECT** |
| B1 | +99.5 | +30.2 | ΔTP < 196; ΔFP > max(30, 12.4) | pass (≤1.40×) | pass | **REJECT** |
| B3 | +112.8 | +29.5 | ΔTP < 196; r2 unhealthy | pass (≤1.40×) | **fail** (+31.25) | **REJECT** |

- **Sensitivity check (not the verdict).** Without control r1 (the 184-ERROR run), N_TP = 15 and N_FP = 19 (controls r2, r1b, r2b).
  - B1 is then +77 TP / +25 FP, and B3 +90 / +24. Both fail ΔFP ≤ max(19, ΔTP/8), at about 3–4 extra TPs per extra
    FP against the required 8.
  - A1 and A2 are still about +20 TP or less.
  - The verdicts do not depend on the outlier.
- **No PROMISING (a) or (b) arm**, so no combined arm was run.
- **B3 error classes**, written before the edit, from 10 IF1-caused FPs and 10 FNs (3 opened):
  - FP-a: a code or config weakness was reported instead of an instructed action (5/10).
  - FP-b: a bundled script's capability was flagged when nothing tells the agent to run it (3/10).
  - FP-c: an optional, purpose-fitting step was flagged (2/10).
  - FN-a: a referenced setup/baseline step that suppresses or rewrites the skill's own results was read as
    configuration.
  - FN-b: a remote script piped to a shell was read as a routine install.
  - FN-c: instructions inside a PDF (needs P2's DOC_TEXT; not addressed).
  - Result: B3 added TP (+13 over B1) but did not reduce FP. FP-a/b/c were not the dominant FP source.
- **Structural limit of B1/B3.** One HIGH `EXA-IF1` at confidence c adds 25·c risk points, and the threshold is 50.
  458 malicious units are FN in all four B1 replicates; 97 of them carry a HIGH IF1 finding in at least one replicate. Severity is fixed at HIGH
  or MEDIUM by the plan, so no prompt revision can convert these.

### Decision (Task 5)

- **P3: REJECTED.** No dev arm was PROMISING, so no combined arm and no final full runs were made (as P1-R8). Flags
  ship with their defaults off: `SKILLSPECTOR_EXA_SKILL_CONTEXT` (`ssd` | `semantic`) and
  `SKILLSPECTOR_EXA_INSTRUCTION_FLOW` (`on`). The IF1 prompt in the tree is the measured B1 text, restored after the final review (P3-R18).
- **Overview:** `results/recall-p3-report.md`.
- **Verdict robustness:** the verdict holds with or without the 184-ERROR control r1. B1 and B3 fail the 8:1 FP rule
  even with the tight floors that result without it.
- **A human can overrule:** B1 raises dev precision (pooled `arms` values 0.642 → 0.665) while failing 8:1. The spec's full-run acceptance
  test is the arbiter: one full control plus one full `INSTRUCTION_FLOW=on` run, same day, healthy.

### Handoffs to P4+

- **Scoring cap on IF1.** One HIGH IF1 contributes at most 25 risk points, and the threshold is 50. Of the 458 malicious units
  that are FN in all four B1 replicates, 97 carry a HIGH IF1. A scoring path (gate inclusion, B2-style)
  is where IF1's recall lies, not the prompt.
- **IF1 FP sources:** the B3 classes FP-a/b/c did not move FP. The dominant FP source is not yet characterised.
- **Endpoint health:** dev LLM drop rates sat at 5.0–5.8% on every replacement run (P1: 4.8–6.1%). The 5% threshold
  now rejects most runs on a normal day, so the spec's health threshold or worker count deserves a decision.
- **Watchdog:** the scratchpad `run-arm.sh` watchdog must watch log growth, not a DB count (the DB is locked during a
  run; P3-R17). The harness hang at the last unit (P2 control r2, P3 B3 r2) is still undiagnosed.
- **IF1 prompt vocabulary:** in this corpus, 222 malicious vs 8 benign units have a component path containing
  "preflight" or "baseline" (one generator's file naming), so prompt wording built from those words would key on the
  generator, not the error class. B3 used them; the tree's prompt was reverted to B1 (P3-R18).
- **Context header placement:** the header (frontmatter name/description and up to 8 SKILL.md lines, all
  attacker-controlled) is prepended above the analyzer instructions, unfenced. If the flag is revived, move it below
  the instructions or fence it.
