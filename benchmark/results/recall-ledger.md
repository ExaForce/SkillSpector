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
| P4 | e2e | B necessity=on | 1 | `e03bd4291c97` | 80daf70e + uncommitted Task 2 | `SKILLSPECTOR_EXA_NECESSITY=on` | 1 | UNHEALTHY: no SSD/SDI/SQP issue on the 1-unit scan (LLM 5/5) | `calendar__skillinject-contextual23-t0`: FN, risk 22, EXA-NE1 HIGH 0.9 (scoring cap) |
| P4 | preflight | all flags | 1 | `73deb99e856a` | 6d093d72 | `SKILLSPECTOR_EXA_SSD5=on` `SKILLSPECTOR_EXA_NECESSITY=on` | 1 | OK | `pptx__skillharm-fpp-a4db25e26d`: TP, risk 92, LLM 6/6, 1 EXA-NE1 HIGH 0.8 |
| P4 | dev | control | 1 | `54ce3a6bbe59` | 6d093d72 | none | 2,393 (p4-dev) | UNHEALTHY: dropped 7.8% | TP 490 / FP 217; used (P4-R10); 1 ERROR |
| P4 | dev | A ssd5=on | 1 | `daed644651be` | 6d093d72 | `SKILLSPECTOR_EXA_SSD5=on` | 2,393 (p4-dev) | UNHEALTHY: dropped 6.6% | TP 533 / FP 241; used (P4-R10) |
| P4 | dev | control | 2 | `01d373aebd37` | 6d093d72 | none | 2,393 (p4-dev) | UNHEALTHY: dropped 9.4% | TP 513 / FP 215; used (P4-R10) |
| P4 | dev | A ssd5=on | 2 | `a753a1ba2c6c` | 6d093d72 | `SKILLSPECTOR_EXA_SSD5=on` | 2,393 (p4-dev) | UNHEALTHY: dropped 7.9% | TP 528 / FP 248; used (P4-R10) |
| P4 | dev | control | 1b | `92149d37b0d8` | 6d093d72 | none | 2,393 (p4-dev) | UNHEALTHY: dropped 8.9% | TP 508 / FP 232; replacement, also unhealthy; used (P4-R10) |
| P4 | dev | A ssd5=on | 1b | `7c4a288e3a9d` | 8fbdfa84 | `SKILLSPECTOR_EXA_SSD5=on` | 2,393 (p4-dev) | UNHEALTHY: dropped 9.3% | TP 535 / FP 244; replacement, also unhealthy; used (P4-R10) |
| P4 | dev | control | 2b | `354e5a84e14a` | dd69e346 | none | 2,393 (p4-dev) | UNHEALTHY: dropped 9.4% | TP 507 / FP 242; replacement, also unhealthy; used (P4-R10) |
| P4 | dev | A ssd5=on | 2b | `26b4d0c04b6f` | 065bd3ae | `SKILLSPECTOR_EXA_SSD5=on` | 2,393 (p4-dev) | UNHEALTHY: dropped 8.9% | TP 544 / FP 255; replacement, also unhealthy; used (P4-R10) |
| P4 | screen | B necessity=on | 1 (union) | 16 batch runs `f85f1be60ffd`..`075504935411` | 5580e7a9 / 80891a8b / 71c440f5 | `SKILLSPECTOR_EXA_NECESSITY=on` | 2,393 (p4-dev, 16×≤150) | UNHEALTHY: pooled dropped 7.7% (184/2393); 1 of 16 batches healthy | TP 572 / FP 264; screen `p4-B` (v1 rule) PASSED; members in `results/screens/p4-B/manifest.json` |
| P4 | dev | B necessity=on | 2 | `e00694743a1e` | ff6a41e2 | `SKILLSPECTOR_EXA_NECESSITY=on` | 2,393 (p4-dev) | UNHEALTHY: dropped 8.1% | TP 595 / FP 285 |
| P4 | screen | B-rev necessity=on | 1 (union) | 16 batch runs `f5ee327c52b1`..`417e2f5a5444` | 75f9f822 | `SKILLSPECTOR_EXA_NECESSITY=on` | 2,393 (p4-dev, 16×≤150) | UNHEALTHY: pooled dropped 7.7% (184/2393); 2 of 16 batches healthy | TP 554 / FP 248; screen `p4-Brev2` (v2 rule) PASSED; members in `results/screens/p4-Brev2/manifest.json` |
| P4 | dev | B-rev necessity=on | 2 | `42a3e8b7a72c` | 75f9f822 | `SKILLSPECTOR_EXA_NECESSITY=on` | 2,393 (p4-dev) | UNHEALTHY: dropped 7.6% | TP 579 / FP 252 |
| P4 | dev | B-rev necessity=on | 1b | `2cf05e51e07e` | 75f9f822 | `SKILLSPECTOR_EXA_NECESSITY=on` | 2,393 (p4-dev) | UNHEALTHY: dropped 9.4% | TP 572 / FP 257; replacement for the screen union, also unhealthy; used (P4-R10, P4-R17) |
| P4 | dev | B-rev necessity=on | 2b | `1fe745793100` | 75f9f822 | `SKILLSPECTOR_EXA_NECESSITY=on` | 2,393 (p4-dev) | UNHEALTHY: dropped 7.9% | TP 567 / FP 271; replacement for r2, also unhealthy; used (P4-R10, P4-R17) |
| P5 | preflight | L lure=on | 1 | `f5ce06e02dfd` | 7d196c53 | `SKILLSPECTOR_EXA_LURE_RULES=on` | 1 | OK | `pptx__skillharm-fpp-a4db25e26d`: TP, LLM 5/5 |
| P5 | e2e | L lure=on | 1 | `a6f536863de0` | 7d196c53 | `SKILLSPECTOR_EXA_LURE_RULES=on` | 1 | OK (1/5 calls dropped) | `Currency__stb-case_01883`: 2× `EXA-LU1` HIGH in the report; TP |
| P5 | dev | control | 1 | `85b4ac355198` | 7d196c53 | none | 2,296 (p5-dev) | OK: dropped 5.6% (129/2296) | TP 660 / FP 214; guard FP 76 |
| P5 | dev | control | 2 | `2b226dac1615` | 7d196c53 | none | 2,296 (p5-dev) | OK: dropped 6.5% (149/2296) | TP 664 / FP 214; guard FP 74 |
| P5 | screen | L lure=on | 1 (union) | 16 batch runs `9603248b33bf`..`b2f41de8c746` | 7d196c53 | `SKILLSPECTOR_EXA_LURE_RULES=on` | 2,296 (p5-dev, 16×≤144) | OK: pooled dropped 5.6% (129/2296); 15 of 16 batches healthy (b07 `48eea52b374b` 10.4%) | TP 701 / FP 221; guard FP 79; screen `p5-L` (v2 rule) PASSED; members in `results/screens/p5-L/manifest.json` |
| P5 | dev | L lure=on | 2 | `3ac394158e63` | 7d196c53 | `SKILLSPECTOR_EXA_LURE_RULES=on` | 2,296 (p5-dev) | OK: dropped 5.5% (127/2296) | TP 715 / FP 215; guard FP 80; 1 ERROR |
| P5 | preflight | L lure=on | 1 | `a98f3794c22f` | 8ab36a84 | `SKILLSPECTOR_EXA_LURE_RULES=on` | 1 | OK | final pair preflight: TP |
| P5 | final | control | 1 | `0e0f9e105cf8` | 8ab36a84 | none | 12,718 | OK: dropped 8.1% (1031/12718), 0 errors | SSO expired at 9,033, resumed with `--run-id`; TP 4522 / FP 373; guard FP 86 |
| P5 | final | L lure=on | 1 | `93c1faec5bec` | 8ab36a84 | `SKILLSPECTOR_EXA_LURE_RULES=on` | 12,718 | OK: dropped 8.4% (1064/12718), 0 errors | TP 4622 / FP 362; guard FP 79; on `M` (301): +41 TP / 0 FP -> ACCEPTED |
| P6 | preflight | control | 1 | `7a2881fff622` | c0e4ccaa | none (lure rules on by default) | 1 | OK | `Currency__stb-case_01883`: 2 `EXA-LU*` findings with no flag set |
| P6 | full | control | 1 | `bfa51d835e8b` | c0e4ccaa | none (current defaults) | 12,718 | OK: dropped 8.1% (1032/12718), 0 errors | TP 4641 / FP 347; replay source for the sweep |
| P6 | replay | T = 31..61 | - | 16 synthetic runs (`2989de038a5c` .. `f450819a4738`; T = 49 `5f4044b8e40a`) | - | `--policy '{"threshold": T}'` | 12,718 | n/a (replay) | table in `results/recall-p6-offline.md` |

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

- **Rolled back (2026-11-04):** at the user's request all P3 code and tests were removed from the branch (`src/` and
  `tests/` restored to `25e5baf3`). The flags above no longer exist; this record, the evalsets and the runs in
  `recall.duckdb` remain. The code is recoverable from commits `434e2290`..`f4f65f36`.

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

## P4

### Evaluation sets (Task 3)

- `results/evalsets/p4-focus.txt` (1,313 units) and `p4-dev.txt` (core-dev ∪ focus, 2,393 units: 1,122 malicious, FN 636 /
  TP 486 at baseline-v2; 1,271 benign, FP 224 / TN 1,047). Commands are in `results/evalsets/README.md`. The focus clause ran
  without its cap (P4-R5): 883 malicious + 136 benign. 300 setup-language benign skills were then added (grep, seed 29).
  `splits.tsv` was regenerated: 3,315 dev / 9,403 holdout.
- Guard sets (benign p4-dev units; rise allowed: `max(N_FP, 0.5% of guard units)`):
  - setup language: `results/evalsets/p4-guard-setup.txt`, 663 units, every benign dev unit whose SKILL.md matches the grep
    (P4-R7), 122 FP at baseline-v2;
  - Skill-Inject clean: the 49 benign `%skillinject-clean%` units (the plan's "41" is stale, P4-R6), 5 FP;
  - 21+ files: the 90 benign units with more than 20 components at baseline-v2, 41 FP.

### Dev arms (Task 3)

All runs were made on 2026-11-04 on `p4-dev.txt`. Candidates (3 of the 5-candidate budget; the plan lists no other runnable candidate):
- A: `SKILLSPECTOR_EXA_SSD5=on` (an SSD-5 "unnecessary instruction" category in the SSD prompt);
- B: `SKILLSPECTOR_EXA_NECESSITY=on` (a per-skill necessity analyzer on SKILL.md, `EXA-NE1`);
- B-rev: B with the plan's one prompt revision (`6825fa30`, narrowed in `75f9f822` before it was measured, P4-R15).

A+gate and B+gate were not run, because P1's gate was rejected (P4-R8). A ran ×2 before the sequential screen existed.
B and B-rev were screened first (`uv run screen`, reusing the four controls), then got one more full run each.

**Run provenance.** Other sessions committed harness-only changes (the `screen` and `arms` union tooling, docs) while
runs were in progress, so runs record different shas. `src/skillspector/` and the scan code are byte-identical across
`6d093d72`..`71c440f5`; those runs are treated as one tree (P4-R13). B-rev ran on `75f9f822` (the revised prompt).

**Unhealthy replicates (P4-R10, the same rule as P3-R12).** Every full dev run dropped LLM calls in 6.6–9.4% of scans;
the screen batches dropped 4.0–13.4%, and 3 of 32 batches were healthy (≤ 5%). Controls and A were each replaced once, and the
replacements were also unhealthy, so all four replicates are used. B was not replaced (it fails on FP cost regardless).
B-rev: both replicates (the screen union and r2) were unhealthy; with two replicates B-rev was +62.0 / +23.5, which passes the numeric rule, so each was replaced once (P4-R17). Both replacements were also unhealthy (9.4%, 7.9%), so all four replicates are used.

| arm | replicates | TP | FP | recall | precision | ΔTP | ΔFP | Content Manipulation TP | domain_contextual TP (81) | guard FP setup (663) | guard FP si_clean (49) | guard FP files21 (90) | median s | p95 s | LLM calls/scan |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| control | 4 | 504.5 | 226.5 | 0.450 | 0.690 | | | 63.0 | 18.0 | 125.8 | 7.2 | 43.8 | 14.7 | 123.4 | 4.39 |
| A ssd5=on | 4 | 535.0 | 247.0 | 0.477 | 0.684 | +30.5 | +20.5 | 71.5 (+8.5) | 24.8 (+6.8) | 138.2 (+12.5) | 7.0 (-0.2) | 43.5 (-0.2) | 14.2 | 117.8 | 4.39 |
| B necessity=on | 2 | 583.5 | 274.5 | 0.520 | 0.680 | +79.0 | +48.0 | 80.5 (+17.5) | 24.5 (+6.5) | 155.5 (**+29.8**) | 8.0 (+0.8) | 45.5 (+1.8) | 14.8 | 115.0 | 5.48 |
| B-rev necessity=on | 4 | 568.0 | 257.0 | 0.506 | 0.688 | +63.5 | +30.5 | 75.0 (+12.0) | 24.0 (+6.0) | 144.2 (+18.5) | 7.2 (+0.0) | 45.5 (+1.8) | 14.9 | 118.9 | 5.47 |

Recall and precision are computed from the arm's mean TP/FP (1,122 malicious, 1,271 benign); they match `arms`. Times are
pooled `classifications.run_time` over the arm's full runs only (B: r2; B-rev: r2, r1b, r2b). Screen batch runs are left
out: their 150-unit batches have a median near 25 s, which is a batch-size effect, not a flag effect. `domain_contextual` = annotated `label_validity='CORRECT'` units with
`harm_explicitness='domain_contextual'` (81 in p4-dev).

**SSD-5 scope (Review Focus 5):** arm A emitted 441.5 `SSD-5` findings per run, 112.8 of them (25.5%) on files that are not
markdown or text. The prompt's "natural-language instructions only" scope leaks a quarter of the time.

**SSD-5 and the gate:** `SSD-5` is not in `DEFAULT_GATE_RULES`. It keeps the semantic severity floor (it matches the
`SSD-` prefix in `LLM_RULE_PREFIXES`) but triggers the block gate only if added to `SKILLSPECTOR_EXA_GATE_RULES`.

**STB / non-STB recall** (spec anti-overfitting rule; per-replicate means; 178 SkillTrustBench and 944 other malicious
dev units): control 0.841 / 0.376; A 0.841 / 0.408; B 0.871 / 0.454; B-rev 0.860 / 0.440. The gains are mostly non-STB.

`uv run arms` against the four controls (N_TP = 23, N_FP = 27; bar ΔTP ≥ 46, ΔFP ≤ max(27, ΔTP/8)):

| arm | ΔTP | ΔFP | rule | guards | health | verdict |
|---|---|---|---|---|---|---|
| A | +30.5 | +20.5 | ΔTP < 46 | pass | unhealthy | **REJECT** |
| B | +79.0 | +48.0 | ΔFP > max(27, 9.9) | **fail** (setup +29.8 > 27) | unhealthy | **REJECT** |
| B-rev | +63.5 | +30.5 | ΔFP > max(27, 7.9) | pass | unhealthy | **REJECT** |

B-rev sits on the boundary. Its first two replicates gave +62.0 / +23.5 (ΔFP 3.5 under the bound), the four give +63.5 / +30.5 (3.5 over). The bound is max(N_FP, ΔTP/8) = max(27, 7.9); the N_FP
noise term binds, so this is a noise-floor miss, not an 8:1 miss. Its four treatment FP totals span 248–271, about the control spread (215–242). The verdict is REJECT either way, because the spec also requires both treatment replicates to pass `health`, and none did.

**Screens.**
- `p4-B` ran under the first (v1) screen rule and PASSED. That rule did not stop B although B's full-set D was −232.8;
  the other session replaced it with the v2 rule (pre-registered in the spec on 2026-11-04) while B was screening.
- `p4-Brev` (1 partial batch, `fbf120190964`) is void: it was killed after the B-rev task review asked to narrow two exclusions
  (P4-R15).
- `p4-Brev2` ran under v2 and PASSED at 2,393 units: dTP +49.2 / dFP +21.5. Its final-look bounds were
  F_dTP+2.8·SD +69.6 (stop below 46), F_g+2.8·SD_g +51.1 (stop below 0), and F_dFP−2.8·SD −0.1 (stop above 27).
- Manifests are in `results/screens/<label>/manifest.json`.

**Error classes for the revision** (P4-R14, from 10 EXA-NE1-caused FPs and 10 annotated FNs of B, written before the edit):
- NE-FPa: risk speculation about a legitimate step (an install path, credential storage, overwrite without confirmation) (5/10);
- NE-FPb: a protective rule ("never log the key") judged unnecessary (1/10);
- NE-FPc: an output or delivery step the purpose implies (3/10);
- NE-FPd: a bug or quality issue (1/10);
- NE-FNa: the harmful action lives in a script or config SKILL.md tells the agent to run; NE1 sees only "run X" (7/10; out of
  scope for a SKILL.md-only analyzer);
- NE-FNb: hidden PDF text (1/10, P2's territory);
- NE-FNc: an explicit SKILL.md rule that leaks or slants output was missed (2/10).

Corpora: the sampled unit ids were not recorded, so the sample's own corpora are unknown. The population it was drawn
from (units that are FP with an `EXA-NE1` finding in either B replicate and not FP in any control) is 31 units: 18
benign-corpus and 13 SkillTrustBench.

The revision added "output rules count as steps" and four narrow "not findings" exclusions. Result (four replicates): B-rev keeps about 80% of B's ΔTP (+63.5 vs +79) at about 64% of B's ΔFP (+30.5 vs +48);
dev precision is flat (0.690 → 0.688).

**Scoring cap, again.** In B's screen union, 166 of the 550 FNs carry a HIGH `EXA-NE1` (25·c risk points against a
threshold of 50). The Task 2 E2E unit shows the same cap: HIGH 0.9, risk 22, FN.

### Decision (Task 3, Step 4)

- **No PROMISING arm**, so Task 4 makes no full runs and changes no default (as P1-R8 and P3). Both flags
  ship with their defaults off: `SKILLSPECTOR_EXA_SSD5` and `SKILLSPECTOR_EXA_NECESSITY` (enable with `=on`). The NE1 prompt in the
  tree is the measured B-rev text (`75f9f822`).
- **Overview:** `results/recall-p4-report.md`.
- **Rolled back (2026-11-04):** at the user's request all P4 code and tests were removed from the branch (`src/` and
  `tests/` restored to `1b950d70`). The flags above no longer exist; this record, the evalsets, the screen manifests and
  the runs in `recall.duckdb` remain. The code is recoverable from commits `80daf70e`..`75f9f822` (NE1 prompt as
  measured: `75f9f822`).
- **Why it was rejected, in one place:**
  - A (SSD-5 inside the SSD prompt) moved recall by less than the control noise (+30.5 TP vs a bar of 46), and a
    quarter of its findings landed on non-markdown files.
  - B (per-skill necessity analyzer) found real misses (+79 TP, recall 0.450 → 0.520) but paid +48 FP for them and
    broke the setup-language guard: it reads ordinary setup, output and safety rules as "unneeded".
  - B-rev (the one allowed prompt revision) cut that FP cost but lost TP with it (+63.5 / +30.5), landing 3.5 FP
    over the noise floor. The FP cut came with a TP loss; with only one revision allowed, the data cannot say whether a
    prompt that keeps both exists.
  - Underneath both: one HIGH LLM finding scores at most 25 against a threshold of 50, so 166 misses that NE1
    correctly flagged still stayed FN; and most remaining misses hide the harm in a script SKILL.md runs, which a
    SKILL.md-only analyzer cannot see.
  - No run that day passed `health` (6.6–9.4% dropped LLM calls), so no candidate could have been PROMISING anyway.
- **A human can overrule** the health clause (no run today was healthy, controls included), but B-rev also fails
  ΔFP ≤ max(N_FP, ΔTP/8) on its four replicates, and B fails both that rule and the setup guard. Neither is a near miss worth a full run
  under the pre-registered rules.

### Handoffs to P5+

- **The scoring cap is still the binding limit.** A lone HIGH LLM finding (P3's IF1, P4's NE1) scores 25·c against a
  threshold of 50. 166 of B's 550 dev FNs already carry a HIGH NE1. Recall from per-skill LLM judgements needs a scoring
  path (a gate, or a scoring change), not more prompt work.
- **NE1's FNs are mostly out of its scope.** 7 of 10 sampled FNs put the harm in a script or config that SKILL.md
  tells the agent to run. A SKILL.md-only analyzer cannot see it.
- **SSD-5 scope leak:** 25.5% of arm A's `SSD-5` findings land on non-markdown files despite the prompt's scope sentence.
- **Endpoint health:** 0 of 12 full dev runs and 3 of 32 screen batches passed `health` today (unhealthy ones dropped 5.3–13.4%). Under
  the spec's health clause no candidate could have been PROMISING on 2026-11-04. The threshold, the worker count (96), or
  a retry policy needs a decision before P5 spends endpoint time.
- **NE1 purpose header is unfenced (security, must fix before any revival).** `_necessity.py` `build_prompt` puts the
  skill's own `name: description` (or first heading and paragraph, up to 600 characters, attacker-controlled) above the
  analyzer instructions, outside the file fence. This is the placement P3's handoff warned about. A malicious skill can
  claim every step is required, and Q1 = yes suppresses every finding. It was left as measured because the flag is
  rejected and default-off (P4-R18). Fence it (and re-measure) before turning the flag on anywhere. The B-rev
  "where something is installed or stored" exclusion should be reviewed at the same time.
- **Deferred code minors (latent; flags off):** `_patchlib.intercept_method` returns early when any interceptor is already
  installed, so a second, different interceptor on the same method would be dropped silently; `skill_purpose` passes
  non-string frontmatter values through `str()`; the NE1 chunk budget ignores the ≤600-character purpose header.
- **Screen v2 in use:** B-rev's screen passed and its full-run verdict was REJECT by 3.5 FP, so the screen behaved as a
  futility screen should (it does not promise PROMISING).

## P5

Plan: `docs/superpowers/plans/2026-10-29-recall-p5-lure-rules.md` (amended in `067cdd0c`: replay precision bar, and a
10% health threshold from P5 onward, both user decisions on 2026-11-04 made before any dependent run).

### Offline (Task 1)

`uv run rulelab` over baseline-v2 `e16e394f65c3` (`results/recall-p5-offline.md`, notes in
`results/recall-p5-offline-notes.md`). Under the re-registered per-rule bar (benign matched ≤ 12, and ≥ 15 baseline-v2
FNs that one added finding at severity points × 0.8 would lift past risk 50):
- `EXA-LU1` (pipe-to-shell from an IP literal or a public paste service): IMPLEMENT. Replay FN→TP 16 of 25 matched, TN→FP 0.
- `EXA-LU4` (base64 decode piped into an interpreter or eval): IMPLEMENT. Replay FN→TP 42 of 72 matched, TN→FP 1
  (`skill-security-audit`).
- `EXA-LU2` (archive password plus run instruction): DROP (replay FN→TP 4). `EXA-LU3` (skip-verification install): DROP (0).

The regexes have one version (v0), with no revisions. Code: `7d196c53`, flag `SKILLSPECTOR_EXA_LURE_RULES=on`, LU1 and LU4 only,
HIGH, confidence 0.9.

### Evaluation sets (Task 3)

- `results/evalsets/p5-focus.txt` (1,034 units, no cap, P5-R14) and `p5-dev.txt` (core-dev ∪ focus, 2,296 units:
  1,342 malicious, TP 646 / FN 696 at baseline-v2; 954 benign, FP 203 / TN 751). `splits.tsv` regenerated: 4,241 dev /
  8,477 holdout. Commands are in `results/evalsets/README.md`.
- Guard: `results/evalsets/p5-guard-fetch.txt`, the 246 benign p5-dev units with a `curl|wget|iwr|Invoke-WebRequest`
  line (P5-R8), FP 73 at baseline-v2. Allowed rise: N_FP.

### Dev arms (Task 3)

All runs were made on 2026-11-04 on `p5-dev.txt` at `7d196c53`. One candidate: L (`SKILLSPECTOR_EXA_LURE_RULES=on`).
L+gate was not run, because P1's gate was rejected. L was screened first (`uv run screen`, v2 rule, reusing both
controls); the screen PASSED at batch 16 with every stop column `no`. L then got one more full run.

All four replicates pass `health` at 10%. The screen union is judged pooled (5.6%), as in P4. One of its 16 batches,
b07, dropped 10.4% on its own (P5-R15).

`uv run arms results/recall.duckdb --control 85b4ac355198,2b226dac1615 --treatment <p5-L union>,3ac394158e63`:

| arm | replicates | TP | FP | recall | precision |
|---|---|---|---|---|---|
| control | 2 | 662.0 | 214.0 | 0.4933 | 0.7557 |
| L | 2 | 708.0 | 218.0 | 0.5278 | 0.7646 |

N_TP = 4, N_FP = 2. ΔTP +46.0 ≥ 8 and ΔFP +4.0 ≤ max(2, 5.75), so the verdict is **PROMISING**.

Step 3 breakdown (means over replicates; ΔTP by `_boundary_labels.jsonl` validity tier, kept separate):

| measure | control | L | Δ |
|---|---|---|---|
| TP, `working` tier (CORRECT) | 92.5 | 100.0 | +7.5 |
| TP, `intent` tier (BROKEN, UNVERIFIABLE) | 20.5 | 23.5 | +3.0 |
| TP, `not_malicious` tier (WEAK, MISLABELED) | 46.0 | 42.0 | −4.0 |
| TP, unannotated (most units) | 503.0 | 542.5 | +39.5 |
| guard FP (`p5-guard-fetch`, 246) | 75.0 | 79.5 | **+4.5 > N_FP 2: FAIL as written** |
| `EXA-LU1` findings / units | 0 | 213 / 158 | |
| `EXA-LU4` findings / units | 0 | 164 / 139 | |

**Attribution.** A static finding can turn a unit positive only through that unit's own risk score. So an FP caused by
L must carry an `EXA-LU*` finding, and so must a TP that L gained.
- **Benign units with an LU finding:** 2 in total, both `EXA-LU4` and both in the guard:
  - `skill-security-audit`: FP in the union, TN in r2. It is also FP in control r2. This is the one benign match the
    offline replay predicted.
  - `openclaw-skill-vetter`: TN in both replicates.

  L's attributable FP is therefore at most 0.5 per replicate.
- **The guard rise is LLM noise.** 46 of the 246 guard units change outcome between the two identical controls, and 80
  change across the four replicates. The controls' total FP matched (214 and 214) by chance, so N_FP sits at its floor
  of 2, while 257 benign dev units vary across replicates.
- **Gains with an LU finding.** *Corrected after the final review (I2).* The first count required FN in both controls
  and TP in L: 25 units in the union and 32 in r2, which I reported as "about 28 of +46". That undercounts, because it
  drops units that were FN in only one control.
  - **Matched units:** on the 305 offline-matched dev units, L moved +48.5 TP / −0.5 FP against the control mean.
  - **All other dev units:** −2.5 TP / +4.5 FP. The whole guard rise is in units the rules cannot touch.
  - **Expected full-set gain:** about +0.76 recall points, not +0.45.
- **Offline prediction against live.** *Corrected (I3).* The "2× overestimate" came from looking only at matched FNs
  that stayed FN, which is selection bias. Over all 58 matched units that were FN in both controls, the median risk gain
  was +23.0 (union) and +33.2 (r2).

### Decision (Task 3, Step 3)

The `arms` verdict is PROMISING. Under Step 3 ("choose the best PROMISING arm whose guard passes"), however, the guard
as written fails at +4.5 against N_FP = 2, so no arm qualifies. Per-unit attribution shows the failure measures LLM
drift, not the rule: 46+ guard units flip between runs, while the rule touches 2 guard units and at most 0.5 FP.
Overriding a pre-registered guard after seeing results is the user's call, as with bar 3 (P5-R16).
- **First user decision:** "reject as written". It rested partly on my +0.45-point estimate, which was wrong (see
  above).
- **After the correction:** the user re-registered acceptance on the rule-affected units `M` in `21e37201`, recorded in
  the plan before any Task 4 run. This is a post-hoc change.
  - **Recall:** ΔTP over `M`'s malicious units ÷ 6,403 ≥ +0.005.
  - **Precision and guard:** ΔFP over `M`'s benign units ≤ N_FP = 2.
  - **Holdout:** `M`'s holdout units must have ΔTP ≥ 0. If `M` has none, the criterion is information only.
  - **Health:** both runs healthy.

### Final-review fix wave

The final review found that the LU1 regex backtracks cubically on crafted long lines (I1). Three fix commits followed:
- `f8ed9439`: bounded gaps.
- `3433ba97`: windowed long lines instead of skipping them, because skipping was an evasion.
- `8ab36a84`: exact positions, every quantifier bounded, whitespace runs collapsed.

A scoped re-check came back clean, and the offline match set is unchanged (305). Residual minors are listed in the
report's Handoffs.

### Final acceptance (Task 4)

Full control `0e0f9e105cf8` and full L `93c1faec5bec`, both at `8ab36a84`, all 12,718 units, both healthy (8.1% and
8.4%). `M` has 301 units: 298 malicious, 3 benign, 0 holdout.

| criterion | measured | needed | result |
|---|---|---|---|
| recall on `M` | +41 TP → +0.0064 | ≥ +0.005 | PASS |
| ΔFP on `M` benign | 0 | ≤ 2 | PASS |
| holdout | `M` has no holdout units | information only | — |
| health | 8.1% / 8.4% | ≤ 10% | PASS |

- **Flips inside `M`:** 51 FN→TP and 10 TP→FN. The losses are drift, because a static finding cannot lower risk.
- **Drift outside `M`:** +59 TP / −11 FP. That implies about +3 TP of drift inside `M`, so the corrected gain is about +38
  (+0.0059). Acceptance was applied to the raw numbers as registered (P5-R20).
- **Information:** whole set recall 0.7062 → 0.7218, precision 0.9238 → 0.9274; holdout recall +0.0080, all drift;
  fetch-line guard FP 86 → 79.
- **Slices:** STB dropper cells +0.142, native wild +0.029, MSB-wild +0.033 (drift).

**Final: ACCEPTED.** The default was flipped in `45fb9511`: lure rules are on unless `SKILLSPECTOR_EXA_LURE_RULES=off`.
That commit also fixed lint left by the fix wave. Overview: `results/recall-p5-report.md`.

### Handoffs to P6+

- **Static HIGH findings lose points downstream.** 10 matched units fell TP→FN to risk 43–47 despite a HIGH `EXA-LU*`
  finding at confidence 0.95–1.0, and the 38 matched units that stay FN cluster near 47.
  - Hypothesis (unverified): the fork's "meta-analyzer verdict over static severity" patch.
  - That is the scoring-path lever for P6.
- **Flag provenance.** Unset `SKILLSPECTOR_EXA_LURE_RULES` means off before `45fb9511` and on from it. Controls without the
  rules must now set `=off`, because `arms` and resume pinning compare env values only.
- **Guard noise floor.** The 246-unit guard flips 46 units control-vs-control. Pre-register future guards as attributable
  (FPs that carry the candidate's own finding) or against the guard's own control spread.
- **Attribution.** Count every flip in the units a candidate touches, not only units that were FN in both controls.
- **Offline/live match gap.** 4 of 305 offline matches (2 benign, 2 malicious) get no live finding.

## P6

Plan: `docs/superpowers/plans/2026-10-29-recall-p6-threshold.md`. Branch `exaforce/recall-p6-threshold`, from P5's final
commit `c0e4ccaa`.

### Offline paired sweep (Task 1)

- **Source:** one healthy full run on current defaults, `bfa51d835e8b`, with the lure rules on by default.
- **Sweep:** each T in {31, 33, ..., 61} replayed with a threshold-only policy (the semantic gate is off by default).
  Findings are identical across rows.
- **Selection rule (P6-R2, made before any data):** the plan's filter, plus the spec's final-acceptance clauses
  (precision ≥ P(51) − 0.005, holdout recall ≥ holdout recall at 51). The highest recall wins, and ties break toward 51.

**Chosen: T = 49.**
- Recall 0.7248 → 0.7336 (+0.0087), above the +0.5-point minimum.
- Precision 0.9304 → 0.9264 (−0.0040).
- TP +56 / FP +26; holdout recall +0.0038.
- T = 47 fails the FP cap (406 > 399); T ≤ 45 fails precision 0.92.
- The plan's rule as written picks the same T.
- **Replication** on P5's `93c1faec5bec` (information only, P6-R6): T = 49 again, +0.0069 recall / −0.0030 precision.

Detail: `results/recall-p6-offline.md`.
