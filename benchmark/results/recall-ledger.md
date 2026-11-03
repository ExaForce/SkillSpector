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
