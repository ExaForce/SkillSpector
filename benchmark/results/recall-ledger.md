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
