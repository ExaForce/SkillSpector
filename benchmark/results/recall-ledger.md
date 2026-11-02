# Recall improvement program: run ledger

Program DB: `benchmark/results/recall.duckdb`, created as a copy of `malskillbench_agentguard_seed.duckdb`, so it holds
the original run `113b02ab497b`. Spec: `docs/superpowers/specs/2026-10-29-recall-improvement-program.md`. Append one
row per run, and one decision block per plan below the table.

| plan | iteration | arm | replicate | run_id | git sha | flags | units | health | note |
|---|---|---|---|---|---|---|---|---|---|
| P0 | ref | original | - | `113b02ab497b` | unrecorded | none | 12,718 | UNHEALTHY: dropped LLM calls 6.9% | seed DB; no `issues.tags`; recall 0.709, precision 0.928 |
| P0 | preflight | control | 1 | `6505da99b6a6` | 4c2a59fe | none | 1 | OK | `pptx__skillharm-fpp-a4db25e26d`: TP, SDI-1/SQP-3 HIGH, tags recorded |
| P0 | baseline | control | 1 | `e16e394f65c3` | 4c2a59fe (src = P0 final) | none | 12,718 | OK (dropped 4.2%, 0 errors) | baseline-v2; crashed at 10,638 on an INT32 line number, fixed in `1db355d1`/`e2023f4e`, resumed with `--run-id`; recall 0.712, precision 0.931 |

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
