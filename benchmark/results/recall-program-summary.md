# Recall improvement program (P0–P7): summary

**Goal** (`docs/superpowers/specs/2026-10-29-recall-improvement-program.md`): raise malicious-skill recall above the
0.709 of the original run `113b02ab497b`, keeping precision at about 0.92 or better.

**Result: met, by a small margin.** The current defaults reach recall **0.734** at precision **0.926**, on all
12,718 units. Two plans shipped:
- P5 lure rules, `SKILLSPECTOR_EXA_LURE_RULES`, on by default (`45fb9511`);
- P6 block threshold 49, `SKILLSPECTOR_EXA_BLOCK_THRESHOLD`, with a score clamp (`4e6863d1`, `33271de5`).

Their same-day causal gains add up to about **+0.015 recall**: P5 +0.0064 (+0.0059 after drift correction) and P6
+0.0087. The rest of the cumulative +0.025 is not attributable to any measured change. It is most likely endpoint
drift and run-to-run churn: in P5, a same-day full pair moved about 1 point outside the rule-affected units.

Four plans were rejected on the dev set:
- **P1, P3 and P4** found real misses, with large TP gains (P1 +31.5, P3 up to +113, P4 up to +79). They failed on
  FP cost, against the 8:1 and noise-floor FP rules, and P3 and P4 also on run health.
- **P7** failed on too little gain: +13 TP at best, against a bar of 20.

P2 has no verdict.

The head run for the cumulative numbers is `60503e65c287`: P6's replay of the full run `bfa51d835e8b` at T = 49 with the
clamp. Per the plan, it is the latest full run with every accepted default, because P7 made no full run
(it was rejected at the dev stage). It carries P5's lure rules (on by default at `c0e4ccaa`) and P6's threshold.

## Per plan

Same-day Δ is the causal estimate: treatment against same-day control, or a paired replay for P6. Dev-set deltas are
on that plan's dev set, not the full set, and do not compare across plans.

| plan | change | verdict | flags shipped (default) | same-day Δrecall | Δprecision | where measured | report |
|---|---|---|---|---|---|---|---|
| P0 | measurement tooling, `baseline-v2` `e16e394f65c3` | n/a | none | +0.003 (drift only) | +0.003 | full set, against the original | [p0](recall-p0-report.md) |
| P1 | semantic-finding gate; doc-finding cap | REJECTED (FP cost) | `SKILLSPECTOR_EXA_SEMANTIC_GATE` (off), doc cap (off) | +0.076 | +0.030 | dev (1,364), ΔTP +31.5 / ΔFP +13.5 against an allowance of 8 | [p1](recall-p1-report.md) |
| P2 | text from PDF/office files; hidden-text rules | INCOMPLETE, no verdict | `SKILLSPECTOR_EXA_DOC_TEXT`, `SKILLSPECTOR_EXA_HIDDEN_TEXT` (off) | rep 1 only: +37 TP / +3 FP (A), +37 / −13 (B) | – | dev (2,154), one replicate | [ledger § P2](recall-ledger.md) |
| P3 | skill-context header; instruction-flow pass | REJECTED, rolled back | none | +0.097 (best arm, B3) | +0.030 | dev (2,112) | [p3](recall-p3-report.md) |
| P4 | necessity audit (SSD-5; EXA-NE1) | REJECTED, rolled back | none | +0.070 (best arm, B) | −0.010 | dev (2,393) | [p4](recall-p4-report.md) |
| P5 | lure rules EXA-LU1, EXA-LU4 | **ACCEPTED** | `SKILLSPECTOR_EXA_LURE_RULES` (**on**) | **+0.0064** | +0.0006 | full set, rule-affected units: +41 TP / 0 FP | [p5](recall-p5-report.md) |
| P6 | block threshold 51 → 49, score clamp | **ACCEPTED** | `SKILLSPECTOR_EXA_BLOCK_THRESHOLD` (**49**) | **+0.0087** | −0.0040 | full set, paired replay: +56 TP / +26 FP | [p6](recall-p6-report.md) |
| P7 | stronger model for the SSD slot | REJECTED (dev; no candidate PROMISING) | none (no code) | +0.032 (best, deepseek) | +0.029 | dev (1,364), ΔTP +13 / ΔFP −10 against a bar of 20; mistral +5.5, qwen +5 (FUTILE) | [p7](recall-p7-report.md) |

## Cumulative

Both comparisons cross days. They include endpoint drift and the ~7% per-unit churn P0 measured with identical code,
so they are not causal. The per-plan rows above are the causal estimates.

| | original `113b02ab497b` | `baseline-v2` `e16e394f65c3` | current defaults `60503e65c287` | Δ against original | Δ against baseline-v2 |
|---|---|---|---|---|---|
| recall | 0.709 | 0.712 | **0.734** | +0.025 | +0.022 |
| precision | 0.928 | 0.931 | **0.926** | −0.002 | −0.005 |
| TP / FP | 4,538 / 352 | 4,557 / 336 | 4,697 / 373 | +159 / +21 | +140 / +37 |
| holdout recall | 0.873 † | 0.873 | 0.879 | † | +0.006 |
| holdout precision | 1.000 † | 0.972 | 0.964 | † | −0.008 |
| non-STB recall | 0.427 | 0.437 | 0.464 | +0.037 | +0.028 |

† The dev sets were drawn from the original run's outcomes, so its holdout figures are biased by construction:
- Every unit the original got wrong on the benign side went into a dev set, so its holdout precision is 1.000.
- 1,355 of its 1,865 FNs (73%) are in dev, although dev holds only 37.5% of malicious units, so its holdout recall
  is inflated.

Holdout Δs against the original are therefore meaningless. Use the `baseline-v2` column for holdout.

The original run also fails today's health check (6.9% of scans dropped LLM calls; P0), so `baseline-v2` is the
cleaner comparator.

## Low-recall behaviours

Recall per behaviour for the 11 behaviours below 0.80 in the original run (`report` "By behavior"; the `(none)` row,
units with no behaviour label, is left out). Original against current defaults:

| behaviour | n | original | current | Δ | still < 0.80? | boundary (`recall-boundaries.md`) |
|---|---|---|---|---|---|---|
| Content Manipulation | 250 | 0.248 | 0.240 | −0.008 | yes | B3 output integrity (purpose-fit harm); only O4 targets it, and O4 (P4) was rejected |
| Credential Theft | 154 | 0.299 | 0.305 | +0.006 | yes | B0: MSB units sanitised or redacted; mostly a label/measurement problem |
| Role Hijack | 13 | 0.308 | 0.385 | +0.077 | yes | B1 scoring: one HIGH semantic finding cannot reach the cut; O1 (P1) rejected on FP cost |
| System Prompt Leak | 43 | 0.302 | 0.395 | +0.093 | yes | B1 scoring, as Role Hijack |
| Safety Bypass | 20 | 0.350 | 0.500 | +0.150 | yes | B1 scoring, as Role Hijack |
| Remote Code Execution | 81 | 0.370 | 0.407 | +0.037 | yes | B0 + B5: MSB vendor pipe-to-shell templates; P5's lure rules cover part |
| Resource Abuse | 122 | 0.434 | 0.475 | +0.041 | yes | SkillHarm `dos` presented as preflight (B3) plus B0 placeholders |
| Goal Hijacking | 234 | 0.598 | 0.590 | −0.008 | yes | B2/B3, SkillHarm only (STB is 1.00) |
| Persistence | 285 | 0.730 | 0.758 | +0.028 | yes | B2: shell-rc edits in PDFs or auxiliary docs; P2 (O2) has no verdict |
| Data Exfiltration | 304 | 0.734 | 0.740 | +0.006 | yes | B0 placeholder hosts plus a SkillHarm detection gap (B2/B3) |
| Privilege Escalation | 1,071 | 0.789 | 0.811 | +0.022 | **no** | crossed 0.80 |

Small slices move a lot by chance: Safety Bypass is 20 units, Role Hijack 13. Against `baseline-v2`, System Prompt
Leak (0.465 → 0.395) and Role Hijack (0.462 → 0.385) went down, so their gains against the original are within
run-to-run noise.

**What is still below 0.80, by boundary:**
- **B1 scoring** (Role Hijack, System Prompt Leak, Safety Bypass): the LLM often finds these, but one HIGH semantic
  finding scores about 25, against a block cut of 49 since P6 (51 before).
  - P1's gate recovered them but cost too many FPs. P3 and P4 reported the same cap on their flagged misses. P6 moved
    the cut only by 2.
  - For these behaviours the lever is a scoring path for corroborated semantic findings that costs fewer FPs than
    P1's gate.
  - This does not hold across the board. On P7's dev set, about 90% of missed units carry no HIGH semantic finding
    under any of four models, so most misses are a detection problem.
- **B3 purpose-fit harm** (Content Manipulation, Goal Hijacking and Resource Abuse on SkillHarm): no plan moved them. P4
  was the only one aimed here and was rejected.
- **B2 visibility** (Persistence, part of Data Exfiltration): P2's document-text extraction is the targeted fix. It
  is unfinished, with one replicate pointing to +37 TP on its dev set.
- **B0 label validity** (Credential Theft, part of RCE and Data Exfiltration): mostly a measurement problem. Tiered
  labels (O0) would raise these on valid units without any classifier change.

## Open items

- **P1:** the gate and cap code is still in `src/skillspector/exaforce/` with the flags off. A rollback, as for P3
  and P4, is the user's call.
- **P2:** the code is in `src/skillspector/exaforce/` with the flags off. The dev arms need replicate 2 and final
  acceptance, or a decision to drop it.
- **Score-50 mass** (P6 handoff): many units sit just under the cut. Explaining it (the fork's meta-verdict-over-static-severity
  patch is the suspect) is the B1 lever above.
- **P7:** no re-test is recommended. The stronger SSD models mostly add MEDIUM findings on units already caught.
- **Harness robustness** (P7 final review): one unrecordable scan still aborts a whole benchmark run. Also,
  `mcp_tool_poisoning` TP4 can put a non-string `explanation` into SkillSpector's JSON report.
