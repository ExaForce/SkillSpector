# P6 offline: paired block-threshold sweep

Source: full run `bfa51d835e8b` ("p6 full control (current defaults)"). It ran on 2026-11-05 at `c0e4ccaa`, covering
all 12,718 units with no `SKILLSPECTOR_EXA_*` flags set, so the lure rules were on by default. The run is healthy:
8.1% of scans dropped LLM calls, with 0 errors.

**Method.** Each T in {31, 33, ..., 61} was replayed with
`uv run replay results/recall.duckdb bfa51d835e8b --policy '{"threshold": T}'`. The gate rules are the shipped
default (the semantic gate is off), so the policy is the threshold alone. Each replay was then reported against the
source run with `uv run report ... --base bfa51d835e8b --split-file results/evalsets/splits.tsv`; the per-T reports are
not committed.
- A threshold-only replay keeps every stored score, so findings are identical in every row. The rows differ only in
  the cut, so there is no nondeterminism noise between them.
- As a check, T = 51 reproduces the source run (4,641 TP / 347 FP).

**Selection rule (P6-R2).** It was set before any sweep data.
- **Plan filter:** precision ≥ 0.92, precision ≥ P(51) − 0.01, and FP ≤ 1.15 × FP(51) = 399.
- **Spec clauses added:** precision ≥ P(51) − 0.005, and holdout recall ≥ holdout recall at 51.
- **Choice:** the highest recall wins, and ties break toward 51. The plan minimum is +0.5 recall points.

| T | replay run | TP | FP | recall | precision | holdout recall | non-STB recall | benign 21+ FP rate | plan filter | P6-R2 filter |
|---|---|---|---|---|---|---|---|---|---|---|
| 31 | `2989de038a5c` | 5051 (+410) | 703 (+356) | 0.7888 | 0.8778 | 0.9158 | 0.555 | 0.644 | no | no |
| 33 | `da76335dc45a` | 4988 (+347) | 641 (+294) | 0.7790 | 0.8861 | 0.9080 | 0.540 | 0.633 | no | no |
| 35 | `720388e934fb` | 4956 (+315) | 614 (+267) | 0.7740 | 0.8898 | 0.9048 | 0.531 | 0.633 | no | no |
| 37 | `7a80021791d7` | 4923 (+282) | 570 (+223) | 0.7689 | 0.8962 | 0.9015 | 0.522 | 0.611 | no | no |
| 39 | `05179264a05e` | 4893 (+252) | 535 (+188) | 0.7642 | 0.9014 | 0.8980 | 0.515 | 0.611 | no | no |
| 41 | `41015ef9c89b` | 4862 (+221) | 505 (+158) | 0.7593 | 0.9059 | 0.8938 | 0.509 | 0.611 | no | no |
| 43 | `93ea1e9912ff` | 4834 (+193) | 479 (+132) | 0.7550 | 0.9098 | 0.8908 | 0.502 | 0.611 | no | no |
| 45 | `aaf0bebc50cb` | 4809 (+168) | 456 (+109) | 0.7511 | 0.9134 | 0.8885 | 0.494 | 0.600 | no | no |
| 47 | `73f9e7209483` | 4749 (+108) | 406 (+59) | 0.7417 | 0.9212 | 0.8828 | 0.478 | 0.567 | no | no |
| **49** | `5f4044b8e40a` | 4697 (+56) | 373 (+26) | 0.7336 | 0.9264 | 0.8793 | 0.464 | 0.556 | yes | yes |
| 51 | `654caf3644f9` | 4641 (+0) | 347 (+0) | 0.7248 | 0.9304 | 0.8755 | 0.447 | 0.522 | yes | yes |
| 53 | `b806bf89ea89` | 4605 (-36) | 325 (-22) | 0.7192 | 0.9341 | 0.8710 | 0.439 | 0.500 | yes | no |
| 55 | `5acabc6075ad` | 4562 (-79) | 297 (-50) | 0.7125 | 0.9389 | 0.8648 | 0.431 | 0.478 | yes | no |
| 57 | `f540eb898267` | 4519 (-122) | 274 (-73) | 0.7058 | 0.9428 | 0.8600 | 0.421 | 0.444 | yes | no |
| 59 | `87d6abbb0320` | 4482 (-159) | 251 (-96) | 0.7000 | 0.9470 | 0.8533 | 0.414 | 0.433 | yes | no |
| 61 | `f450819a4738` | 4425 (-216) | 244 (-103) | 0.6911 | 0.9477 | 0.8453 | 0.404 | 0.433 | yes | no |

**Applied.**
- **T = 49 is chosen**, under both the plan's rule as written and P6-R2:
  - recall 0.7248 → 0.7336 (**+0.0087**, minimum +0.005: PASS);
  - precision 0.9304 → 0.9264 (−0.0040, within −0.005);
  - TP +56 and FP +26;
  - holdout recall +0.0038.
- **T = 47 fails** the FP cap (406 > 399).
- **T ≤ 45 fails** precision 0.92.
- **T > 51** only loses recall.

**What T = 49 moves.** It blocks units scored 49 or 50, and the source run has 82 of them: 56 malicious and 26 benign.
Score 50 alone holds 43 malicious and 23 benign, the largest single-score mass between 41 and 52. Every flip is FN→TP
or TN→FP, with about 2.2 TP gained per FP added. P5 gained +41 TP at 0 FP on its affected units, so this is a weaker
trade. The pre-registered filter accepts it.
- **Benign 21+ FP rate:** packages with 21 or more components go from 0.522 to 0.556.
- **Non-STB recall:** +0.017.

**Replication (P6-R6, information only).** The same sweep over P5's full L run `93c1faec5bec` (2026-11-04, same scoring
behaviour, an independent LLM sample) also picks T = 49:

| T | TP | FP | recall | precision | P6-R2 filter |
|---|---|---|---|---|---|
| 47 | 4736 | 412 | 0.7397 | 0.9200 | no |
| 49 | 4666 | 382 | 0.7287 | 0.9243 | yes |
| 51 | 4622 | 362 | 0.7218 | 0.9274 | yes |

On that run, T = 49 gives +0.0069 recall and −0.0030 precision. T = 47 fails there too, on precision 0.92 (0.91997)
and on R2's −0.005. So the choice is not specific to one run.

**Decision.** T = 49 goes to Task 2: flag `SKILLSPECTOR_EXA_BLOCK_THRESHOLD`, then default 49.
