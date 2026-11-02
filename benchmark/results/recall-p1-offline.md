# P1 offline policy selection

Synthetic runs from `uv run replay results/recall.duckdb $BV2 ...` (`BV2=e16e394f65c3`, 12,718 units, 6,403
malicious). Replay is deterministic, so there is no noise floor here; Task 4's live arms provide it. Gate rules:
SSD-1..4 and P2 at HIGH+. Reports: `uv run report results/recall.duckdb <run> --base $BV2`.

| policy | run | ΔTP | ΔFP | recall | precision | SkillHarm attributed recall | STB recall | non-STB recall |
|---|---|---|---|---|---|---|---|---|
| BV2 (no policy) | `e16e394f65c3` | 0 | 0 | 0.712 | 0.931 | 0.210 | 0.900 | 0.437 |
| gate=any | `5f9fefc7f1f6` | +210 | +24 | 0.744 | 0.930 | 0.213 | 0.910 | 0.503 |
| gate=confirmed | `b1933d090aa7` | +185 | +18 | 0.741 | 0.931 | 0.213 | 0.910 | 0.494 |
| cap=2 | `89c73f98af88` | -3 | -1 | 0.711 | 0.931 | 0.210 | 0.900 | 0.436 |
| cap=3 | `4a8049d56816` | -1 | 0 | 0.712 | 0.931 | 0.210 | 0.900 | 0.436 |
| cap=5 | `e671c607a9e7` | 0 | 0 | 0.712 | 0.931 | 0.210 | 0.900 | 0.437 |

All five synthetic runs report `healthy`. The cap does essentially nothing on this corpus (at most one FP removed).

## Where the gate's gain comes from (STB and non-STB separately)

Added TPs are FN→TP against BV2 and added FPs are TN→FP. `corpus` is `units.corpus`; "native wild" is
`corpus=malware` (benign: `corpus=benign`). This run differs from the review's "154 of 210 in native wild and PI",
which came from the original run: here native wild is 141 of 210 and the prompt-injection corpus (Skill-Inject) 11.

| | gate=any added TP (210) | gate=confirmed added TP (185) | any added FP (24) | confirmed added FP (18) |
|---|---|---|---|---|
| native wild (`malware` / `benign`) | 141 | 121 | 20 | 14 |
| SkillTrustBench | 37 | 35 | 4 | 4 |
| MaliciousSkillBench | 17 | 15 | 0 | 0 |
| Skill-Inject (PI) | 11 | 10 | 0 | 0 |
| SkillHarm | 4 | 4 | 0 | 0 |
| **STB subtotal** | **37** | **35** | **4** | **4** |
| **non-STB subtotal** | **173** | **150** | **20** | **14** |

- STB recall moves 0.900 to 0.910 (+37 of 3,797 units); non-STB recall 0.437 to 0.503 (any) or 0.494 (confirmed)
  (+173 / +150 of 2,606). Roughly 82% of the gain is non-STB, mostly native wild, which is the less-trusted
  portion of the labels.
- MaliciousSkillBench's 17 added TPs split by `source_dataset`: SkillSafetyBench 7, ATR Skill Security Benchmark 3,
  AgentTrap 2, SkillLeakBench 2, MaliciousAgentSkillsBench 2, SkillFortifyBench 1.
- Added FPs are all native benign (20 / 14) plus 4 STB benign.
- SkillHarm attributed recall rises only 187 to 190 of 890: the gate flips verdicts mostly without pointing at
  injected files.

## Share of hits from `llm-unconfirmed` findings (for Task 5)

A unit counts as unconfirmed-only when every HIGH+ gate-rule finding it has in BV2 is tagged `llm-unconfirmed`.

| mode | added TPs unconfirmed-only | added FPs unconfirmed-only |
|---|---|---|
| any | 25 of 210 (11.9%) | 6 of 24 (25%) |
| confirmed | 0 of 185 (by construction) | 0 of 18 |

So `any` over `confirmed` buys +25 TP for +6 FP (4.2 TP per FP), well below the 8:1 bar.

## Decision

GATE=confirmed, CAP=none. Arithmetic is in `results/recall-ledger.md` (`## P1`).
