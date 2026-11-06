# Upstream upgrades: on indefinite hold

**Decision (2026-10-26):** the fork stays on upstream NVIDIA/SkillSpector
**2.8.1**. Pulling 2.13.1 was attempted, benchmarked, patched, and
re-benchmarked; the best result still had **2x the false positives** and
**45 scan timeouts** against a base that had none, and the patched tree was
2.7x slower per scan. The pull is parked in a git stash (see the end of this
file). Nothing from it is on the branch.

Everything below is from `benchmark/malskillbench_agentguard_seed.duckdb`
(4,844 units: 3,913 benign, 931 malicious; model
`nvidia.nemotron-super-3-120b` via bedrock-mantle; verdict = `DO_NOT_INSTALL`).

## Runs

| run | tree | correct | FP | FN | errors | precision | recall | F1 | avg scan |
|---|---|---|---|---|---|---|---|---|---|
| `efd838e2e656` | **base**: fork on upstream 2.8.1 | **0.876** | **187** | 415 | **0** | 0.734 | 0.554 | 0.632 | 20.5s |
| `ca1cf8d781dd` | pure upstream 2.13.1, no fork patches | 0.658 | 1241 | 257 | 157 | 0.314 | 0.688 | 0.431 | 99.0s |
| `3af1174df436` | 2.13.1 + fork patches re-applied as-is | 0.680 | 1347 | 166 | 35 | 0.361 | 0.821 | 0.501 | 49.7s |
| `aa767af2fb97` | 2.13.1 + fork patches reworked (below) | 0.851 | 376 | 303 | 45 | 0.624 | 0.673 | 0.648 | 55.2s |

"correct" is (TP + TN) / 4,844 with errors counted as wrong. All 2.13.1 runs
used 96 workers; the base run's worker count was not recorded. `8ed7dfa5fc00`
was a 1,624-unit partial of the as-is tree and agrees with `3af1174df436`.

The pure-upstream run shows the regression is upstream's, not the fork's: with
no fork code at all, 2.13.1 flags 1,241 benign skills where 2.8.1 flagged 187.

## What changed upstream (2.8.1 → 2.13.1) and why it hurts

Two independent changes, neither with an upstream opt-out.

### 1. TP4 analyzes Markdown code fences (#421)

TP4 is the LLM "description-behavior mismatch" check in
`nodes/analyzers/mcp_tool_poisoning.py`. Until 2.13 it ran only when a skill
shipped real executable files. Since #421 every `bash`/`python`/`js`/`ts`/…
fence in SKILL.md (and any other Markdown/text file) is extracted and sent to
the LLM, one batch per fence, as "the implementation". Benign skills are mostly
SKILL.md with example commands, so the LLM reports a mismatch per fence at
HIGH / ~0.92 confidence.

| | base | 2.13.1 as-is |
|---|---|---|
| benign units with a TP4 HIGH finding | 37 | 2,183 |
| share of score points *added* to benign units | | 92 % |
| benign FPs after rescoring with TP4 removed (offline) | | 1,373 → 623 |

Three TP4 occurrences alone contribute ~40 of the 51 points needed for
`DO_NOT_INSTALL`. This is also why scan time more than doubled: a live
20-unit check gave a median of 41s with fence scanning on and 10s with it off.

### 2. The meta-analyzer no longer removes anything (#393)

Before 2.13 the meta-analyzer LLM dropped findings it did not confirm
(MEDIUM/LOW outright; CRITICAL/HIGH kept on a floor). Since 2.13 it only
annotates: `report.py` scores `state["findings"]`, which merges by id and
never deletes ("Meta/LLM analysis can enrich canonical objects but cannot
remove deterministic findings"), and `finalize_ledger` re-selects every
finding. The fork's `_filter_patches.py` post-filter still ran, but its drops
never reached the score. Unconfirmed MEDIUM statics that 2.8.1 removed now all
count: on benign SKILL.md files E1 went 30 → 639 units, RA2 23 → 435, LP3 and
PE3 similarly. This is why the fork tree and pure upstream scored the same.

## Fix attempts and outcomes

### Attempt A: re-apply the fork's filter patch unchanged (`3af1174df436`)

Rewritten `apply_filter` wrapper for 2.13's stamp-based review outcomes. All
unit tests passed; end to end it was a no-op for the reason in §2. Result
indistinguishable from pure upstream (1,347 vs 1,241 FP).

### Attempt B: live isolation of the two causes (40 units, 4 configs)

20 benign units the pull had flipped TN→FP and 20 malicious units it had
flipped FN→TP, each scanned under four configurations:

| configuration | benign flagged /20 | malware caught /20 |
|---|---|---|
| 2.13.1 as-is | 15 | 17 |
| TP4 Markdown fences off | 9 | 7 |
| filter drops made effective | 9 | 14 |
| both | 4 | 7 |
| filter effective + TP4 follows meta verdict (offline) | 3 | 7 |
| filter effective + TP4 scored once per unit (offline) | 5 | 11 |

The malware column is a worst case (these are exactly the units the new code
fixed), but it shows the trade: most of 2.13's recall gain comes from the same
fence scanning that causes the false positives. The meta-analyzer marked most
TP4 findings `missing` or `disagreed`; the fork's `semantic` floor kept them.

### Attempt C: reworked patches (`aa767af2fb97`)

1. `apply_filter` wrapper returns every finding in upstream's order but
   **zeroes the confidence** of the ones it drops (tag `llm-rejected`).
   `_compute_risk_score` skips confidence ≤ 0, so the drop reaches the verdict
   while upstream's "always listed" contract holds. Verified by a graph-level
   test that failed at score 34 before the change and 0 after.
2. **TP4 removed from the LLM severity floor**, so it follows the
   meta-analyzer verdict like a static rule.

Full suite green in all three floor modes (16 upstream tests that assert
"unconfirmed finding is retained" pass again under the new contract; 4 remain
by-design xfails). Benchmark vs base:

| | base | attempt C | Δ |
|---|---|---|---|
| correct | 4242 | 4120 | −122 |
| false positives | 187 | 376 | +189 |
| false negatives | 415 | 303 | −112 |
| errors (all 300s timeouts) | 0 | 45 | +45 |
| precision | 0.734 | 0.624 | −0.110 |
| recall | 0.554 | 0.673 | +0.119 |
| F1 | 0.632 | 0.648 | +0.016 |
| avg / median / p95 scan | 20.5s / 14.2s / 64.9s | 55.2s / 28.1s / 237.3s | 2.7x / 2.0x / 3.7x |

The residual 241 new false positives decompose as:

- **TP4 the meta-analyzer confirms**: still on 355 benign units, top
  contributor on 136 of the 241. Both LLMs agree, so no floor policy touches
  it; only disabling fence scanning or capping TP4's contribution would.
- **Lost LLM batches**: 114 of the 376 benign FPs had
  `llm_calls_succeeded < llm_calls_attempted`. A failed meta-analyzer batch
  keeps every finding fail-closed at full weight (418 scans lost calls at 96
  workers; see the `llm-failure-amplification` note in the benchmark docs).
- **Timeouts**: 45 scans hit the 300s cap, all scored wrong.

F1 is slightly up only because the harmonic mean rewards lifting the weaker
side (recall); on a corpus that is 81 % benign, overall correctness is down.

## What would be needed to lift the hold

Any of these would need its own controlled A/B against `efd838e2e656`
(same day, replicated; per-unit flips are noisy, judge aggregates only):

- An upstream opt-out for TP4 fence scanning, or a fork patch that empties
  `_TP4_MARKDOWN_TYPES` (restores 2.8.1 TP4 gating; cuts scan time ~2.5x;
  gives up most of 2.13's recall gain).
- Capping TP4 to one scored occurrence per skill (attempt B's offline
  estimate: FP 5/20, TP 11/20 on the hard sample).
- Fewer workers so batches stop being dropped, since dropped batches turn
  directly into false positives under 2.13's fail-closed design.
- An upstream change to §2 that lets meta-analysis remove or down-weight
  findings in the public result.

Without at least the TP4 change the 2.13 line is slower and less precise than
what the fork ships today, and the recall gain does not pay for it.

## Where the attempt lives

The 2.13.1 pull plus attempt C (`_filter_patches.py`, `tests/exaforce/`,
root `conftest.py`, `docs/superpowers/EXPECTED_TEST_FAILURES.md`) is in
`git stash` on branch `bump-upstream-version`, entry
"upstream 2.13.1 pull + fork fix attempt C (on hold)". The benchmark runs
above are in the DuckDB and are not part of the stash. Fork-side diagnosis
notes are also in the Claude project memory under
`upstream-2-13-fp-regression-causes`.
