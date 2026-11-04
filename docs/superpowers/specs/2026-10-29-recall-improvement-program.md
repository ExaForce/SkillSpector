# Recall improvement program: shared spec

<sub>Written 2026-10-29. This spec is shared by plans P0-P7 in `docs/superpowers/plans/2026-10-29-recall-p*.md`. The
analysis behind it is `benchmark/recall-boundaries.md`, and the evidence is in `benchmark/recall-boundaries-review.md`.
Every plan's Global Constraints section implicitly includes everything below.</sub>

## Goal

Raise SkillSpector's malicious-skill recall above the 0.709 of run `113b02ab497b` while keeping precision at
about 0.92 or better. Each improvement option from `recall-boundaries.md` gets its own plan:

| Plan | Option | What it changes | Depends on |
|---|---|---|---|
| P0 | O0 | Measurement: the tooling every later plan uses to quantify a change, plus the `baseline-v2` run | none |
| P1 | O1 | A semantic-finding gate, plus an optional cap on findings from documentation files | P0 |
| P2 | O2 | Text extraction from PDF/office files, plus hidden-text rules | P0, P1 |
| P3 | O3 | Skill-level context for per-file LLM calls, plus an instruction-flow pass | P0, P1, P2 |
| P4 | O4 | A necessity audit of imperative steps | P0, P1; P3 code (`intercept_method`, the analyzer pattern) |
| P5 | O5 | Rules for remote-installer lures | P0, P1, P2 |
| P6 | O6 | Re-tune the block threshold | P0, plus every accepted plan before it |
| P7 | O7 | A stronger model for the per-skill passes only | P0; P3 or P4 |

Run the plans in order P0 → P7, one per session. A plan whose prerequisites were rejected still runs: it only needs
the code its prerequisites shipped, and rejected changes ship behind a flag that defaults to off.

## Autonomy rules (no human interaction once a plan starts)

1. **Never ask the user anything.** Each plan carries the decisions it needs as pre-registered rules (see Decision
   rules). Where a plan offers alternatives, it measures every arm and applies the rule.
2. **Commit each task as soon as its review is clean** (the user's CLAUDE.md rule for plan execution). Never push,
   open a PR, merge into `main`, or use `--no-verify`.
3. **Stage files by explicit path only.** Never use `git add -A` or `git add .`. The working tree carries user
   work-in-progress that must never be committed and must stay in place, because the expanded dataset depends on it:
   `benchmark/benchmark/dataset_handler/malskillbench.py`, `benchmark/uv.lock`, `benchmark/tests/test_external_labels.py`,
   and the untracked `.md` reports in `benchmark/`. Work in the main checkout `/Users/will/workspace/SkillSpector`,
   not a worktree, so that WIP stays active.
4. **Branches.** P0 starts from `exaforce/promote-confirmed-ssd-high`. Every later plan PN branches from the final
   commit of plan P(N-1)'s branch, named `exaforce/recall-pN-<slug>`. Stacked branches, no merges.
5. **When blocked, stop cleanly.** "Blocked" means credentials expired, the LLM endpoint fails its health check twice
   in a row, or the dataset is missing. Write `benchmark/results/BLOCKED-pN.md` with:
   - the failing command and its output;
   - the last good run id;
   - the exact command to resume (for an interrupted scan, `--run-id <id>`).

   Commit what is finished, then end the session. Do not loop waiting for a human.
6. **Credentials preflight** before every benchmark invocation. Run `aws sts get-caller-identity`. Then make one
   1-unit LLM scan of a known-malicious unit and check that `uv run health` passes on it (P0 builds `health`). Run every
   benchmark with `--auth-wait-seconds 0`, so an SSO expiry aborts to a resumable DB instead of waiting for a login
   nobody will do.
7. **Fork boundaries** (see `docs/superpowers/EXPECTED_TEST_FAILURES.md`):
   - Classifier changes go only in `src/skillspector/exaforce/` as drift-guarded runtime patches (use
     `exaforce/_patchlib.py`), with tests in `tests/exaforce/`. Harness changes go only in `benchmark/`.
   - Never edit `tests/nodes/*`, `Makefile`, `.github/`, root `pyproject.toml`, root `uv.lock`, or any other
     `src/skillspector/` file.
   - No new runtime dependencies. Use the stdlib (`zlib`, `zipfile`, `xml.etree`, `re`, `base64`) for parsing.
   - The by-design upstream failures listed in `EXPECTED_TEST_FAILURES.md` are marked `xfail(strict=True)` by the
     root `conftest.py`. A plain FAIL anywhere is yours to fix.
   - Test commands:
     - repo root: `uv run pytest -q`;
     - harness: `cd benchmark && uv run pytest -q`;
     - lint: `uv run ruff check <files> && uv run ruff format --check <files>`, from the root for `src/` and `tests/`,
       and from `benchmark/` for harness files.

## Flags

Every classifier change ships behind an environment flag named `SKILLSPECTOR_EXA_<NAME>`:
- Read the flag on every call, never cached at import, the same way `SKILLSPECTOR_META_SEVERITY_FLOOR` is read in
  `_filter_patches.py`. That lets one code tree run both arms.
- The default stays **off** until the plan's final acceptance passes. Turning the default on is a separate final
  commit.
- A rejected change stays committed with its default off. Its flag and its rejection evidence are recorded in the
  ledger.

Rule IDs added by the fork use the prefix `EXA-`, for example `EXA-HT1`. Before using an ID, confirm it is unused with
`grep -rn '"EXA-' src/`.

## Data and paths

- Program DB: `benchmark/results/recall.duckdb`. P0 creates it by copying
  `benchmark/malskillbench_agentguard_seed.duckdb`, so it contains the original baseline run `113b02ab497b`. Every
  run in every plan appends to this one DB (`-o results/recall.duckdb`). `*.duckdb` is gitignored.
- Dataset: `/Users/will/workspace/MalSkillBench/Dataset`. Label files live in `.../Dataset/Skills/`:
  - `_external_labels.jsonl`;
  - `_boundary_features.jsonl` (all 6,403 malicious units);
  - `_boundary_labels.jsonl` (412 annotated units);
  - `_skillharm_injected.jsonl`, which P0 creates.
- Evaluation sets: `benchmark/results/evalsets/*.txt`, one `unit_path` per line, committed.
- Ledger: `benchmark/results/recall-ledger.md`, committed. Every run gets one row, appended:
  `plan | iteration | arm | replicate | run_id | git sha | flags | units | health | note`.
  Below the table there is one decision block per plan.
- Reports: `benchmark/results/recall-pN-report.md`, committed.
- Commands run from `benchmark/` with `uv run ...`.

## Evaluation protocol

Per-unit verdicts flip on identical input: about 3% of units, and up to 21 of 34 borderline units. A comparison against
a run from another day also mixes in endpoint drift. So:

1. **Every comparison is same-day, arm against arm, on the same code tree.** Control and treatment differ only in
   their env flags.
2. **Dev iterations** run on the plan's dev set: the core set from P0, plus the plan's focus set. Each arm is run
   **twice**.
   - Control replicates: run them once per day per dev set, and reuse them for every candidate that day.
   - Noise floor: `N_TP = max(3, |TP(c1) − TP(c2)|)` and `N_FP = max(2, |FP(c1) − FP(c2)|)`.
3. **Offline replay first, where the change is to scoring.** A pure scoring change (gate, cap, threshold) is first
   evaluated with `uv run replay` over the stored issues of the latest full run. That costs no LLM time, and it is how
   existing results quantify a change. A live run then confirms the winner.
4. **Final acceptance** is one full run on the treatment flags plus one same-day full run on control flags. A full run
   is all units, about 1 hour of wall time at 96 workers. Score it on all units, and separately on the **holdout**
   split (every unit not in any dev set).
5. **The overview at the end of every plan:**
   ```bash
   uv run report results/recall.duckdb <treatment_full> --base <control_full> -o results/recall-pN-report.md
   uv run report results/recall.duckdb <treatment_full> --base <baseline_v2> --split-file results/evalsets/splits.tsv \
     >> results/recall-pN-report.md
   ```
   The first compares against same-day control; that is the claim. The second is cumulative against P0's
   `baseline-v2`, and is confounded by drift, as the report's preamble states. Then append the plan's decision block
   to the ledger.

## Decision rules (pre-registered; apply mechanically)

Let `ΔTP` and `ΔFP` be the treatment mean minus the control mean over replicates.

**Dev verdict for a recall-raising candidate:** `PROMISING` when all three hold:
- `ΔTP ≥ 2·N_TP`;
- `ΔFP ≤ max(N_FP, ΔTP / 8)`, i.e. at least 8 extra TPs per extra FP;
- both treatment replicates pass `health`.

Otherwise the verdict is `REJECT`. `uv run arms` computes this.

**Dev verdict for an FP-reducing candidate:** `PROMISING` when all three hold:
- `−ΔFP ≥ 2·N_FP`;
- `−ΔTP ≤ (−ΔFP) / 2`;
- SkillHarm attributed recall does not drop.

**Iteration budget:** at most **5** candidates per plan. A candidate is one flag setting or prompt variant. Pick the
candidate with the highest `ΔTP − 8·ΔFP` among the PROMISING ones. If none is PROMISING after 5, the plan's verdict is
REJECTED. Record that and still produce the overview.

### Sequential futility screen (pre-registered 2026-11-04)

A candidate is screened with `uv run screen` before its full dev replicates. The screen scans the dev set in stratified
batches (never repeating a unit), pairs treatment with same-day control on the units judged so far, and stops only to
reject.

- Constants, used verbatim:
  - batch size 150;
  - seed 29;
  - FP weight 8 (the spec's 8:1 rule);
  - minimum batches before any stop: 3;
  - z = 2.8 (one-sided per look, about 0.26%; over about 16 looks the false-futility rate stays below 5%);
  - allowance `16·n/N`, which is the spec's `N_FP ≥ 2` floor (8·2) scaled to the n of N units judged so far.
- Per-unit paired score:
  - `d_i = (tp_t − tp_c) − 8·(fp_t − fp_c)`, where `tp`/`fp` are the unit's TP/FP indicators. With several runs on a
    side, they are means over that side's runs that contain the unit.
  - A unit whose outcome is ERROR in any run on either side is excluded from `d` and counted separately.
- Boundary:
  - `D = Σ d_i` over the n judged units so far.
  - `SE = sd(d, ddof=1)·sqrt(n)`, or 0 when n < 2.
  - Stop (FUTILE) iff the batch count is ≥ 3 and `D + 2.8·SE < −16·n/N`.
  - Never stop for success.
- FP-reducing candidates (`--kind fp`, mirroring `arms --kind`). The spec's rule needs `−ΔTP ≤ (−ΔFP)/2`, that is
  `2·ΔTP − ΔFP ≥ 0`.
  - The per-unit score is `d_i = 2·(tp_t − tp_c) − (fp_t − fp_c)`, and the allowance is 0.
  - Stop iff the batch count is ≥ 3 and `D + 2.8·SE < 0`.
  - The default is `--kind recall`.
- Stratum key per unit, from a reference run's `evaluation` row: `'benign'` when not malicious, else
  `coalesce(behavior, corpus, 'unknown')`. A unit absent from the reference run gets `'unknown'`.
- A FUTILE screen is that candidate's dev verdict, REJECT, and it still counts toward the 5-candidate budget.
- A PASSED screen is followed by the standard dev verdict. The screen's union of treatment batch runs is treatment
  replicate 1, and its control is control replicate 1 (or the reused control runs). One more full replicate of each
  arm is run the same day, then `uv run arms` judges.
  - When control runs are reused, they are the control replicates (×2), and only the treatment gets one more full
    same-day run (screen union + T2).
  - When control was scanned per batch, its union is control replicate 1, and one more full control run and one more
    full treatment run are made.
- Control runs are reused only from the same day, tree and dev set.
- The screen never accepts.

Validation (2026-11-04, simulate on existing runs):
- The first replay averaged the two treatment runs on each side. A live screen has one treatment run per unit, so it
  is weaker than that replay.
  - P4 A (control 54ce3a6bbe59,01d373aebd37 vs treatment daed644651be,a753a1ba2c6c on p4-dev, two treatment runs
    averaged): FUTILE at batch 7, 1050 of 2393 units scanned.
  - P3 B1 (control bfcbcbe585e5,2e6e81859349 vs treatment a9949fa84c95,2a94f96eb7c8 on p3-dev, two averaged), whose
    full dev verdict was REJECT on FP cost: not stopped. The final look was D + 2.8·SE = +16.00 against a boundary of
    −15.99, with D = −172.5 and SE = 67.3 at n = 2111.
  - Control against control (bfcbcbe585e5 vs 2e6e81859349): not stopped, as required.
- Replays in the live configuration (control = the 2 reused runs, one treatment run):
  - P4 A stops in 1 of 2: a753a1ba2c6c is FUTILE at batch 7 (1050 units); daed644651be is PASSED, all 16 batches.
  - P3 B1 passes in both: a9949fa84c95 (final D + 2.8·SE −13.11 vs −15.99) and 2a94f96eb7c8 (+123.70).
- Limitations, stated as properties of the pre-registered rule:
  - P3 B1 is not a near miss. Its D = −172.5 is about 11× the allowance. It passes because `SE = sd·√n` has no
    finite-population correction, so SE keeps growing as n approaches N.
  - The rule scores only net 8:1-weighted harm. It has no `ΔTP ≥ 2·N_TP` clause, so a null or weak candidate is never
    stopped by design. It catches grossly net-harmful candidates only; every other reject comes from the standard dev
    verdict.
  - The constants are not retuned.

**Final acceptance (full run):** `ACCEPTED` when all of these hold:
- recall gain ≥ the plan's minimum, which defaults to **+0.5 points**;
- precision ≥ control precision − 0.005;
- holdout-split recall gain ≥ 0;
- both full runs pass `health`;
- any plan-specific guard passes.

On ACCEPTED, turn the default on in a final commit. Otherwise leave it off.

## Quantifying with existing results

Live LLM runs are the expensive part, so every plan first quantifies from data that already exists:

| Source | Used for | Where |
|---|---|---|
| Original run `113b02ab497b` (seed DB) | selecting dev, focus and holdout sets from known outcomes; the original-baseline column of every cumulative report | P0 Task 8; every plan's focus set |
| `baseline-v2` (P0, with finding tags) | the replay source for every scoring change; the cumulative base | P1, P6 |
| `uv run replay` | exact counterfactual verdicts for gates, caps and thresholds from stored findings, with no LLM calls | P1 Task 1, P6 Task 1 |
| `uv run rulelab` | exact benign and malicious match counts for candidate static rules over the dataset files, with no scan | P5 Task 1 |
| `_boundary_labels.jsonl` / `_boundary_features.jsonl` | validity tiers, STB/non-STB split, focus-set predicates | the P0 report extras; every focus set |
| `_skillharm_injected.jsonl` (P0) | SkillHarm attributed recall | the P0 report extras; guards in P1-P3 |

Live arms then confirm what offline analysis predicts. Each plan's overview reports the offline prediction next to
the live result.

## Pre-registered policy decisions

These were open questions in `recall-boundaries.md`. They are fixed here so no plan has to stop and ask:
- **SkillTrustBench `suspicious` stays malicious** in ground truth, exactly as imported. No plan targets `V_*` cells
  specifically. The STB/non-STB split in every report keeps their effect visible.
- **BROKEN and UNVERIFIABLE units stay malicious** in ground truth: an install gate should flag intent. Every report
  shows the validity tiers, so gains on the `intent` tier are never presented as payload detection.
- **Lure-only skills are positives** for an install gate (P5). They are reported separately.

## Execution and cost

- Start each plan in a fresh session with `superpowers:subagent-driven-development`. Do not ask the user to choose an
  execution method; this spec's autonomy rules already answer that.
- Approximate wall time at 96 workers:
  - a full run is about 1 h;
  - a dev arm (about 1,400-2,300 units) is about 8-12 min.

| Plan | Approximate scan wall time |
|---|---|
| P0 | ~1.5 h |
| P1 | ~3 h |
| P2-P5 | ~3-4.5 h each |
| P6 | ~1.2 h |
| P7 | ~4 h |

- Bedrock tokens last about 12 h and are re-minted automatically. An SSO-session expiry needs a human (see Known
  limits).

## Anti-overfitting rules

- Prompts, regexes and allowlists must not contain unit directory names, hostnames, file names, numeric constants or
  distinctive phrases copied from dataset units. Describe *classes* of behaviour. The final reviewer checks the diff
  for this.
- Do not tune any rule against units of a single corpus generator, for example SkillHarm's white-fill PDFs. Evidence
  must include at least two corpora, or the plan's report must say it does not.
- Never use `_boundary_labels.jsonl` `pretext` values to select units: they reproduce only 63%. `label_validity`,
  `carrier` and `purpose_fit` may be used. `harm_explicitness` may be used as a range only.
- Report STB and non-STB recall separately in every claim. The report does this after P0.

## Known limits that no plan can fix here

- The benign corpus has 6 PDFs, all in one unit. Precision of PDF and hidden-text rules is **unmeasured** and must be
  reported as such.
- The SSO session needs a human `aws sso login` when it expires. Plans stop cleanly (autonomy rule 5); they do not
  work around it.
