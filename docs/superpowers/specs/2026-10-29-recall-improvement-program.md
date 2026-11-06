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
- both treatment replicates pass `health` (a union replicate pooled over its member runs, as one run).

Otherwise the verdict is `REJECT`. `uv run arms` computes this.

**Health threshold (amended 2026-11-04, user decision, before any P5 run).** From P5 onward a run (or a pooled union
replicate) passes the dropped-call check of `health` when at most **10%** of its scans dropped an LLM call (was 5%;
`benchmark/benchmark/health.py` `MAX_DROPPED_FRACTION`). It applies to control and treatment alike, and to the full
acceptance runs. Reason: on 2026-11-04 every P4 dev run dropped 6.6–9.4% (controls included), so the 5% clause made
every candidate unpromotable regardless of its effect. P0–P4 verdicts were made at 5% and are not re-judged; re-running
`arms` on their runs now reports them against 10%.

**Dev verdict for an FP-reducing candidate:** `PROMISING` when all three hold:
- `−ΔFP ≥ 2·N_FP`;
- `−ΔTP ≤ (−ΔFP) / 2`;
- SkillHarm attributed recall does not drop.

**Iteration budget:** at most **5** candidates per plan. A candidate is one flag setting or prompt variant. Pick the
candidate with the highest `ΔTP − 8·ΔFP` among the PROMISING ones. If none is PROMISING after 5, the plan's verdict is
REJECTED. Record that and still produce the overview.

### Sequential futility screen (pre-registered 2026-11-04, amended 2026-11-04)

A candidate is screened with `uv run screen` before its full dev replicates. The screen scans the dev set in stratified
batches (never repeating a unit), pairs treatment with same-day control on the units judged so far, and stops only to
reject.

- Constants, used verbatim:
  - batch size 150;
  - seed 29;
  - FP weight 8 (the spec's 8:1 rule);
  - minimum batches before any stop: 3;
  - z = 2.8 (one-sided per look, about 0.26%).
- Per-unit paired differences: `tp`/`fp` are the unit's TP/FP indicators. With several runs on a side, they are means
  over that side's runs that contain the unit. A unit whose outcome is ERROR in any run on either side is excluded and
  counted separately.
- Recall-raising candidates (`--kind recall`, the default) use the v2 rule below.
- FP-reducing candidates (`--kind fp`, mirroring `arms --kind`). The spec's rule needs `−ΔTP ≤ (−ΔFP)/2`, that is
  `2·ΔTP − ΔFP ≥ 0`.
  - The per-unit score is `d_i = 2·(tp_t − tp_c) − (fp_t − fp_c)`, and the allowance is 0.
  - `D = Σ d_i` over the n judged units so far; `SE = sd(d, ddof=1)·sqrt(n)`, or 0 when n < 2.
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
- A union replicate's health is pooled over its member runs: scans, dropped calls and ERRORs summed, semantic issues
  counted over all members, the median run_time over the union's scans, and the LLM checks applied if any member used
  the LLM. It is judged exactly as the one full run it stands in for.
- Control runs are reused only from the same day, tree and dev set. The screen refuses reused control replicates
  unless each one covers the whole units file as the union of its members, and no replicate's members overlap.
- The screen never accepts.

**Amended 2026-11-04, before any live screen: recall-kind rule v2.** The rule and its acceptance criteria were written
before any v2 replay was computed. All criteria passed, so v2 replaced v1 for `--kind recall`. v1 (`D + 2.8·SE <
−16·n/N` on `d = Δtp − 8·Δfp`) tested only net 8:1-weighted harm: it never stopped null or weak candidates, and it had
no finite-population or replicate-2 modelling, so its SE kept growing as n approached N.

Rule (v2), verbatim from the pre-registration:
- Inputs at look k (after batch k):
  - `N`: units in the units file.
  - `n`: judged units (covered by both sides, with no ERROR on either side).
  - Per judged unit j:
    - `dtp_j = tp_T(j) − mean_C tp(j)` and `dfp_j = fp_T(j) − mean_C fp(j)`, where T is the screen's treatment
      run(s);
    - `g_j = dtp_j − 8·dfp_j`.
  - Noise floors, as `arms` computes them:
    - If the reused control runs are ≥ 2 complete replicates, `N_TP = max(3, range of TP totals)` and
      `N_FP = max(2, range of FP totals)`.
    - Otherwise (per-batch control, or 1 control), use the floors `N_TP = 3` and `N_FP = 2`. The floors are the
      smallest the final verdict can use, so they are conservative for futility. *(Amended below: this holds for the
      TP clause only, and the FP clause is off in floors mode.)*
- Projection of the final verdict quantities. The final verdict is the mean of 2 treatment replicates minus the
  control mean, as dev-set totals.
  - For x in {dtp, dfp, g}:
    - `F_x = N·mean(x)`;
    - `SD_x = sd(x)·½·(sqrt(N(N−n)/n) + sqrt(N(N+n)/n))`.
  - `SD_x` adds the replicate-1 prediction error for the unscanned units and the replicate-2 prediction error,
    treating them as perfectly correlated. Units are modelled as iid; persistent per-unit effects make this
    conservative.
- Stop (FUTILE) iff `k ≥ 3` and either of:
  - (TP) `F_dtp + z·SD_dtp < 2·N_TP`;
  - (FP) `F_g + z·SD_g < 0` **and** `F_dfp − z·SD_dfp > N_FP`.

  with `z = 2.8`. It never stops for success. Batching, seed, batch size, min batches and ERROR handling are
  unchanged.

`uv run screen` takes the replicates' TP/FP totals over the units file (a union replicate sums its members). With
n < 2 it never stops, and the SDs are n/a.

**Floors-mode amendment (2026-11-04, after review, before any live screen).** The floors are conservative for the TP
clause only: a smaller `2·N_TP` makes a TP stop harder, but a smaller `N_FP` makes an FP stop easier. In per-batch
control mode the final verdict's N_FP is the FP range of 2 control replicates (13–14 on P1 and P3), so the floor 2
could stop a candidate that the final verdict would accept. So when the noise floors come from the fallback (fewer than
2 complete reused control replicates, which includes per-batch control), N_FP is unknown and the FP clause is off: only
the TP clause can stop. The screen's header and table say "FP clause off: N_FP unknown". This only removes stops; the
validated 2-reused-control path is unchanged. Recall screens should reuse 2 complete same-day control replicates.

Acceptance criteria (v2 replaces v1 only if all pass):
- A1: no stop in any single-treatment-run replay of a historical dev-PROMISING candidate (P1 gate=confirmed, P2 A,
  P2 B), with PROMISING recomputed by `arms` logic on the same runs.
- A2: synthetic false futility ≤ 5% for clearly PROMISING effects (as pre-registered; see the composite verdicts
  below). A spare same-day control replicate stands in for treatment noise (P3: controls bfcbcbe585e5, 2e6e81859349, spare e89e74415880; P4: controls 54ce3a6bbe59,
  01d373aebd37, spare 92149d37b0d8), with effects injected on random units, 300 draws per scenario:
  - S1: +3·N_TP TPs and 0 FP;
  - S2: +4·N_TP TPs and +(4·N_TP/8 − 1) FPs, meant to be PROMISING on both clauses.
- A3: v2 stops strictly more single-run replays of historical dev-REJECT candidates (P3 A1, P3 A2, P3 B1, P3 B3, P4 A,
  each replicate) than v1.
- A4 (informational): stop rates of control against control and of the S0 null (spare control, no injection).

Results (simulate on existing runs, one treatment run per replay; `arms` verdict as dTP, dFP, N_TP, N_FP):

| candidate | arms verdict | treatment run | v1 stop | v2 stop |
|---|---|---|---|---|
| P1 gate=confirmed (N=1364) | PROMISING (+32.5, +3.0, 3, 13) | 46bf363f7145 | never | never |
| P1 gate=confirmed | PROMISING | 4952d46c49a0 | never | never |
| P2 A doc_text (N=2154) | PROMISING (+37.0, +3.0, 3, 2) | ab0a8478cbe9 | never | never |
| P2 B doc_text+hidden | PROMISING (+37.0, −13.0, 3, 2) | d05bd241b62a | never | never |
| P3 A1 ctx=ssd (N=2112) | REJECT (+18.0, +9.5, 15, 14) | a88091f5b7bc | never | never |
| P3 A1 ctx=ssd | REJECT | df2855f770be | never | never |
| P3 A2 ctx=semantic | REJECT (+5.5, +23.5, 15, 14) | 40a9a3b9c46c | never | b8 (1128 units) |
| P3 A2 ctx=semantic | REJECT | 4d56e7b6db30 | b8 (1128 units) | never |
| P3 B1 if=on | REJECT (+76.0, +31.0, 15, 14) | a9949fa84c95 | never | b13 (1832 units) |
| P3 B1 if=on | REJECT | 2a94f96eb7c8 | never | never |
| P3 B3 prompt-rev | REJECT (+90.0, +28.0, 15, 14) | e8688634c909 | b4 (564 units) | b4 (564 units) |
| P3 B3 prompt-rev | REJECT | 09b9a0110cf8 | never | never |
| P4 A ssd5=on (N=2393) | REJECT (+29.0, +28.5, 23, 2) | daed644651be | never | never |
| P4 A ssd5=on | REJECT | a753a1ba2c6c | b7 (1050 units) | b7 (1050 units) |
| null: P3 spare | REJECT (−0.5, +12.0, 15, 14) | e89e74415880 | never | b14 (1972 units) |
| null: P4 spare | REJECT (+6.5, +16.0, 23, 2) | 92149d37b0d8 | never | b3 (450 units) |
| null: P3 control vs control | REJECT (+15.0, +14.0, 3, 2) | bfcbcbe585e5 | never | never |

The A2 composite verdict is `arms` logic on the spare's own totals plus the injection, against the control mean. It
counts the spare's own drift: the P3 spare is at ΔTP −0.5, ΔFP +12 (N_FP 14), and the P4 spare at ΔTP +6.5, ΔFP +16
(N_FP 2). Totals are over the units file, from `recall.duckdb`.

| base | scenario | N_TP | composite ΔTP, ΔFP vs max(N_FP, ΔTP/8) | composite verdict | v1 stop rate | v2 stop rate |
|---|---|---|---|---|---|---|
| P3 spare e89e74415880 | S1 +3·N_TP TP (+45) | 15 | +44.5 ≥ 30, +12 ≤ max(14, 5.6) | PROMISING | 0/300 | 0/300 |
| P3 spare e89e74415880 | S2 +4·N_TP TP, +(N_TP/2 − 1) FP (+60, +6) | 15 | +59.5, +18 > max(14, 7.4) | REJECT | 0/300 | 0/300 |
| P4 spare 92149d37b0d8 | S1 +3·N_TP TP (+69) | 23 | +75.5, +16 > max(2, 9.4) | REJECT | 0/300 | 0/300 |
| P4 spare 92149d37b0d8 | S2 +4·N_TP TP, +(N_TP/2 − 1) FP (+92, +10) | 23 | +98.5, +26 > max(2, 12.3) | REJECT | 3/300 | 15/300 |

- A1 passes: no PROMISING replay stops.
- A2 passes as pre-registered (no cell above 5%), but only P3 S1 is a PROMISING composite. The false-futility evidence
  is therefore P3 S1 (0/300, an effect 1.5× the TP threshold) plus the A1 replays, all far above their thresholds.
  P3 S2, P4 S1 and P4 S2 are REJECT composites because of the spares' own FP drift. So the 15/300 P4 S2 stops are
  probably correct stops, and the 0/300 cells for P3 S2 and P4 S1 are misses of rejects. No A2 cell tests N_TP at the
  floor or an effect near a threshold.
- A3 passes: v2 stops 4 of 10 reject replays, v1 stops 3.
- A4: v2 stops 2 of 3 null replays (the S0 rows are the two spare-control replays); v1 stops none.

Limitation, from the data: v2 stopped 4 of 10 historical reject replays and 2 of 3 null replays, and no promising
candidate. Any stop saves at least the second treatment replicate. A reject that v2 misses is still caught by the full
dev verdict. `F + z·SD` uses a normal approximation, which can be anti-conservative for sparse effects near the floor
thresholds: a gain concentrated on a few units may barely show by batch 3. The constants are not retuned.

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
