"""Same-day arm comparison with the spec's pre-registered dev verdicts.

Verdict rules are copied from "Decision rules" in
docs/superpowers/specs/2026-10-29-recall-improvement-program.md; keep them in sync.
Do not tune them here.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field
from statistics import mean
from typing import Literal

import click

from .health import check_health
from .report.extras import load_extras

TP_FLOOR = 3
FP_FLOOR = 2
RECALL_FP_PER_TP = 8


@dataclass
class ArmsResult:
    kind: str
    control: list[str]
    treatment: list[str]
    control_mean: dict[str, float]
    treatment_mean: dict[str, float]
    n_tp: int
    n_fp: int
    d_tp: float
    d_fp: float
    attributed_recall: tuple[float | None, float | None]
    verdict: str
    reasons: list[str] = field(default_factory=list)
    replicates: tuple[int, int] = (0, 0)


def _counts(con, run_id: str) -> dict[str, int]:
    got = dict(
        con.execute(
            "SELECT outcome, count(*) FROM evaluation WHERE run_id = ? GROUP BY outcome",
            [run_id],
        ).fetchall()
    )
    return {k: got.get(k, 0) for k in ("TP", "FP", "FN", "TN")}


def _check_runs(con, control: list[str], treatment: list[str]) -> None:
    if not control or not treatment:
        raise SystemExit("need at least one control and one treatment run")
    all_ids = [*control, *treatment]
    known = {r[0] for r in con.execute("SELECT run_id FROM runs").fetchall()}
    missing = [r for r in all_ids if r not in known]
    if missing:
        raise SystemExit(f"unknown run id(s): {', '.join(missing)}")
    sets = {
        r: {
            x[0]
            for x in con.execute("SELECT unit_path FROM units WHERE run_id = ?", [r]).fetchall()
        }
        for r in all_ids
    }
    ref = all_ids[0]
    for r in all_ids[1:]:
        if sets[r] != sets[ref]:
            diff = len(sets[r] ^ sets[ref])
            raise SystemExit(
                f"runs {ref} and {r} cover different unit sets"
                f" ({len(sets[ref])} vs {len(sets[r])} units; {diff} units differ)"
            )


def _mean_attributed(con, run_ids: list[str]) -> float | None:
    vals = []
    for r in run_ids:
        a = load_extras(con, r, None).skillharm_attributed
        if a is None or a.attributed_recall is None:
            return None
        vals.append(a.attributed_recall)
    return mean(vals)


def compare_arms(
    con, control: list[str], treatment: list[str], kind: Literal["recall", "fp"] = "recall"
) -> ArmsResult:
    if kind not in ("recall", "fp"):
        raise SystemExit(f"unknown kind {kind!r}; expected 'recall' or 'fp'")
    _check_runs(con, control, treatment)
    cc = [_counts(con, r) for r in control]
    tc = [_counts(con, r) for r in treatment]

    def arm_mean(cs):
        return {k: mean(c[k] for c in cs) for k in ("TP", "FP", "FN", "TN")}

    cm, tm = arm_mean(cc), arm_mean(tc)
    tps, fps = [c["TP"] for c in cc], [c["FP"] for c in cc]
    n_tp = max(TP_FLOOR, max(tps) - min(tps))
    n_fp = max(FP_FLOOR, max(fps) - min(fps))
    d_tp = tm["TP"] - cm["TP"]
    d_fp = tm["FP"] - cm["FP"]
    att = (_mean_attributed(con, control), _mean_attributed(con, treatment))

    reasons: list[str] = []
    if len(control) == 1:
        reasons.append(
            f"1 replicate in control: noise floors fall back to N_TP={TP_FLOOR}, N_FP={FP_FLOOR}"
        )

    failed = False

    def fail(msg: str) -> None:
        nonlocal failed
        failed = True
        reasons.append(msg)

    if kind == "recall":
        if not d_tp >= 2 * n_tp:
            fail(f"dTP {d_tp:+.1f} < 2*N_TP = {2 * n_tp}")
        allowed = max(n_fp, d_tp / RECALL_FP_PER_TP)
        if not d_fp <= allowed:
            fail(
                f"dFP {d_fp:+.1f} > max(N_FP={n_fp}, dTP/8={d_tp / RECALL_FP_PER_TP:.2f})"
                f" = {allowed:.2f}: FP cost exceeds 8:1 extra TPs per extra FP"
            )
        for r in treatment:
            problems = check_health(con, r)
            if problems:
                fail(f"treatment run {r} failed health: {'; '.join(problems)}")
        if att[0] is None or att[1] is None:
            reasons.append("attributed recall n/a (labels missing); not a recall-kind condition")
    else:
        if not -d_fp >= 2 * n_fp:
            fail(f"-dFP {-d_fp:+.1f} < 2*N_FP = {2 * n_fp}")
        if not -d_tp <= -d_fp / 2:
            fail(f"-dTP {-d_tp:+.1f} > (-dFP)/2 = {-d_fp / 2:.2f}: TP loss too large for FP gain")
        if att[0] is None or att[1] is None:
            fail("attributed recall is unavailable (SkillHarm labels missing); cannot confirm")
        elif att[1] < att[0]:
            fail(f"attributed recall dropped: {att[0]:.4f} -> {att[1]:.4f}")

    return ArmsResult(
        kind=kind,
        control=list(control),
        treatment=list(treatment),
        control_mean=cm,
        treatment_mean=tm,
        n_tp=n_tp,
        n_fp=n_fp,
        d_tp=d_tp,
        d_fp=d_fp,
        attributed_recall=att,
        verdict="REJECT" if failed else "PROMISING",
        reasons=reasons,
        replicates=(len(control), len(treatment)),
    )


def _rates(m: dict[str, float]) -> tuple[str, str]:
    pos, pred = m["TP"] + m["FN"], m["TP"] + m["FP"]
    return (f"{m['TP'] / pos:.4f}" if pos else "n/a", f"{m['TP'] / pred:.4f}" if pred else "n/a")


def _fmt_att(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.4f}"


def _rep(n: int) -> str:
    return f"{n} replicate" + ("" if n == 1 else "s")


def render_markdown(r: ArmsResult) -> str:
    out = [f"# Arm comparison ({r.kind})", ""]
    out += [
        f"- control: {', '.join(r.control)} ({_rep(r.replicates[0])})",
        f"- treatment: {', '.join(r.treatment)} ({_rep(r.replicates[1])})",
        "",
        "| arm | replicates | TP | FP | FN | TN | recall | precision | attributed recall |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, m, n, a in (
        ("control", r.control_mean, r.replicates[0], r.attributed_recall[0]),
        ("treatment", r.treatment_mean, r.replicates[1], r.attributed_recall[1]),
    ):
        rec, prec = _rates(m)
        out.append(
            f"| {name} | {_rep(n)} | {m['TP']:.1f} | {m['FP']:.1f} | {m['FN']:.1f} |"
            f" {m['TN']:.1f} | {rec} | {prec} | {_fmt_att(a)} |"
        )
    out += [
        "",
        f"- noise floor (control, {_rep(r.replicates[0])}): N_TP = {r.n_tp}, N_FP = {r.n_fp}",
        f"- dTP = {r.d_tp:+.1f}, dFP = {r.d_fp:+.1f}",
    ]
    if r.reasons:
        out += ["", "Reasons:"] + [f"- {x}" for x in r.reasons]
    out += ["", f"VERDICT: {r.verdict}", ""]
    return "\n".join(out)


@click.command()
@click.argument("db_path", metavar="DB")
@click.option("--control", required=True, help="Comma-separated control run ids.")
@click.option("--treatment", required=True, help="Comma-separated treatment run ids.")
@click.option("--kind", type=click.Choice(["recall", "fp"]), default="recall", show_default=True)
@click.option("-o", "--output", "output", type=click.Path(), default=None)
def main(db_path, control, treatment, kind, output):
    """Compare same-day control and treatment arms and print the pre-registered verdict."""
    import duckdb

    con = duckdb.connect(db_path, read_only=True)
    try:
        r = compare_arms(
            con,
            [x.strip() for x in control.split(",") if x.strip()],
            [x.strip() for x in treatment.split(",") if x.strip()],
            kind,
        )
    finally:
        con.close()
    text = render_markdown(r)
    click.echo(text)
    if output:
        pathlib.Path(output).write_text(text)
