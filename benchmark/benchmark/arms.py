"""Same-day arm comparison with the spec's pre-registered dev verdicts.

Verdict rules are copied from "Decision rules" in
docs/superpowers/specs/2026-10-29-recall-improvement-program.md; keep them in sync.
Do not tune them here.
"""

from __future__ import annotations

import json
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
EXA_PREFIX = "SKILLSPECTOR_EXA_"
UNRECORDED = "unrecorded"


@dataclass
class RunProvenance:
    """What a run recorded about how it ran: display only, never part of the verdict."""

    arm: str
    run_id: str
    git_sha: str | None  # None: no config_json / no git_sha recorded
    exa_env: dict[str, str] | None  # SKILLSPECTOR_EXA_* env; None: unrecorded
    started: str | None  # UTC date, YYYY-MM-DD


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
    provenance: list[RunProvenance] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def parse_replicates(spec: str) -> list[list[str]]:
    """``"a+b,c"`` -> ``[["a", "b"], ["c"]]``: comma separates replicates, ``+`` joins runs."""
    out = []
    for rep in spec.split(","):
        members = [m.strip() for m in rep.split("+") if m.strip()]
        if members:
            out.append(members)
    return out


Replicate = str | list[str]


def _members(rep: Replicate) -> list[str]:
    return [rep] if isinstance(rep, str) else list(rep)


def _label(rep: Replicate) -> str:
    return "+".join(_members(rep))


def _counts(con, run_id: str) -> dict[str, int]:
    got = dict(
        con.execute(
            "SELECT outcome, count(*) FROM evaluation WHERE run_id = ? GROUP BY outcome",
            [run_id],
        ).fetchall()
    )
    return {k: got.get(k, 0) for k in ("TP", "FP", "FN", "TN")}


def _rep_counts(con, rep: Replicate) -> dict[str, int]:
    """A replicate's TP/FP/FN/TN: the sums over its member runs."""
    cs = [_counts(con, r) for r in _members(rep)]
    return {k: sum(c[k] for c in cs) for k in ("TP", "FP", "FN", "TN")}


def _check_runs(con, control: list[Replicate], treatment: list[Replicate]) -> None:
    if not control or not treatment:
        raise SystemExit("need at least one control and one treatment run")
    reps = [*control, *treatment]
    all_ids = [r for rep in reps for r in _members(rep)]
    known = {r[0] for r in con.execute("SELECT run_id FROM runs").fetchall()}
    missing = [r for r in all_ids if r not in known]
    if missing:
        raise SystemExit(f"unknown run id(s): {', '.join(missing)}")
    member_units = {
        r: {
            x[0]
            for x in con.execute("SELECT unit_path FROM units WHERE run_id = ?", [r]).fetchall()
        }
        for r in all_ids
    }
    sets: dict[str, set[str]] = {}
    for rep in reps:
        members = _members(rep)
        seen: set[str] = set()
        for r in members:
            shared = seen & member_units[r]
            if shared:
                raise click.UsageError(
                    f"replicate {_label(rep)}: run {r} shares {len(shared)} unit(s) with an"
                    " earlier member; union members must be disjoint"
                )
            seen |= member_units[r]
        sets[_label(rep)] = seen
    labels = [_label(rep) for rep in reps]
    ref = labels[0]
    for r in labels[1:]:
        if sets[r] != sets[ref]:
            diff = len(sets[r] ^ sets[ref])
            raise SystemExit(
                f"runs {ref} and {r} cover different unit sets"
                f" ({len(sets[ref])} vs {len(sets[r])} units; {diff} units differ)"
            )


def _provenance(con, control: list[Replicate], treatment: list[Replicate]) -> list[RunProvenance]:
    out = []
    for arm, reps in (("control", control), ("treatment", treatment)):
        for r in (m for rep in reps for m in _members(rep)):
            cfg_json, started = con.execute(
                "SELECT config_json, started_at FROM runs WHERE run_id = ?", [r]
            ).fetchone()
            cfg = json.loads(cfg_json) if cfg_json else {}
            env = cfg.get("env")
            out.append(
                RunProvenance(
                    arm=arm,
                    run_id=r,
                    git_sha=cfg.get("git_sha"),
                    exa_env=None
                    if env is None
                    else {k: v for k, v in sorted(env.items()) if k.startswith(EXA_PREFIX)},
                    started=started.date().isoformat() if started else None,
                )
            )
    return out


def _date_warnings(prov: list[RunProvenance]) -> list[str]:
    dates = sorted({p.started for p in prov if p.started})
    if len(dates) <= 1:
        return []
    return [
        f"runs started on different dates ({', '.join(dates)}); the protocol compares same-day arms"
    ]


def _mean_attributed(con, reps: list[Replicate]) -> float | None:
    """Mean over replicates of attributed recall; a union replicate pools its members
    (sum of attributed TPs over sum of SkillHarm units). None if any member lacks labels."""
    vals = []
    for rep in reps:
        att_tp = units = 0
        for r in _members(rep):
            a = load_extras(con, r, None).skillharm_attributed
            if a is None or a.attributed_recall is None:
                return None
            att_tp += a.attributed_tp
            units += a.units
        vals.append(att_tp / units)
    return mean(vals)


def compare_arms(
    con,
    control: list[Replicate],
    treatment: list[Replicate],
    kind: Literal["recall", "fp"] = "recall",
) -> ArmsResult:
    if kind not in ("recall", "fp"):
        raise SystemExit(f"unknown kind {kind!r}; expected 'recall' or 'fp'")
    _check_runs(con, control, treatment)
    cc = [_rep_counts(con, r) for r in control]
    tc = [_rep_counts(con, r) for r in treatment]

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
        for r in (m for rep in treatment for m in _members(rep)):
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

    prov = _provenance(con, control, treatment)
    return ArmsResult(
        kind=kind,
        control=[_label(r) for r in control],
        treatment=[_label(r) for r in treatment],
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
        provenance=prov,
        warnings=_date_warnings(prov),
    )


def _rates(m: dict[str, float]) -> tuple[str, str]:
    pos, pred = m["TP"] + m["FN"], m["TP"] + m["FP"]
    return (f"{m['TP'] / pos:.4f}" if pos else "n/a", f"{m['TP'] / pred:.4f}" if pred else "n/a")


def _fmt_att(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.4f}"


def _rep(n: int) -> str:
    return f"{n} replicate" + ("" if n == 1 else "s")


def _show(v: str | None) -> str:
    return "(unset)" if v is None else repr(v)


def _env_cell(p: RunProvenance, ref: RunProvenance) -> str:
    """``p``'s SKILLSPECTOR_EXA_* env, as a diff against the reference (first control) run."""
    if p.exa_env is None:
        return UNRECORDED
    if p is ref:
        flags = ", ".join(f"{k}={v!r}" for k, v in p.exa_env.items()) or "no EXA flags"
        return f"reference: {flags}"
    if ref.exa_env is None:
        return f"reference {ref.run_id} unrecorded"
    diffs = [
        f"{k}: {_show(ref.exa_env.get(k))} -> {_show(p.exa_env.get(k))}"
        for k in sorted(set(ref.exa_env) | set(p.exa_env))
        if ref.exa_env.get(k) != p.exa_env.get(k)
    ]
    return "; ".join(diffs) or f"same as {ref.run_id}"


def _provenance_lines(r: ArmsResult) -> list[str]:
    if not r.provenance:
        return []
    ref = r.provenance[0]
    out = [
        "",
        f"Run provenance (from runs.config_json; flags relative to the first control, "
        f"{ref.run_id}):",
        "",
        "| arm | run | git sha | started (UTC) | SKILLSPECTOR_EXA_* |",
        "|---|---|---|---|---|",
    ]
    for p in r.provenance:
        out.append(
            f"| {p.arm} | {p.run_id} | {p.git_sha or UNRECORDED} | {p.started or UNRECORDED} |"
            f" {_env_cell(p, ref)} |"
        )
    return out


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
    out += _provenance_lines(r)
    if r.warnings:
        out += [""] + [f"WARNING: {w}" for w in r.warnings]
    if r.reasons:
        out += ["", "Reasons:"] + [f"- {x}" for x in r.reasons]
    out += ["", f"VERDICT: {r.verdict}", ""]
    return "\n".join(out)


@click.command()
@click.argument("db_path", metavar="DB")
@click.option(
    "--control",
    required=True,
    help="Comma-separated control replicates; join runs of one replicate with +.",
)
@click.option(
    "--treatment",
    required=True,
    help="Comma-separated treatment replicates; join runs of one replicate with +.",
)
@click.option("--kind", type=click.Choice(["recall", "fp"]), default="recall", show_default=True)
@click.option("-o", "--output", "output", type=click.Path(), default=None)
def main(db_path, control, treatment, kind, output):
    """Compare same-day control and treatment arms and print the pre-registered verdict."""
    import duckdb

    con = duckdb.connect(db_path, read_only=True)
    try:
        r = compare_arms(
            con,
            parse_replicates(control),
            parse_replicates(treatment),
            kind,
        )
    finally:
        con.close()
    text = render_markdown(r)
    click.echo(text)
    if output:
        pathlib.Path(output).write_text(text)
