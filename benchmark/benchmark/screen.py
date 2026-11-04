"""Sequential futility screen: scan a dev set in stratified batches and stop early to reject.

Pre-registered rule (docs/superpowers/specs/2026-10-29-recall-improvement-program.md,
"Sequential futility screen"; keep in sync, do not tune here). After each batch, treatment is
paired with same-day control on every unit judged so far (``n`` of the ``N`` units of the units
file). ``tp``/``fp`` are a unit's TP/FP indicators, averaged over the runs on that side that hold
it; a unit that is ERROR in any run on either side is left out and counted apart.

- recall kind (v2, amended 2026-11-04): per judged unit ``dtp = tp_t - tp_c``,
  ``dfp = fp_t - fp_c`` and ``g = dtp - 8·dfp``. For x in {dtp, dfp, g}, the final verdict's
  dev-set total is projected as ``F_x = N·mean(x)`` with
  ``SD_x = sd(x, ddof=1)·½·(sqrt(N(N-n)/n) + sqrt(N(N+n)/n))`` (n/a when n < 2). FUTILE iff
  at least 3 batches are in and either
  - (TP) ``F_dtp + 2.8·SD_dtp < 2·N_TP``, or
  - (FP) ``F_g + 2.8·SD_g < 0`` and ``F_dfp - 2.8·SD_dfp > N_FP``.
  ``N_TP``/``N_FP`` are ``arms``' noise floors from the reused control runs when they hold at
  least 2 replicates (totals restricted to the units file), else the floors 3 and 2.
- fp kind (v1): ``d_i = 2·(tp_t - tp_c) - (fp_t - fp_c)``, ``D = Σ d_i``,
  ``SE = sd(d, ddof=1)·sqrt(n)`` (0 when n < 2); FUTILE iff at least 3 batches are in and
  ``D + 2.8·SE < 0``.

It never stops for success: a candidate that passes goes on to the standard dev verdict
(``arms``).

Scans run the ``benchmark`` command as a subprocess, one run per batch and arm, so scan
semantics stay in one place. A scan whose log stops growing for ``--stall-seconds`` is
killed (whole process group) and resumed with ``--run-id``, at most twice.
"""

from __future__ import annotations

import contextlib
import json
import math
import os
import pathlib
import random
import re
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from statistics import mean, stdev

import click

from .arms import FP_FLOOR, RECALL_FP_PER_TP, TP_FLOOR, noise_floors, parse_replicates
from .main import read_units_file

BATCH_SIZE = 150
SEED = 29
Z = 2.8
MIN_BATCHES = 3
FP_WEIGHT = RECALL_FP_PER_TP  # 8: the spec's 8:1 rule
FP_KIND_TP_WEIGHT = 2  # fp kind: -dTP <= (-dFP)/2, i.e. 2·dTP - dFP >= 0
MAX_RESUMES = 2


# The scan command; tests replace it with a fake that never calls an LLM.
def _default_benchmark_cmd() -> list[str]:
    """The ``benchmark`` console script next to this interpreter (independent of the current
    directory); ``uv run benchmark`` when it is not installed there."""
    script = pathlib.Path(sys.executable).with_name("benchmark")
    return [str(script)] if script.exists() else ["uv", "run", "benchmark"]


BENCHMARK_CMD = _default_benchmark_cmd()


# --- pure parts -------------------------------------------------------------------------------


def strata_for(con, ref_run: str, units: list[str]) -> dict[str, str]:
    """Stratum per unit from ``ref_run``'s evaluation row: ``'benign'`` when not malicious,
    else ``coalesce(behavior, corpus, 'unknown')``; ``'unknown'`` when the run lacks the unit."""
    rows = con.execute(
        "SELECT unit_path, CASE WHEN truth_malicious THEN coalesce(behavior, corpus, 'unknown')"
        " ELSE 'benign' END FROM evaluation WHERE run_id = ?",
        [ref_run],
    ).fetchall()
    got = dict(rows)
    return {u: got.get(u, "unknown") for u in units}


def build_batches(
    units: list[str], strata: dict[str, str], batch_size: int = BATCH_SIZE, seed: int = SEED
) -> list[list[str]]:
    """``ceil(len(units)/batch_size)`` batches of the same stratum mix, no unit repeated.

    Strata in sorted key order; within each, units sorted then shuffled by one shared
    ``Random(seed)``; the concatenation is dealt round-robin (unit ``i`` to batch ``i % B``).
    """
    n_batches = math.ceil(len(units) / batch_size)
    rng = random.Random(seed)
    by_stratum: dict[str, list[str]] = {}
    for u in units:
        by_stratum.setdefault(strata.get(u, "unknown"), []).append(u)
    order: list[str] = []
    for key in sorted(by_stratum):
        members = sorted(by_stratum[key])
        rng.shuffle(members)
        order += members
    batches: list[list[str]] = [[] for _ in range(n_batches)]
    for i, u in enumerate(order):
        batches[i % n_batches].append(u)
    return batches


def unit_outcomes(
    con, run_ids: list[str], units: list[str]
) -> dict[str, tuple[float, float, bool]]:
    """``unit -> (tp, fp, errored)``: TP/FP rates over the ``run_ids`` holding the unit, and
    whether any of them is ERROR. Units no run covers are absent."""
    if not run_ids:
        return {}
    wanted = set(units)
    rows = con.execute(
        "SELECT unit_path, outcome FROM evaluation"
        f" WHERE run_id IN ({', '.join('?' * len(run_ids))})",
        list(run_ids),
    ).fetchall()
    per: dict[str, list[str]] = {}
    for u, outcome in rows:
        if u in wanted:
            per.setdefault(u, []).append(outcome)
    return {
        u: (mean(o == "TP" for o in os_), mean(o == "FP" for o in os_), "ERROR" in os_)
        for u, os_ in per.items()
    }


@dataclass
class Look:
    """One fp-kind look (v1 rule)."""

    batch: int
    n: int  # units in D: judged on both sides, not errored
    n_errors: int  # units left out because a run on either side was ERROR
    d_tp: float
    d_fp: float
    D: float  # the spec's name for the running sum of d_i
    se: float
    ucb: float  # D + z·SE
    allowance: float
    stop: bool


@dataclass
class RecallLook:
    """One recall-kind look (v2 rule). Projections are None when n is 0, SDs and bounds when
    n < 2."""

    batch: int
    n: int  # judged units: on both sides, not errored
    n_errors: int  # units left out because a run on either side was ERROR
    d_tp: float  # Σ dtp over judged units
    d_fp: float  # Σ dfp over judged units
    n_tp: int
    n_fp: int
    f_dtp: float | None
    sd_dtp: float | None
    f_g: float | None
    sd_g: float | None
    f_dfp: float | None
    sd_dfp: float | None
    tp_ucb: float | None  # F_dtp + z·SD_dtp; TP clause: < 2·N_TP
    g_ucb: float | None  # F_g + z·SD_g; FP clause: < 0 ...
    fp_lcb: float | None  # F_dfp - z·SD_dfp; ... and > N_FP
    clause: str | None  # "TP", "FP", "TP+FP": the clauses crossed at this look, else None
    stop: bool  # crossed, and at least min_batches batches are in


def _pairs(control, treatment, units):
    """``(dtp, dfp)`` per judged unit, and the number of units left out as ERROR."""
    out: list[tuple[float, float]] = []
    n_errors = 0
    for u in units:
        c, t = control.get(u), treatment.get(u)
        if c is None or t is None:
            continue
        if c[2] or t[2]:
            n_errors += 1
            continue
        out.append((t[0] - c[0], t[1] - c[1]))
    return out, n_errors


def _project(xs: list[float], n_total: int) -> tuple[float | None, float | None]:
    """``(F, SD)`` of the final dev-set total from the judged units' ``xs`` (see the docstring)."""
    n = len(xs)
    if n == 0:
        return None, None
    if n > n_total:
        raise ValueError(f"{n} judged units exceed the {n_total} units of the units file")
    f = n_total * mean(xs)
    if n < 2:
        return f, None
    big_n = n_total
    factor = 0.5 * (math.sqrt(big_n * (big_n - n) / n) + math.sqrt(big_n * (big_n + n) / n))
    return f, stdev(xs) * factor


def judge(
    control: dict[str, tuple[float, float, bool]],
    treatment: dict[str, tuple[float, float, bool]],
    units: list[str],
    n_total: int,
    z: float = Z,
    *,
    batch: int,
    min_batches: int = MIN_BATCHES,
    kind: str = "recall",
    n_tp: int | None = None,
    n_fp: int | None = None,
) -> Look | RecallLook:
    """One look over ``units`` (every unit scanned so far); see the module docstring.
    ``n_tp``/``n_fp`` (the noise floors) are required for the recall kind."""
    if kind not in ("recall", "fp"):
        raise ValueError(f"unknown kind {kind!r}")
    pairs, n_errors = _pairs(control, treatment, units)
    d_tp = float(sum(p[0] for p in pairs))
    d_fp = float(sum(p[1] for p in pairs))
    n = len(pairs)
    if kind == "recall":
        if n_tp is None or n_fp is None:
            raise ValueError("the recall kind needs n_tp and n_fp")
        f_dtp, sd_dtp = _project([p[0] for p in pairs], n_total)
        f_g, sd_g = _project([p[0] - FP_WEIGHT * p[1] for p in pairs], n_total)
        f_dfp, sd_dfp = _project([p[1] for p in pairs], n_total)
        tp_ucb = g_ucb = fp_lcb = None
        clauses = []
        if n >= 2:
            tp_ucb = f_dtp + z * sd_dtp
            g_ucb = f_g + z * sd_g
            fp_lcb = f_dfp - z * sd_dfp
            if tp_ucb < 2 * n_tp:
                clauses.append("TP")
            if g_ucb < 0 and fp_lcb > n_fp:
                clauses.append("FP")
        clause = "+".join(clauses) or None
        return RecallLook(
            batch=batch,
            n=n,
            n_errors=n_errors,
            d_tp=d_tp,
            d_fp=d_fp,
            n_tp=n_tp,
            n_fp=n_fp,
            f_dtp=f_dtp,
            sd_dtp=sd_dtp,
            f_g=f_g,
            sd_g=sd_g,
            f_dfp=f_dfp,
            sd_dfp=sd_dfp,
            tp_ucb=tp_ucb,
            g_ucb=g_ucb,
            fp_lcb=fp_lcb,
            clause=clause,
            stop=batch >= min_batches and clause is not None,
        )
    ds = [FP_KIND_TP_WEIGHT * dtp - dfp for dtp, dfp in pairs]
    total = float(sum(ds))
    se = stdev(ds) * math.sqrt(n) if n >= 2 else 0.0
    ucb = total + z * se
    return Look(
        batch=batch,
        n=n,
        n_errors=n_errors,
        d_tp=d_tp,
        d_fp=d_fp,
        D=total,
        se=se,
        ucb=ucb,
        allowance=0.0,
        stop=batch >= min_batches and ucb < 0,
    )


def simulate(
    con,
    batches: list[list[str]],
    control_ids: list[str],
    treatment_ids: list[str],
    n_total: int,
    *,
    z: float = Z,
    min_batches: int = MIN_BATCHES,
    kind: str = "recall",
    n_tp: int | None = None,
    n_fp: int | None = None,
) -> list[Look | RecallLook]:
    """Looks of a screen replayed on existing full runs, up to and including the first stop."""
    units = [u for b in batches for u in b]
    control = unit_outcomes(con, control_ids, units)
    treatment = unit_outcomes(con, treatment_ids, units)
    looks: list[Look | RecallLook] = []
    seen: list[str] = []
    for k, b in enumerate(batches, 1):
        seen += b
        looks.append(
            judge(
                control,
                treatment,
                seen,
                n_total,
                z,
                batch=k,
                min_batches=min_batches,
                kind=kind,
                n_tp=n_tp,
                n_fp=n_fp,
            )
        )
        if looks[-1].stop:
            break
    return looks


def _replicate_totals(con, rep: list[str], units: list[str]) -> tuple[int, int]:
    """A replicate's TP and FP totals over ``units`` (sums over its member runs)."""
    wanted = set(units)
    rows = con.execute(
        "SELECT unit_path, outcome FROM evaluation"
        f" WHERE run_id IN ({', '.join('?' * len(rep))}) AND outcome IN ('TP', 'FP')",
        list(rep),
    ).fetchall()
    tp = sum(1 for u, o in rows if o == "TP" and u in wanted)
    fp = sum(1 for u, o in rows if o == "FP" and u in wanted)
    return tp, fp


def noise_floors_for(con, control_runs: str | None, units: list[str]) -> tuple[int, int, str]:
    """``(N_TP, N_FP, source)`` for the recall kind: ``arms``' noise floors over the reused
    control replicates when there are at least 2 (totals restricted to ``units``), else the
    floors ``TP_FLOOR``/``FP_FLOOR``."""
    reps = parse_replicates(control_runs or "")
    if len(reps) >= 2:
        totals = [_replicate_totals(con, rep, units) for rep in reps]
        n_tp, n_fp = noise_floors([t for t, _ in totals], [f for _, f in totals])
        return n_tp, n_fp, f"range over {len(reps)} reused control replicates"
    why = "1 control replicate" if reps else "per-batch control"
    return TP_FLOOR, FP_FLOOR, f"floors: {why}"


def uncovered(con, run_ids: list[str], units: list[str]) -> int:
    """How many of ``units`` none of ``run_ids`` has an evaluation row for."""
    return len(set(units) - set(unit_outcomes(con, run_ids, units)))


def provenance_warnings(con, control_ids: list[str], treatment_ids: list[str]) -> list[str]:
    """Warnings when the arms' runs started on different UTC dates or recorded different git shas."""

    def info(ids: list[str]) -> tuple[set[str], set[str]]:
        dates, shas = set(), set()
        for rid in ids:
            row = con.execute(
                "SELECT started_at, config_json FROM runs WHERE run_id = ?", [rid]
            ).fetchone()
            if row is None:
                continue
            if row[0] is not None:
                dates.add(row[0].date().isoformat())
            sha = json.loads(row[1]).get("git_sha") if row[1] else None
            if sha:
                shas.add(sha)
        return dates, shas

    (cd, cs), (td, ts) = info(control_ids), info(treatment_ids)
    out = []
    if len(cd | td) > 1:
        out.append(
            f"control started {', '.join(sorted(cd))} but treatment {', '.join(sorted(td))};"
            " the protocol compares same-day arms"
        )
    if len(cs | ts) > 1:
        out.append(f"control git sha {', '.join(sorted(cs))} but treatment {', '.join(sorted(ts))}")
    return out


def _num(x: float | None, fmt: str) -> str:
    return "n/a" if x is None else format(x, fmt)


def render_table(looks: list[Look] | list[RecallLook], scanned: list[int], z: float = Z) -> str:
    """Markdown table, one row per look; ``scanned[i]`` is the units scanned by look i."""
    if looks and isinstance(looks[0], RecallLook):
        return _render_recall(looks, scanned, z)
    out = [
        f"| batch | units scanned | n judged | errors | dTP | dFP | D | SE | D+{z:g}·SE"
        " | -allowance | stop |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for look, m in zip(looks, scanned, strict=True):
        out.append(
            f"| {look.batch} | {m} | {look.n} | {look.n_errors} | {look.d_tp:+.1f} |"
            f" {look.d_fp:+.1f} | {look.D:+.1f} | {look.se:.2f} | {look.ucb:+.2f} |"
            f" {-look.allowance:.2f} | {'FUTILE' if look.stop else 'no'} |"
        )
    return "\n".join(out)


def _render_recall(looks: list[RecallLook], scanned: list[int], z: float) -> str:
    n_tp, n_fp = looks[0].n_tp, looks[0].n_fp
    out = [
        f"| batch | units scanned | n judged | errors | dTP | dFP | F_dTP ± SD"
        f" | F_dTP+{z:g}·SD (TP: < 2·N_TP = {2 * n_tp}) | F_g+{z:g}·SD_g (FP: < 0)"
        f" | F_dFP-{z:g}·SD (FP: > N_FP = {n_fp}) | stop |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for look, m in zip(looks, scanned, strict=True):
        out.append(
            f"| {look.batch} | {m} | {look.n} | {look.n_errors} | {look.d_tp:+.1f} |"
            f" {look.d_fp:+.1f} | {_num(look.f_dtp, '+.1f')} ± {_num(look.sd_dtp, '.1f')} |"
            f" {_num(look.tp_ucb, '+.1f')} | {_num(look.g_ucb, '+.1f')} |"
            f" {_num(look.fp_lcb, '+.1f')} | {f'FUTILE ({look.clause})' if look.stop else 'no'} |"
        )
    return "\n".join(out)


def _scanned(batches: list[list[str]], k: int) -> list[int]:
    return [sum(len(b) for b in batches[:i]) for i in range(1, k + 1)]


# --- orchestration ----------------------------------------------------------------------------

_STARTED = re.compile(r"^(?:starting|extending) run ([^\s:]+)", re.M)
_WROTE = re.compile(r"^wrote .* \(run id (\S+)\)$", re.M)


def _kill_group(proc: subprocess.Popen) -> None:
    """Kill the scan and every process it spawned (``uv`` -> python -> pool workers)."""
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        os.killpg(proc.pid, signal.SIGKILL)  # stragglers left in the group, or a stuck leader
    except ProcessLookupError:
        pass  # the whole group is gone
    proc.wait()


def _raise_exit(signum, frame):
    raise SystemExit(128 + signum)


@contextlib.contextmanager
def _exit_on_signals():
    """SIGTERM/SIGHUP raise ``SystemExit`` so ``_watch``'s ``finally`` kills the scan's process
    group (it runs in its own session, so the terminal's signals never reach it)."""
    old = {s: signal.signal(s, _raise_exit) for s in (signal.SIGTERM, signal.SIGHUP)}
    try:
        yield
    finally:
        for s, h in old.items():
            signal.signal(s, h)


class ScanFailed(SystemExit):
    """A scan that failed or stalled out; ``run_id`` is the run it started, if its log said."""

    def __init__(self, message: str, run_id: str | None):
        super().__init__(message)
        self.run_id = run_id


def _watch(cmd: list[str], env: dict[str, str], log: pathlib.Path, stall_seconds: float):
    """Run ``cmd`` with output streamed to ``log``; returns its exit code, or None if it
    stalled (``log`` did not grow for ``stall_seconds``) and was killed."""
    poll = min(1.0, stall_seconds / 4)
    with log.open("wb") as fh:
        proc = subprocess.Popen(
            cmd, stdout=fh, stderr=subprocess.STDOUT, env=env, start_new_session=True
        )
        try:
            size, grew = -1, time.monotonic()
            while True:
                try:
                    return proc.wait(timeout=poll)
                except subprocess.TimeoutExpired:
                    pass
                now_size = log.stat().st_size
                if now_size != size:
                    size, grew = now_size, time.monotonic()
                elif time.monotonic() - grew >= stall_seconds:
                    _kill_group(proc)
                    return None
        finally:
            if proc.poll() is None:
                _kill_group(proc)


def run_scan(
    base_cmd: list[str], env: dict[str, str], log: pathlib.Path, stall_seconds: float
) -> str:
    """Run one ``benchmark`` scan to completion and return its run id; on a stall, resume it
    with ``--run-id`` (at most ``MAX_RESUMES`` times), then give up naming the run."""
    run_id: str | None = None
    for attempt in range(MAX_RESUMES + 1):
        path = log if attempt == 0 else log.with_suffix(f".retry{attempt}.log")
        cmd = base_cmd + (["--run-id", run_id] if run_id else [])
        rc = _watch(cmd, env, path, stall_seconds)
        text = path.read_text(errors="replace")
        if run_id is None:
            m = _STARTED.search(text)
            run_id = m.group(1) if m else None
        if rc is None:
            click.echo(
                f"WARNING: scan stalled ({stall_seconds:g}s without output; log {path});"
                f" killed run {run_id or '(no run id yet)'}"
            )
            continue
        wrote = _WROTE.search(text)
        run_id = wrote.group(1) if wrote else run_id
        if rc != 0 or run_id is None:
            raise ScanFailed(
                f"scan failed (exit {rc}) for run {run_id or '(no run id)'}; see {path}", run_id
            )
        return run_id
    raise ScanFailed(
        f"scan stalled {MAX_RESUMES + 1} times; giving up on run {run_id or '(no run id)'}"
        f" (logs: {log.parent})",
        run_id,
    )


def _parse_env(pairs: tuple[str, ...]) -> dict[str, str]:
    out = {}
    for p in pairs:
        k, sep, v = p.partition("=")
        if not sep or not k:
            raise click.BadParameter(f"expected K=V, got {p!r}")
        out[k] = v
    return out


def _slug(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", label).strip("-") or "screen"


def _flat(spec: str | None) -> list[str]:
    return [r for rep in parse_replicates(spec or "") for r in rep]


def _refuse_uncovered(con, side: str, ids: list[str], batches: list[list[str]]) -> None:
    known = {r for (r,) in con.execute("SELECT run_id FROM runs").fetchall()}
    missing = [r for r in ids if r not in known]
    if missing:
        raise SystemExit(f"unknown {side} run id(s): {', '.join(missing)}")
    units = [u for b in batches for u in b]
    gaps = [(k, uncovered(con, ids, b)) for k, b in enumerate(batches, 1)]
    total = sum(n for _, n in gaps)
    if total:
        detail = ", ".join(f"batch {k}: {n}" for k, n in gaps if n)
        raise SystemExit(
            f"{side} runs {'+'.join(ids)} do not cover {total} of {len(units)} units ({detail});"
            " they must hold every unit of the units file (same units file, same day)"
        )


def _extra_units(con, ids: list[str], units: set[str]) -> int:
    """Number of distinct units held by the runs ``ids`` that are not in ``units``."""
    marks = ",".join("?" * len(ids))
    rows = con.execute(
        f"SELECT DISTINCT unit_path FROM classifications WHERE run_id IN ({marks})", ids
    ).fetchall()
    return sum(1 for (u,) in rows if u not in units)


def _open(db: str):
    import duckdb

    return duckdb.connect(db, read_only=True)


def _finish(stopped: Look | RecallLook | None, batches: list[list[str]], n_total: int) -> None:
    if stopped:
        click.echo(
            f"SCREEN: FUTILE at batch {stopped.batch}"
            f" ({_scanned(batches, stopped.batch)[-1]} units)"
        )
    else:
        click.echo(f"SCREEN: PASSED ({n_total} units)")


@click.command()
@click.argument("dataset_path", type=click.Path(exists=True, file_okay=False))
@click.option("--db", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--units-file", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--ref-run", required=True, help="run whose evaluation rows give the strata")
@click.option("--label", required=True, help="names the screen dir and the scans' descriptions")
@click.option("--kind", type=click.Choice(["recall", "fp"]), default="recall", show_default=True)
@click.option("--treatment-env", multiple=True, metavar="K=V", help="env for treatment scans")
@click.option("--control-env", multiple=True, metavar="K=V", help="env for control scans")
@click.option(
    "--control-runs",
    help="reuse these same-day control runs (replicates by comma, unions by +) instead of"
    " scanning control per batch; they must cover every unit",
)
@click.option("--batch-size", type=click.IntRange(min=1), default=BATCH_SIZE, show_default=True)
@click.option("--seed", type=int, default=SEED, show_default=True)
@click.option("--z", type=float, default=Z, show_default=True)
@click.option("--min-batches", type=click.IntRange(min=1), default=MIN_BATCHES, show_default=True)
@click.option("--stall-seconds", type=click.FloatRange(min=1), default=1200, show_default=True)
@click.option("--auth-wait-seconds", type=float, default=0, show_default=True)
@click.option("--out-dir", type=click.Path(file_okay=False), default="results/screens")
@click.option(
    "--simulate", "simulate_mode", is_flag=True, help="judge existing full runs; scan nothing"
)
@click.option("--treatment-runs", help="with --simulate: the treatment runs to judge")
def main(
    dataset_path,
    db,
    units_file,
    ref_run,
    label,
    kind,
    treatment_env,
    control_env,
    control_runs,
    batch_size,
    seed,
    z,
    min_batches,
    stall_seconds,
    auth_wait_seconds,
    out_dir,
    simulate_mode,
    treatment_runs,
):
    """Screen a candidate on the units file in stratified batches; stop early only to reject."""
    if simulate_mode and not (control_runs and treatment_runs):
        raise click.UsageError("--simulate needs --control-runs and --treatment-runs")
    if treatment_runs and not simulate_mode:
        raise click.UsageError("--treatment-runs only applies with --simulate")
    units = read_units_file(units_file)
    if not units:
        raise click.UsageError(f"{units_file} lists no units")
    n_total = len(units)
    control_ids = _flat(control_runs)

    con = _open(db)
    try:
        if not con.execute("SELECT 1 FROM runs WHERE run_id = ?", [ref_run]).fetchone():
            raise SystemExit(f"unknown --ref-run {ref_run}")
        batches = build_batches(units, strata_for(con, ref_run, units), batch_size, seed)
        n_tp = n_fp = noise_source = None
        if kind == "recall":
            n_tp, n_fp, noise_source = noise_floors_for(con, control_runs, units)
        extra_warning = None
        if control_ids:
            _refuse_uncovered(con, "control", control_ids, batches)
            extra = _extra_units(con, control_ids, set(units))
            if extra:
                extra_warning = (
                    f"control runs {'+'.join(control_ids)} hold {extra} unit(s) outside the"
                    " units file; the screen proceeds, but `arms` will refuse the printed line"
                    " because the control and treatment unit sets differ"
                )
        if simulate_mode:
            treatment_ids = _flat(treatment_runs)
            _refuse_uncovered(con, "treatment", treatment_ids, batches)
            warnings = provenance_warnings(con, control_ids, treatment_ids)
            looks = simulate(
                con,
                batches,
                control_ids,
                treatment_ids,
                n_total,
                z=z,
                min_batches=min_batches,
                kind=kind,
                n_tp=n_tp,
                n_fp=n_fp,
            )
    finally:
        con.close()

    floors = f"; N_TP={n_tp}, N_FP={n_fp} ({noise_source})" if kind == "recall" else ""
    click.echo(
        f"screen {label} ({kind}): {n_total} units in {len(batches)} batches"
        f" of <= {batch_size} (seed {seed}, z {z:g}, min batches {min_batches}){floors}"
    )
    if extra_warning:
        click.echo(f"WARNING: {extra_warning}")
    if simulate_mode:
        for w in warnings:
            click.echo(f"WARNING: {w}")
        click.echo(render_table(looks, _scanned(batches, len(looks)), z))
        _finish(looks[-1] if looks[-1].stop else None, batches, n_total)
        return

    with _exit_on_signals():
        _run_screen(
            dataset=str(pathlib.Path(dataset_path).resolve()),
            db=str(pathlib.Path(db).resolve()),
            label=label,
            kind=kind,
            batches=batches,
            n_total=n_total,
            control_runs=",".join("+".join(rep) for rep in parse_replicates(control_runs))
            if control_runs
            else None,
            control_ids=control_ids,
            env={"control": _parse_env(control_env), "treatment": _parse_env(treatment_env)},
            z=z,
            min_batches=min_batches,
            n_tp=n_tp,
            n_fp=n_fp,
            noise_source=noise_source,
            stall_seconds=stall_seconds,
            auth_wait_seconds=auth_wait_seconds,
            screen_dir=pathlib.Path(out_dir) / _slug(label),
            settings={
                "units_file": str(pathlib.Path(units_file).resolve()),
                "ref_run": ref_run,
                "batch_size": batch_size,
                "seed": seed,
            },
        )


def _run_screen(
    *,
    dataset: str,
    db: str,
    label: str,
    kind: str,
    batches: list[list[str]],
    n_total: int,
    control_runs: str | None,
    control_ids: list[str],
    env: dict[str, dict[str, str]],
    z: float,
    min_batches: int,
    n_tp: int | None,
    n_fp: int | None,
    noise_source: str | None,
    stall_seconds: float,
    auth_wait_seconds: float,
    screen_dir: pathlib.Path,
    settings: dict,
) -> None:
    manifest_path = screen_dir / "manifest.json"
    if manifest_path.exists():
        raise SystemExit(f"{manifest_path} already exists; pick another --label or --out-dir")
    screen_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "label": label,
        "kind": kind,
        "dataset": dataset,
        "db": db,
        **settings,
        "n_total": n_total,
        "z": z,
        "min_batches": min_batches,
        "n_tp": n_tp,
        "n_fp": n_fp,
        "noise_floors": noise_source,
        "control_runs": control_runs,
        "env": env,
        "batches": [],
        "looks": [],
        "warnings": [],
        "result": "running",
    }

    def save() -> None:
        tmp = manifest_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(manifest, indent=2) + "\n")
        tmp.replace(manifest_path)

    for k, b in enumerate(batches, 1):
        name = f"batch-{k:02d}.txt"
        (screen_dir / name).write_text("\n".join(b) + "\n")
        manifest["batches"].append(
            {"batch": k, "file": name, "units": b, "control": None, "treatment": None}
        )
    save()

    def scan(arm: str, k: int) -> str:
        cmd = [
            *BENCHMARK_CMD,
            dataset,
            "-o",
            db,
            "--units-file",
            str((screen_dir / f"batch-{k:02d}.txt").resolve()),
            "--auth-wait-seconds",
            f"{auth_wait_seconds:g}",
            "--description",
            f"{label} {arm} b{k}",
        ]
        log = screen_dir / f"b{k:02d}-{arm}.log"
        click.echo(f"batch {k}/{len(batches)}: scanning {arm} (log {log})")
        full_env = {**os.environ, **env[arm], "PYTHONUNBUFFERED": "1"}
        try:
            return run_scan(cmd, full_env, log, stall_seconds)
        except ScanFailed as e:
            if e.run_id:  # keep the id so the scan can be finished by hand (--run-id)
                entry = manifest["batches"][k - 1]
                if arm == "control":
                    entry["control"] = [e.run_id]
                else:
                    entry["treatment"] = e.run_id
                entry["incomplete"] = arm
                save()
            raise

    batch_controls: list[str] = []
    treatments: list[str] = []
    seen: list[str] = []
    stopped: Look | RecallLook | None = None
    look_cls = RecallLook if kind == "recall" else Look
    for k, b in enumerate(batches, 1):
        entry = manifest["batches"][k - 1]
        if control_runs:
            entry["control"] = control_ids
        else:
            batch_controls.append(scan("control", k))
            entry["control"] = [batch_controls[-1]]
            save()
        treatments.append(scan("treatment", k))
        entry["treatment"] = treatments[-1]
        save()
        seen += b
        con = _open(db)
        try:
            c_ids = control_ids or batch_controls
            look = judge(
                unit_outcomes(con, c_ids, seen),
                unit_outcomes(con, treatments, seen),
                seen,
                n_total,
                z,
                batch=k,
                min_batches=min_batches,
                kind=kind,
                n_tp=n_tp,
                n_fp=n_fp,
            )
            for w in provenance_warnings(con, c_ids, treatments):
                if w not in manifest["warnings"]:
                    manifest["warnings"].append(w)
                    click.echo(f"WARNING: {w}")
        finally:
            con.close()
        manifest["looks"].append(asdict(look))
        save()
        looks = [look_cls(**x) for x in manifest["looks"]]
        click.echo(render_table(looks, _scanned(batches, k), z))
        if look.stop:
            stopped = look
            break

    manifest["result"] = "FUTILE" if stopped else "PASSED"
    save()
    _finish(stopped, batches, n_total)
    if not stopped:
        control_spec = control_runs or "+".join(batch_controls)
        click.echo(f"arms: --control {control_spec} --treatment {'+'.join(treatments)}")
