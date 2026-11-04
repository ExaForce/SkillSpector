"""Sequential futility screen: scan a dev set in stratified batches and stop early to reject.

Pre-registered rule (docs/superpowers/specs/2026-10-29-recall-improvement-program.md,
"Decision rules"; keep in sync, do not tune here). After each batch, treatment is paired
with same-day control on every unit judged so far:

- recall kind: ``d_i = (tp_t - tp_c) - 8·(fp_t - fp_c)``, allowance ``16·n/N``;
- fp kind:     ``d_i = 2·(tp_t - tp_c) - (fp_t - fp_c)``, allowance 0;
- ``D = Σ d_i``, ``SE = sd(d, ddof=1)·sqrt(n)`` (0 when n < 2);
- FUTILE iff at least 3 batches are in and ``D + 2.8·SE < -allowance``. It never stops
  for success: a candidate that passes goes on to the standard dev verdict (``arms``).

``tp``/``fp`` are a unit's TP/FP indicators, averaged over the runs on that side that hold
it; a unit that is ERROR in any run on either side is left out of ``d`` and counted apart.
``n`` is the number of units in ``d`` and ``N`` the size of the units file.

Scans run the ``benchmark`` command as a subprocess, one run per batch and arm, so scan
semantics stay in one place. A scan whose log stops growing for ``--stall-seconds`` is
killed (whole process group) and resumed with ``--run-id``, at most twice.
"""

from __future__ import annotations

import json
import math
import os
import pathlib
import random
import re
import signal
import subprocess
import time
from dataclasses import asdict, dataclass
from statistics import mean, stdev

import click

from .arms import FP_FLOOR, RECALL_FP_PER_TP, parse_replicates
from .main import read_units_file

BATCH_SIZE = 150
SEED = 29
Z = 2.8
MIN_BATCHES = 3
FP_WEIGHT = RECALL_FP_PER_TP  # 8: the spec's 8:1 rule
ALLOWANCE = RECALL_FP_PER_TP * FP_FLOOR  # 16: the N_FP >= 2 floor, scaled by n/N
FP_KIND_TP_WEIGHT = 2  # fp kind: -dTP <= (-dFP)/2, i.e. 2·dTP - dFP >= 0
MAX_RESUMES = 2

# The scan command; tests replace it with a fake that never calls an LLM.
BENCHMARK_CMD = ["uv", "run", "benchmark"]


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
) -> Look:
    """One look over ``units`` (every unit scanned so far); see the module docstring."""
    if kind not in ("recall", "fp"):
        raise ValueError(f"unknown kind {kind!r}")
    ds: list[float] = []
    d_tp = d_fp = 0.0
    n_errors = 0
    for u in units:
        c, t = control.get(u), treatment.get(u)
        if c is None or t is None:
            continue
        if c[2] or t[2]:
            n_errors += 1
            continue
        dtp, dfp = t[0] - c[0], t[1] - c[1]
        d_tp += dtp
        d_fp += dfp
        ds.append(dtp - FP_WEIGHT * dfp if kind == "recall" else FP_KIND_TP_WEIGHT * dtp - dfp)
    n = len(ds)
    total = float(sum(ds))
    se = stdev(ds) * math.sqrt(n) if n >= 2 else 0.0
    ucb = total + z * se
    allowance = ALLOWANCE * n / n_total if kind == "recall" else 0.0
    return Look(
        batch=batch,
        n=n,
        n_errors=n_errors,
        d_tp=d_tp,
        d_fp=d_fp,
        D=total,
        se=se,
        ucb=ucb,
        allowance=allowance,
        stop=batch >= min_batches and ucb < -allowance,
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
) -> list[Look]:
    """Looks of a screen replayed on existing full runs, up to and including the first stop."""
    units = [u for b in batches for u in b]
    control = unit_outcomes(con, control_ids, units)
    treatment = unit_outcomes(con, treatment_ids, units)
    looks: list[Look] = []
    seen: list[str] = []
    for k, b in enumerate(batches, 1):
        seen += b
        looks.append(
            judge(control, treatment, seen, n_total, z, batch=k, min_batches=min_batches, kind=kind)
        )
        if looks[-1].stop:
            break
    return looks


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


def render_table(looks: list[Look], scanned: list[int], z: float = Z) -> str:
    """Markdown table, one row per look; ``scanned[i]`` is the units scanned by look i."""
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
            raise SystemExit(
                f"scan failed (exit {rc}) for run {run_id or '(no run id)'}; see {path}"
            )
        return run_id
    raise SystemExit(
        f"scan stalled {MAX_RESUMES + 1} times; giving up on run {run_id or '(no run id)'}"
        f" (logs: {log.parent})"
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


def _open(db: str):
    import duckdb

    return duckdb.connect(db, read_only=True)


def _finish(stopped: Look | None, batches: list[list[str]], n_total: int) -> None:
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
@click.option("--stall-seconds", type=float, default=1200, show_default=True)
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
        if control_ids:
            _refuse_uncovered(con, "control", control_ids, batches)
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
            )
    finally:
        con.close()

    click.echo(
        f"screen {label} ({kind}): {n_total} units in {len(batches)} batches"
        f" of <= {batch_size} (seed {seed}, z {z:g}, min batches {min_batches})"
    )
    if simulate_mode:
        for w in warnings:
            click.echo(f"WARNING: {w}")
        click.echo(render_table(looks, _scanned(batches, len(looks)), z))
        _finish(looks[-1] if looks[-1].stop else None, batches, n_total)
        return

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
        return run_scan(cmd, full_env, log, stall_seconds)

    batch_controls: list[str] = []
    treatments: list[str] = []
    seen: list[str] = []
    stopped: Look | None = None
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
            )
            for w in provenance_warnings(con, c_ids, treatments):
                if w not in manifest["warnings"]:
                    manifest["warnings"].append(w)
                    click.echo(f"WARNING: {w}")
        finally:
            con.close()
        manifest["looks"].append(asdict(look))
        save()
        looks = [Look(**x) for x in manifest["looks"]]
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
