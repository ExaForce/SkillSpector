"""SkillSpector benchmark CLI: two console scripts, ``benchmark`` and ``report``.

``benchmark`` scans a MalSkillBench Dataset tree and records results to DuckDB so
you can measure how well SkillSpector classifies. Each *unit* is scanned
in-process via SkillSpector's LangGraph workflow (one fresh worker process per
scan); the scan -- plus its resolved ground-truth label and SkillSpector's
verdict, issues and components -- is written to DuckDB. ``report`` compares two
runs in a DB into a PR-ready markdown summary.

Usage:
    benchmark /path/to/MalSkillBench/Dataset
    benchmark .../Dataset/Skills/malware --limit 50 --workers 16
    benchmark .../Dataset --no-llm                       # static analysis only
    benchmark .../Dataset -o out.duckdb --run-id abc123   # extend run abc123
    report out.duckdb <run>                    # single-run summary
    report out.duckdb <head> --base <base>     # compare head vs base

(From the repo root without cd: ``uv run --directory benchmark benchmark ...``.)
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import sys
import uuid
from collections.abc import Mapping
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import UTC, datetime
from types import SimpleNamespace

import click
from tqdm import tqdm

from .config import SCAN_TIMEOUT_SECONDS, configure_run, default_workers
from .dataset_handler import discover
from .db import (
    config_snapshot,
    current_git_sha,
    delete_runs,
    open_db,
    print_summary,
    purge_incomplete,
    record_result,
    resolve_run_id,
    run_row_counts,
)
from .models import ScanResult
from .runner import scan_worker
from .utils import quiet_logging


@click.command()
@click.argument("dataset_path", required=False)
@click.option("-o", "--output", help="DuckDB output file (default benchmark_<id>.duckdb)")
@click.option(
    "--from-run",
    help="re-scan the units recorded for an existing run instead of discovering a "
    "DATASET_PATH (omit the positional when using this). Reads the run from the -o "
    "DB and appends the new run there, so it pairs with `report`. Requires -o.",
)
@click.option(
    "--failures-only",
    is_flag=True,
    help="with --from-run, re-scan only that run's FAILED units (false pos/neg, "
    "timeouts, and errors) -- a fast check of whether a change fixes them.",
)
@click.option(
    "--units-file",
    type=click.Path(exists=True, dir_okay=False),
    help="scan only the units listed in this file (one unit_path per line; '#' comments "
    "and blank lines ignored). Works with DATASET_PATH or --from-run; file order is kept. "
    "Cannot be combined with --failures-only.",
)
@click.option(
    "--dataset",
    help="with --from-run, override the dataset path recorded for the source run "
    "(use if the MalSkillBench checkout has moved).",
)
@click.option(
    "--description",
    help="optional free-text note describing this run, stored in the runs table",
)
@click.option(
    "--run-id",
    help="extend an existing run instead of starting a new one: re-scan only "
    "its unfinished units and append into the same run (requires -o pointing "
    "at the DB that holds it). Refused when SKILLSPECTOR_EXA_*, SKILLSPECTOR_MODEL/"
    "PROVIDER, MODEL_OVERRIDE or --units-file differ from what the run recorded. "
    "Default: every invocation is a new run.",
)
@click.option("--no-llm", is_flag=True, help="static analysis only (no LLM)")
@click.option(
    "--categories",
    default="skill,code",
    show_default=True,
    help="comma-separated unit categories to scan (skill, code, prompt). Prompts "
    "are EXCLUDED by default -- they are raw prompt-injection samples, not the "
    "repo config files this tool classifies. Pass --categories skill,code,prompt "
    "to include them.",
)
@click.option(
    "--limit",
    type=int,
    default=0,
    help="cap units PER GROUP (a unit's parent directory, e.g. Skills/malware "
    "vs Skills/benign); 0 = no cap",
)
@click.option(
    "--workers",
    type=click.IntRange(min=1),
    default=None,
    help="concurrent scan processes (default: sized from this machine's RAM and CPUs, "
    "capped at 96). Lower it if the summary reports scans that lost LLM calls.",
)
@click.option(
    "--max-tasks-per-child",
    type=int,
    default=1,
    help="scans per worker process before it is recycled (default 1 = fresh "
    "process per scan, avoids any SkillSpector state leak; raise to amortize "
    "the ~0.8s import cost on fast --no-llm runs)",
)
@click.option(
    "--timeout",
    type=float,
    default=SCAN_TIMEOUT_SECONDS,
    show_default=True,
    help="per-scan timeout seconds",
)
@click.option(
    "--overwrite",
    is_flag=True,
    help="delete the output DB before running (default: append a new run to it)",
)
@click.option(
    "--auth-wait-seconds",
    type=float,
    default=1800,
    show_default=True,
    help="on a mid-run SSO expiry, how long to pause for `aws sso login` "
    "before aborting to a resumable DB",
)
def run(**kwargs: object) -> None:
    """Scan a MalSkillBench Dataset tree and record results to DuckDB.

    DATASET_PATH is a MalSkillBench Dataset dir or any subtree of it. Each *unit*
    is scanned in-process via SkillSpector's LangGraph workflow (one fresh worker
    process per scan) and the scan -- plus its resolved ground-truth label and
    SkillSpector's verdict, issues and components -- is written to DuckDB.

    Each invocation is a new run by default; pass --run-id to extend an existing
    one (re-scan only its unfinished units and append into the same run).

    Instead of a DATASET_PATH, pass --from-run <run_id> to re-scan the units of a
    previous run (optionally --failures-only) -- handy for checking whether a
    change improves the units that previously failed.
    """
    sys.exit(_run_benchmark(SimpleNamespace(**kwargs)))


def _load_run_spec(
    db_path: pathlib.Path, from_run: str, failures_only: bool
) -> tuple[str, str, list[str]]:
    """Read a source run from ``db_path``: returns (run_id, dataset_path, unit_paths).

    ``failures_only`` keeps just the units that didn't get a correct verdict --
    false pos/neg plus timeouts and other errors (outcome FN/FP/ERROR). The unit
    *content* isn't stored in the DB (code/prompt units are materialized at scan
    time), so callers rediscover ``dataset_path`` and filter to these unit_paths.
    """
    import duckdb

    if not db_path.exists():
        raise SystemExit(f"--from-run needs an existing benchmark DB; {db_path} not found")
    con = duckdb.connect(str(db_path), read_only=True)
    try:
        run_id = resolve_run_id(con, from_run)
        dataset_path = con.execute(
            "SELECT dataset_path FROM runs WHERE run_id = ?", [run_id]
        ).fetchone()[0]
        sql = "SELECT unit_path FROM evaluation WHERE run_id = ?"
        if failures_only:
            sql += " AND outcome IN ('FN', 'FP', 'ERROR')"
        paths = [r[0] for r in con.execute(sql, [run_id]).fetchall()]
        return run_id, dataset_path, paths
    finally:
        con.close()


def read_units_file(path: str | os.PathLike) -> list[str]:
    """Read unit_paths, one per line; skip blanks and ``#`` comments; dedupe keeping order."""
    seen: dict[str, None] = {}
    for line in pathlib.Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            seen.setdefault(line, None)
    return list(seen)


def select_units(units: list, wanted: list[str]) -> tuple[list, int]:
    """Pick the units named in ``wanted`` (unit_path), in ``wanted`` order.

    Returns (selected, number of wanted paths not present in ``units``).
    """
    by_path = {u.unit_path: u for u in units}
    selected = [by_path[p] for p in wanted if p in by_path]
    return selected, len(wanted) - len(selected)


def print_units_file_selection(selected: int, missing: int) -> None:
    print(f"--units-file: selected {selected} units ({missing} not found)")


# Env that changes what a scan decides: a resumed run must see exactly what it started with.
# Other recorded env (log level, auth wait, ...) may differ between sessions.
_RESUME_PINNED_PREFIX = "SKILLSPECTOR_EXA_"
_RESUME_PINNED_ENV = frozenset({"SKILLSPECTOR_MODEL", "SKILLSPECTOR_PROVIDER", "MODEL_OVERRIDE"})


def units_file_record(path: str | os.PathLike | None) -> dict | None:
    """``{"path": <resolved path>, "sha256": <hex of its bytes>}``, or None without a file."""
    if not path:
        return None
    p = pathlib.Path(path).resolve()
    return {"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}


def run_config_json(
    environ: Mapping[str, str], git_sha: str, units_file: str | os.PathLike | None
) -> str:
    """``runs.config_json``: :func:`config_snapshot` plus the ``units_file`` record."""
    cfg = json.loads(config_snapshot(environ, git_sha))
    cfg["units_file"] = units_file_record(units_file)
    return json.dumps(cfg)


def _show_env(v: str | None) -> str:
    return "(unset)" if v is None else repr(v)


def _show_units_file(rec: dict | None) -> str:
    return "(none)" if rec is None else f"{rec.get('path')} (sha256 {rec.get('sha256')})"


def resume_config_mismatches(stored_json: str, current_json: str) -> list[str]:
    """What differs between a run's recorded config and this invocation's, as "name: old -> new".

    Compared: env vars named ``SKILLSPECTOR_EXA_*``, ``SKILLSPECTOR_MODEL``,
    ``SKILLSPECTOR_PROVIDER`` and ``MODEL_OVERRIDE`` (unset vs set counts as different), and
    the ``units_file`` record (a config without the key counts as no units file). Nothing
    else (git sha, other env) is compared.
    """
    stored, current = json.loads(stored_json), json.loads(current_json)
    old_env, new_env = stored.get("env") or {}, current.get("env") or {}
    out = [
        f"{k}: {_show_env(old_env.get(k))} -> {_show_env(new_env.get(k))}"
        for k in sorted(set(old_env) | set(new_env))
        if (k.startswith(_RESUME_PINNED_PREFIX) or k in _RESUME_PINNED_ENV)
        and old_env.get(k) != new_env.get(k)
    ]
    old_uf, new_uf = stored.get("units_file"), current.get("units_file")
    if old_uf != new_uf:
        out.append(f"units_file: {_show_units_file(old_uf)} -> {_show_units_file(new_uf)}")
    return out


def verify_resume_config(con, run_id: str, current_json: str) -> None:
    """Refuse (``click.UsageError``) to extend ``run_id`` under different flags or units file.

    A run recorded before ``config_json`` existed cannot be checked: warn and carry on.
    """
    row = con.execute("SELECT config_json FROM runs WHERE run_id = ?", [run_id]).fetchone()
    stored = row[0] if row else None
    if stored is None:
        print(
            f"WARNING: run {run_id} has no recorded config_json; cannot verify that this "
            "resume uses the same SKILLSPECTOR_EXA_* flags, model and --units-file."
        )
        return
    mismatches = resume_config_mismatches(stored, current_json)
    if mismatches:
        raise click.UsageError(
            f"refusing to extend run {run_id}: this invocation differs from what the run "
            "recorded (old -> new):\n  "
            + "\n  ".join(mismatches)
            + "\nRe-export the run's env flags and pass the same --units-file, "
            "or omit --run-id to start a new run."
        )


def _run_benchmark(args: SimpleNamespace) -> int:
    if getattr(args, "units_file", None) and args.failures_only:
        raise click.UsageError("--failures-only cannot be combined with --units-file")
    if bool(args.dataset_path) == bool(args.from_run):
        print("ERROR: pass either a DATASET_PATH or --from-run <run_id> (exactly one)")
        return 2
    if (args.run_id or args.from_run) and not args.output:
        print("ERROR: --run-id/--from-run require -o/--output pointing at the DB they read")
        return 2
    if args.run_id and args.overwrite:
        print("ERROR: --run-id cannot be combined with --overwrite (it would delete the run)")
        return 2
    if args.from_run and args.overwrite:
        print(
            "ERROR: --from-run cannot be combined with --overwrite (it would delete the source run)"
        )
        return 2
    if args.failures_only and not args.from_run:
        print("ERROR: --failures-only only applies with --from-run")
        return 2
    if args.dataset and not args.from_run:
        print("ERROR: --dataset only applies with --from-run")
        return 2

    if args.workers is None:
        args.workers = default_workers()

    gen_id = uuid.uuid4().hex[:12]
    out_path = pathlib.Path(args.output or f"benchmark_{gen_id}.duckdb").resolve()

    if args.from_run:
        source_run, src_dataset, want = _load_run_spec(out_path, args.from_run, args.failures_only)
        root = pathlib.Path(args.dataset).resolve() if args.dataset else pathlib.Path(src_dataset)
        if not root.exists():
            print(
                f"ERROR: dataset for run {source_run} not found at {root} "
                "(use --dataset to point at the checkout)"
            )
            return 2
        print(f"discovering units under {root} ...")
        by_path = {u.unit_path: u for u in discover(root)}
        units = [by_path[p] for p in want if p in by_path]
        missing = len(want) - len(units)
        scope = "failed units" if args.failures_only else "units"
        print(
            f"from run {source_run}: re-scanning {len(units)} {scope}"
            + (f" ({missing} no longer present in the dataset, skipped)" if missing else "")
        )
        if args.description is None:
            args.description = f"recheck of {source_run}" + (
                " (failures)" if args.failures_only else ""
            )
    else:
        root = pathlib.Path(args.dataset_path).resolve()
        if not root.exists():
            print(f"ERROR: {root} does not exist")
            return 2
        print(f"discovering units under {root} ...")
        units = discover(root)
        selected = {c.strip() for c in args.categories.split(",") if c.strip()}
        available = {u.category for u in units}
        unknown = selected - available
        if unknown:
            print(
                f"note: --categories names {sorted(unknown)} not present here "
                f"(found {sorted(available)})"
            )
        dropped = sum(u.category not in selected for u in units)
        units = [u for u in units if u.category in selected]
        if dropped:
            print(f"excluded {dropped} unit(s) outside --categories={args.categories}")

    if getattr(args, "units_file", None):
        units, missing = select_units(units, read_units_file(args.units_file))
        print_units_file_selection(len(units), missing)

    if args.limit:
        per_group: dict[str, int] = {}
        capped = []
        for u in units:
            if per_group.get(u.group, 0) < args.limit:
                per_group[u.group] = per_group.get(u.group, 0) + 1
                capped.append(u)
        print(
            f"limiting to {args.limit}/group: kept {len(capped)} of {len(units)} units "
            f"across {len(per_group)} group(s)"
        )
        units = capped
    if not units:
        if args.from_run:
            print(
                f"nothing to re-scan: run {args.from_run} has no "
                + ("failed units" if args.failures_only else "matching units in the dataset")
                + "."
            )
        else:
            print(
                "No units found: empty/unsupported directory, or everything was filtered "
                f"out by --categories={args.categories}."
            )
        return 1

    by_cat: dict[str, int] = {}
    mal = sum(u.is_malicious for u in units)
    resolved = sum(u.label is not None for u in units)
    for u in units:
        by_cat[u.category] = by_cat.get(u.category, 0) + 1
    print(
        f"found {len(units)} units: {by_cat}  (malicious={mal}, benign={len(units) - mal}, "
        f"fine-label resolved={resolved})"
    )

    if out_path.exists() and args.overwrite:
        out_path.unlink()
        # Drop the sibling write-ahead log too; a stale <db>.wal left behind
        # would otherwise be replayed into the fresh DB on connect.
        (out_path.parent / (out_path.name + ".wal")).unlink(missing_ok=True)

    # Inherited by spawned workers: how long a worker pauses for `aws sso login`.
    os.environ["SKILLSPECTOR_BENCH_AUTH_WAIT"] = str(args.auth_wait_seconds)
    cfg, provider, model, region = configure_run(args.no_llm, args.timeout)

    run_config = run_config_json(os.environ, current_git_sha(), getattr(args, "units_file", None))
    con, done, extending = open_db(out_path, args.run_id)
    if extending:
        run_id = args.run_id
        try:
            verify_resume_config(con, run_id, run_config)
        except click.UsageError:
            con.close()
            raise
        purge_incomplete(con, run_id)
        units_to_scan = [u for u in units if u.unit_path not in done]
        print(
            f"extending run {run_id}: {len(done)} already classified, {len(units_to_scan)} to scan"
        )
    else:
        run_id = gen_id
        print(f"starting run {run_id}")
        con.execute(
            "INSERT INTO runs (run_id, started_at, finished_at, dataset_path, provider, model, "
            "region, use_llm, workers, sample_limit, description, config_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                run_id,
                datetime.now(UTC),
                None,
                str(root),
                provider,
                model,
                region,
                not args.no_llm,
                args.workers,
                args.limit or None,
                args.description,
                run_config,
            ],
        )
        units_to_scan = units

    if not units_to_scan:
        print("nothing to scan: every unit is already classified in this DB.")
        print_summary(con, run_id)
        con.close()
        return 0

    print(
        f"scanning {len(units_to_scan)} units: {args.workers} worker procs, "
        f"{args.max_tasks_per_child} task(s)/child, llm={'off' if args.no_llm else 'on'}"
    )
    aborted = False
    with ProcessPoolExecutor(
        max_workers=args.workers,
        max_tasks_per_child=args.max_tasks_per_child,
        initializer=quiet_logging,
    ) as pool:
        futures = {pool.submit(scan_worker, u, cfg): u for u in units_to_scan}
        for fut in tqdm(as_completed(futures), total=len(units_to_scan), desc="scan", unit="u"):
            u = futures[fut]
            try:
                res = fut.result()
            except Exception as e:  # noqa: BLE001 - record, never abort the run
                res = ScanResult(unit=u, scan_status="error", error_message=repr(e))
            res.unit = u
            record_result(con, run_id, res, args.no_llm)
            if res.scan_status == "auth_failed" and not aborted:
                aborted = True
                pool.shutdown(wait=False, cancel_futures=True)
                break

    con.execute("UPDATE runs SET finished_at = ? WHERE run_id = ?", [datetime.now(UTC), run_id])
    if aborted:
        con.close()
        # Reconstruct the unit-source part of the original command so the resume
        # hint is runnable: --from-run has no positional DATASET_PATH.
        if args.from_run:
            source = f"--from-run {args.from_run}"
            if args.failures_only:
                source += " --failures-only"
            if args.dataset:
                source += f" --dataset {args.dataset}"
        else:
            source = str(root)
        print(
            "\nABORTED: AWS credentials were not restored in time; progress is saved.\n"
            "  Run `aws sso login`, then re-run with --run-id to extend this run:\n"
            f"    {pathlib.Path(sys.argv[0]).name} {source} -o {out_path} "
            f"--run-id {run_id}",
            file=sys.stderr,
        )
        return 3

    print_summary(con, run_id)
    con.close()
    print(f"\nwrote {out_path} (run id {run_id})")
    print(
        "tables: runs, units, classifications, issues, components | view: evaluation\n"
        f'  e.g.  duckdb {out_path.name} "SELECT outcome, count(*) FROM evaluation GROUP BY 1"'
    )
    return 0


@click.command()
@click.argument("db_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("run")
@click.option(
    "--base",
    help="baseline run id to compare RUN against; omit for a single-run summary "
    "(a unique prefix is accepted)",
)
@click.option(
    "-o", "--output", type=click.Path(dir_okay=False), help="write markdown here (default: stdout)"
)
@click.option("--label", help="display name for RUN (default: its description or id)")
@click.option("--base-label", help="display name for the base run")
@click.option(
    "--top",
    type=int,
    default=None,
    help="max regression/fix rows to list, comparison only (default: 25)",
)
@click.option(
    "--split-file",
    type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
    help="TSV of unit_path<TAB>split; adds a per-split section (unlisted units: unassigned)",
)
def report(db_path, run, base, output, label, base_label, top, split_file):
    """Summarize a benchmark run, or compare it against a base run.

    DB_PATH is a benchmark DuckDB and RUN is a run id in it (a unique prefix is
    accepted). Without --base, emit a single-run summary of RUN. With --base
    BASE_RUN, compare RUN (head/candidate) against BASE_RUN (baseline) -- metrics,
    distributions, and the units whose classification changed between them. Paste
    the output into a PR to show the run's results or the improvement.
    """
    import duckdb

    from .report import DEFAULT_TOP, build_report

    con = duckdb.connect(db_path, read_only=True)
    try:
        md = build_report(
            con,
            run,
            base,
            label=label,
            base_label=base_label,
            db_path=db_path,
            generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
            top=DEFAULT_TOP if top is None else top,
            split_file=split_file,
        )
    finally:
        con.close()
    if output:
        pathlib.Path(output).write_text(md, encoding="utf-8")
        click.echo(f"wrote {output}")
    else:
        click.echo(md)


@click.command()
@click.argument("db_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("run_ids", nargs=-1, required=True)
@click.option("-y", "--yes", is_flag=True, help="skip the confirmation prompt (for scripted use)")
def remove_run(db_path, run_ids, yes):
    """Delete one or more runs from a benchmark DuckDB.

    DB_PATH is a benchmark DuckDB and RUN_IDS is one or more run ids in it (a
    unique prefix is accepted). Every row for each run is removed across all of
    its tables (runs, units, classifications, issues, components). Ids that don't
    resolve are skipped with a warning; the rest are shown with their row counts
    and deleted together after one confirmation (bypass with --yes).

    Useful for pruning throwaway local-validation runs before versioning the DB.
    """
    import duckdb

    con = duckdb.connect(db_path)
    try:
        tables = {r[0] for r in con.execute("SHOW TABLES").fetchall()}
        if "runs" not in tables:
            raise SystemExit(f"no benchmark results in {db_path}")

        resolved: dict[str, None] = {}  # resolved run_id -> None, insertion-ordered + deduped
        for ref in run_ids:
            try:
                run_id = resolve_run_id(con, ref)
            except SystemExit:
                # run ids are unique, so the only real miss is an unknown ref.
                click.echo(f"skipping {ref!r}: not found", err=True)
                continue
            resolved.setdefault(run_id, None)

        if not resolved:
            raise SystemExit("no matching runs to delete")

        click.echo(f"about to delete {len(resolved)} run(s) from {db_path}:")
        for run_id in resolved:
            counts = run_row_counts(con, run_id)
            desc = con.execute(
                "SELECT description FROM runs WHERE run_id = ?", [run_id]
            ).fetchone()[0]
            detail = ", ".join(f"{t}={counts[t]}" for t in counts)
            line = f"  {run_id}  ({detail}; total {sum(counts.values())} rows)"
            click.echo(line + (f"  -- {desc}" if desc else ""))

        if not yes:
            click.confirm("proceed?", abort=True)

        delete_runs(con, list(resolved))
        click.echo(f"deleted {len(resolved)} run(s) from {db_path}")
    finally:
        con.close()
