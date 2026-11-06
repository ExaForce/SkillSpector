"""Deterministic evaluation sets: a core dev set, focus sets and a dev/holdout split file.

Later recall-improvement plans iterate on these sets and score final acceptance on the
holdout, so every builder is deterministic (sorted inputs, ``random.Random(seed)``).

Core set (``build_core``) = union of
- every annotated malicious unit (``_boundary_labels.jsonl``) present in the run;
- every FP of the run;
- ``n_tn`` (600) TNs sampled per ruling R4:
  strata = corpus x package-size bucket over the run's TN units (``evaluation.corpus``;
  bucket from the per-unit ``components`` row count, ``1`` / ``2-5`` / ``6-20`` / ``21+``,
  the same bucketing as ``report.extras``; units with no components rows go to a
  ``(none)`` stratum with weight 1). 600 is allocated across strata in proportion to
  (stratum TN count x weight), weight 3 for ``6-20`` and ``21+`` (where FPs live), 1
  otherwise, by largest-remainder rounding (ties broken by stratum key order). Each
  stratum is capped at its size and the overflow redistributed by the same rule until
  ``n_tn`` is reached or every TN is taken. Within a stratum the sample is
  ``random.Random(seed)`` over the sorted unit list, strata iterated in sorted key order.

The builders only read the DB; the CLI opens it read-only.
"""

from __future__ import annotations

import pathlib
import random

import click

from .report.extras import _size_bucket
from .report.query import one, rows

DEFAULT_SEED = 29
CORE_TN = 600
OVERSAMPLED_BUCKETS = ("6-20", "21+")
OVERSAMPLE_WEIGHT = 3
FEATURES_FILE = "_boundary_features.jsonl"
LABELS_FILE = "_boundary_labels.jsonl"


def _allocate(sizes: dict, total: int) -> dict:
    """Split ``total`` over strata by weighted size, largest remainder, capped at sizes.

    ``sizes`` maps stratum key -> (count, weight). Ties break by key order.
    """
    alloc = dict.fromkeys(sizes, 0)
    remaining = min(total, sum(n for n, _ in sizes.values()))
    while remaining > 0:
        active = sorted(k for k in sizes if alloc[k] < sizes[k][0])
        weights = {k: sizes[k][0] * sizes[k][1] for k in active}
        total_w = sum(weights.values())
        quotas = {k: remaining * weights[k] / total_w for k in active}
        give = {k: int(quotas[k]) for k in active}
        leftover = remaining - sum(give.values())
        for k in sorted(active, key=lambda k: (-(quotas[k] - give[k]), k))[:leftover]:
            give[k] += 1
        for k in active:
            take = min(give[k], sizes[k][0] - alloc[k])
            alloc[k] += take
            remaining -= take
    return alloc


def _sample_tns(con, run_id: str, n_tn: int, seed: int) -> list[str]:
    tns = rows(
        con,
        "SELECT unit_path, corpus FROM evaluation WHERE run_id = ? AND outcome = 'TN'",
        [run_id],
    )
    counts = {
        r["unit_path"]: r["n"]
        for r in rows(
            con,
            "SELECT unit_path, count(*) AS n FROM components WHERE run_id = ? GROUP BY unit_path",
            [run_id],
        )
    }
    strata: dict[tuple[str, str], list[str]] = {}
    for r in tns:
        key = (r["corpus"] or "", _size_bucket(counts.get(r["unit_path"])))
        strata.setdefault(key, []).append(r["unit_path"])
    sizes = {
        k: (len(v), OVERSAMPLE_WEIGHT if k[1] in OVERSAMPLED_BUCKETS else 1)
        for k, v in strata.items()
    }
    alloc = _allocate(sizes, n_tn)
    rng = random.Random(seed)
    picked: list[str] = []
    for key in sorted(strata):
        picked += rng.sample(sorted(set(strata[key])), alloc[key])
    return picked


def tn_strata(con, run_id: str, units: list[str]) -> dict[tuple[str, str], int]:
    """Count ``units`` per (corpus, size bucket) stratum of the run (for reporting)."""
    corpus = {
        r["unit_path"]: r["corpus"]
        for r in rows(con, "SELECT unit_path, corpus FROM units WHERE run_id = ?", [run_id])
    }
    counts = {
        r["unit_path"]: r["n"]
        for r in rows(
            con,
            "SELECT unit_path, count(*) AS n FROM components WHERE run_id = ? GROUP BY unit_path",
            [run_id],
        )
    }
    out: dict[tuple[str, str], int] = {}
    for u in units:
        key = (corpus.get(u) or "", _size_bucket(counts.get(u)))
        out[key] = out.get(key, 0) + 1
    return dict(sorted(out.items()))


def build_core(
    con,
    run_id: str,
    labels_path: pathlib.Path,
    seed: int = DEFAULT_SEED,
    n_tn: int = CORE_TN,
) -> list[str]:
    """Annotated malicious units + every FP + ``n_tn`` stratified TNs, sorted and unique.

    Annotated units absent from the run are skipped (see ``count_annotated_missing``).
    """
    in_run = {
        r["unit_path"] for r in rows(con, "SELECT unit_path FROM units WHERE run_id = ?", [run_id])
    }
    annotated = {
        r["unit_path"]
        for r in rows(con, "SELECT unit_path FROM read_json_auto(?)", [str(labels_path)])
    } & in_run
    fps = {
        r["unit_path"]
        for r in rows(
            con, "SELECT unit_path FROM evaluation WHERE run_id = ? AND outcome = 'FP'", [run_id]
        )
    }
    return sorted(annotated | fps | set(_sample_tns(con, run_id, n_tn, seed)))


def count_annotated_missing(con, run_id: str, labels_path: pathlib.Path) -> int:
    """Annotated units in ``labels_path`` that the run does not contain (expected 0)."""
    return one(
        con,
        "SELECT count(*) AS n FROM (SELECT DISTINCT unit_path FROM read_json_auto(?)) l"
        " WHERE unit_path NOT IN (SELECT unit_path FROM units WHERE run_id = ?)",
        [str(labels_path), run_id],
    )["n"]


def build_focus(
    con,
    run_id: str,
    sql_where: str,
    cap: int | None,
    seed: int = DEFAULT_SEED,
) -> list[str]:
    """Units of the run matching ``sql_where``, sorted; at most ``cap`` when given.

    ``e`` is the ``evaluation`` view and ``bf`` the dataset's ``_boundary_features.jsonl``
    (NULL columns for benign units). ``sql_where`` is trusted operator input (a CLI
    argument) and is interpolated into the query by design -- never pass untrusted text.
    Over the cap, every malicious match is kept first and benign matches are sampled with
    ``random.Random(seed)`` over the sorted benign list; if malicious matches alone exceed
    the cap they are sampled down to it the same way (so the cap wins).
    """
    dataset = one(con, "SELECT dataset_path FROM runs WHERE run_id = ?", [run_id]).get(
        "dataset_path"
    )
    if not dataset:
        raise ValueError(f"run {run_id} has no dataset_path")
    features = pathlib.Path(dataset) / "Skills" / FEATURES_FILE
    matches = rows(
        con,
        "SELECT DISTINCT e.unit_path, e.truth_malicious FROM evaluation e"
        " LEFT JOIN read_json_auto(?) bf USING (unit_path)"
        f" WHERE e.run_id = ? AND ({sql_where})",
        [str(features), run_id],
    )
    mal = sorted(r["unit_path"] for r in matches if r["truth_malicious"])
    ben = sorted(r["unit_path"] for r in matches if not r["truth_malicious"])
    if cap is None or len(mal) + len(ben) <= cap:
        return sorted(mal + ben)
    rng = random.Random(seed)
    if len(mal) >= cap:
        return sorted(rng.sample(mal, cap))
    return sorted(mal + rng.sample(ben, cap - len(mal)))


def write_splits(all_units, dev_sets, out: pathlib.Path) -> None:
    """Write ``unit_path<TAB>split`` (no header), sorted; ``dev`` if in any dev set else ``holdout``."""
    dev = {u for s in dev_sets for u in s}
    lines = [f"{u}\t{'dev' if u in dev else 'holdout'}\n" for u in sorted(set(all_units))]
    out = pathlib.Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(lines), encoding="utf-8")


def _write_units(path, units: list[str]) -> None:
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{u}\n" for u in units), encoding="utf-8")


def _open_ro(db_path, run: str):
    import duckdb

    con = duckdb.connect(str(db_path), read_only=True)
    if not one(con, "SELECT 1 AS x FROM runs WHERE run_id = ?", [run]):
        con.close()
        raise click.ClickException(f"run {run} not found in {db_path}")
    return con


def _labels_path(con, run: str) -> pathlib.Path:
    dataset = one(con, "SELECT dataset_path FROM runs WHERE run_id = ?", [run]).get("dataset_path")
    if not dataset:
        raise click.ClickException(f"run {run} has no dataset_path")
    return pathlib.Path(dataset) / "Skills" / LABELS_FILE


_db = click.option("--db", "db_path", required=True, type=click.Path(exists=True))
_run = click.option("--run", required=True, help="Run id to select from.")
_seed = click.option("--seed", type=int, default=DEFAULT_SEED, show_default=True)


@click.group()
def main():
    """Build deterministic evaluation sets (core, focus, dev/holdout split)."""


@main.command()
@click.argument("out", type=click.Path())
@_db
@_run
@_seed
def core(out, db_path, run, seed):
    """Write the core dev set (annotated + FPs + stratified TNs) to OUT."""
    con = _open_ro(db_path, run)
    try:
        labels = _labels_path(con, run)
        units = build_core(con, run, labels, seed)
        missing = count_annotated_missing(con, run, labels)
        fps = {
            r["unit_path"]
            for r in rows(
                con,
                "SELECT unit_path FROM evaluation WHERE run_id = ? AND outcome = 'FP'",
                [run],
            )
        }
        tns = [
            r["unit_path"]
            for r in rows(
                con,
                "SELECT unit_path FROM evaluation WHERE run_id = ? AND outcome = 'TN'",
                [run],
            )
        ]
        chosen_tn = [u for u in units if u in set(tns)]
        strata = tn_strata(con, run, chosen_tn)
    finally:
        con.close()
    _write_units(out, units)
    click.echo(f"core: {len(units)} units ({len(fps)} FP, {len(chosen_tn)} TN) -> {out}")
    click.echo(f"annotated units not in run: {missing}")
    for (corpus, bucket), n in strata.items():
        click.echo(f"  TN {corpus or '(none)'} / {bucket}: {n}")


@main.command()
@click.argument("out", type=click.Path())
@_db
@_run
@click.option("--where", "sql_where", required=True, help="SQL over aliases e (evaluation), bf.")
@click.option("--cap", type=int, default=None)
@_seed
def focus(out, db_path, run, sql_where, cap, seed):
    """Write a focus set (units matching --where) to OUT."""
    con = _open_ro(db_path, run)
    try:
        units = build_focus(con, run, sql_where, cap, seed)
    finally:
        con.close()
    _write_units(out, units)
    click.echo(f"focus: {len(units)} units -> {out}")


@main.command()
@click.argument("out", type=click.Path())
@click.argument("devfiles", nargs=-1, required=True, type=click.Path(exists=True))
@_db
@_run
def splits(out, devfiles, db_path, run):
    """Write the dev/holdout TSV for every unit of the run; units in any DEVFILE are dev."""
    from .main import read_units_file

    con = _open_ro(db_path, run)
    try:
        all_units = [
            r["unit_path"] for r in rows(con, "SELECT unit_path FROM units WHERE run_id = ?", [run])
        ]
    finally:
        con.close()
    write_splits(all_units, [read_units_file(f) for f in devfiles], out)
    dev = {u for f in devfiles for u in read_units_file(f)} & set(all_units)
    click.echo(f"splits: {len(dev)} dev, {len(set(all_units)) - len(dev)} holdout -> {out}")
