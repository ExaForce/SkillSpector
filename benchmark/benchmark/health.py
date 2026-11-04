"""Run-health gate: flag runs poisoned or degraded by dropped LLM calls or errors."""

import sys

import click

MAX_DROPPED_FRACTION = 0.05
MAX_ERROR_FRACTION = 0.01
MIN_MEDIAN_RUN_TIME = 3.0
SEMANTIC_PREFIXES = ("SSD-", "SDI-", "SQP-")


def check_health(con, run_id: str) -> list[str]:
    """Return problems found in ``run_id`` (empty list = healthy)."""
    return check_health_pooled(con, [run_id])


def check_health_pooled(con, run_ids: list[str]) -> list[str]:
    """Problems of ``run_ids`` judged as one run (a union replicate): scans, dropped calls and
    errors summed, semantic issues counted over all of them, the median run_time over all
    their scans, and the LLM checks applied if any of them used the LLM. Raises ``KeyError``
    naming the first unknown run."""
    if not run_ids:
        raise ValueError("no run ids")
    marks = ", ".join("?" * len(run_ids))
    use = dict(
        con.execute(
            f"SELECT run_id, use_llm FROM runs WHERE run_id IN ({marks})", run_ids
        ).fetchall()
    )
    for r in run_ids:
        if r not in use:
            raise KeyError(r)
    use_llm = any(bool(use[r]) for r in run_ids)

    total, dropped, run_times_n, median = con.execute(
        "SELECT count(*),"
        " count(*) FILTER (WHERE llm_calls_succeeded < llm_calls_attempted),"
        " count(run_time), median(run_time)"
        f" FROM classifications WHERE run_id IN ({marks})",
        run_ids,
    ).fetchone()
    if total == 0:
        return ["no scans recorded for " + ("this run" if len(run_ids) == 1 else "these runs")]

    problems: list[str] = []
    if use_llm:
        (n_sem,) = con.execute(
            f"SELECT count(*) FROM issues WHERE run_id IN ({marks})"
            " AND (starts_with(rule_id, 'SSD-') OR starts_with(rule_id, 'SDI-')"
            " OR starts_with(rule_id, 'SQP-'))",
            run_ids,
        ).fetchone()
        if n_sem == 0:
            problems.append("LLM run has no SSD-/SDI-/SQP- issues (semantic rules never fired)")

    if dropped / total > MAX_DROPPED_FRACTION:
        problems.append(
            f"dropped LLM calls in {dropped / total:.1%} of scans ({dropped}/{total})"
            f" > {MAX_DROPPED_FRACTION:.0%}"
        )

    (errors,) = con.execute(
        f"SELECT count(*) FROM evaluation WHERE run_id IN ({marks}) AND outcome = 'ERROR'",
        run_ids,
    ).fetchone()
    if errors / total > MAX_ERROR_FRACTION:
        problems.append(
            f"ERROR outcomes in {errors / total:.1%} of scans ({errors}/{total})"
            f" > {MAX_ERROR_FRACTION:.0%}"
        )

    if use_llm and run_times_n > 0 and median < MIN_MEDIAN_RUN_TIME:
        problems.append(f"median run_time {median:.2f}s < {MIN_MEDIAN_RUN_TIME:g}s on an LLM run")
    return problems


@click.command()
@click.argument("db_path", metavar="DB")
@click.argument("run", metavar="RUN")
def main(db_path, run):
    """Check that RUN in DB is healthy; exit 1 and list problems otherwise."""
    import duckdb

    con = duckdb.connect(db_path, read_only=True)
    try:
        try:
            problems = check_health(con, run)
        except KeyError:
            raise click.ClickException(f"run {run!r} not found in {db_path}") from None
    finally:
        con.close()
    if problems:
        for p in problems:
            click.echo(f"UNHEALTHY: {p}")
        sys.exit(1)
    click.echo(f"run {run} healthy")
