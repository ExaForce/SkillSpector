"""Run-health gate: flag runs poisoned or degraded by dropped LLM calls or errors."""

import sys

import click

MAX_DROPPED_FRACTION = 0.05
MAX_ERROR_FRACTION = 0.01
MIN_MEDIAN_RUN_TIME = 3.0
SEMANTIC_PREFIXES = ("SSD-", "SDI-", "SQP-")


def check_health(con, run_id: str) -> list[str]:
    """Return problems found in ``run_id`` (empty list = healthy)."""
    row = con.execute("SELECT use_llm FROM runs WHERE run_id = ?", [run_id]).fetchone()
    if row is None:
        raise KeyError(run_id)
    use_llm = bool(row[0])

    total, dropped, run_times_n, median = con.execute(
        "SELECT count(*),"
        " count(*) FILTER (WHERE llm_calls_succeeded < llm_calls_attempted),"
        " count(run_time), median(run_time)"
        " FROM classifications WHERE run_id = ?",
        [run_id],
    ).fetchone()
    if total == 0:
        return ["no scans recorded for this run"]

    problems: list[str] = []
    if use_llm:
        (n_sem,) = con.execute(
            "SELECT count(*) FROM issues WHERE run_id = ?"
            " AND (starts_with(rule_id, 'SSD-') OR starts_with(rule_id, 'SDI-')"
            " OR starts_with(rule_id, 'SQP-'))",
            [run_id],
        ).fetchone()
        if n_sem == 0:
            problems.append("LLM run has no SSD-/SDI-/SQP- issues (semantic rules never fired)")

    if dropped / total > MAX_DROPPED_FRACTION:
        problems.append(
            f"dropped LLM calls in {dropped / total:.1%} of scans ({dropped}/{total})"
            f" > {MAX_DROPPED_FRACTION:.0%}"
        )

    (errors,) = con.execute(
        "SELECT count(*) FROM evaluation WHERE run_id = ? AND outcome = 'ERROR'", [run_id]
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
