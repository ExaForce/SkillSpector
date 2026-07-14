"""Compare two benchmark runs and render a GitHub-PR-ready markdown report.

``build_report`` is the package entry point: open the DuckDB, load the run,
and render markdown — a single-run summary, or (with ``base``) a head-to-head
comparison. The CLI wiring lives in ``benchmark.main`` (the ``report`` command).
"""

from __future__ import annotations

from ..db import resolve_run_id
from .compare import DEFAULT_TOP, compare
from .data import load_run
from .render import render_report, render_summary


def build_report(
    con,
    run: str,
    base: str | None = None,
    *,
    label: str | None = None,
    base_label: str | None = None,
    db_path: str = "",
    generated_at: str = "",
    top: int = DEFAULT_TOP,
) -> str:
    run = resolve_run_id(con, run)
    head = load_run(con, run)
    if base is None:
        return render_summary(
            head,
            label=label or (head.description or head.run_id[:12]),
            db_path=db_path,
            generated_at=generated_at,
        )
    base = resolve_run_id(con, base)
    if base == run:
        raise SystemExit("run and base are the same run; nothing to compare.")
    base_report = load_run(con, base)
    comparison = compare(con, base, run, top=top)
    return render_report(
        base_report,
        head,
        comparison,
        label_base=base_label or (base_report.description or base_report.run_id[:12]),
        label_head=label or (head.description or head.run_id[:12]),
        db_path=db_path,
        generated_at=generated_at,
    )


__all__ = ["DEFAULT_TOP", "build_report"]
