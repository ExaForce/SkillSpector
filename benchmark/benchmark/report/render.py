"""Assemble the comparison context and render it through the Jinja2 template."""

from __future__ import annotations

import pathlib

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from . import charts
from .compare import Comparison
from .data import DIMENSIONS, Breakdown, RunReport

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"

# Show the loud coverage-skew warning once the non-shared share of the two runs'
# scanned units exceeds this — below it the gap is immaterial to the deltas.
_COVERAGE_SKEW_PCT = 5.0


def _merge_dim(base_list: list[Breakdown], head_list: list[Breakdown]) -> list[dict]:
    """Align two runs' per-value breakdowns by key, ordered by combined size."""
    by_key: dict[str, dict] = {}
    for bd in base_list:
        by_key.setdefault(bd.key, {"key": bd.key, "base": None, "head": None})["base"] = bd
    for bd in head_list:
        by_key.setdefault(bd.key, {"key": bd.key, "base": None, "head": None})["head"] = bd
    rows = list(by_key.values())
    rows.sort(
        key=lambda r: -((r["base"].n if r["base"] else 0) + (r["head"].n if r["head"] else 0))
    )
    return rows


def _merged_dists(base: RunReport, head: RunReport) -> dict[str, list[dict]]:
    return {dim: _merge_dim(base.dists[dim], head.dists[dim]) for dim in DIMENSIONS}


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    # Expose the formatting helpers as filters so the template stays logic-free.
    env.filters["bar"] = charts.bar
    env.filters["pct"] = charts.pct
    env.filters["metric"] = charts.metric
    env.filters["num"] = charts.num
    env.filters["delta"] = charts.delta
    env.filters["sub"] = charts.sub
    env.filters["signed"] = charts.signed
    env.filters["duration"] = charts.duration
    return env


def render_report(
    base: RunReport,
    head: RunReport,
    comparison: Comparison,
    *,
    label_base: str,
    label_head: str,
    db_path: str,
    generated_at: str,
) -> str:
    ctx = {
        "base": base,
        "head": head,
        "label_base": label_base,
        "label_head": label_head,
        "cmp": comparison,
        "merged": _merged_dists(base, head),
        "coverage_skewed": comparison.coverage.nonshared_pct >= _COVERAGE_SKEW_PCT,
        "dimensions": list(DIMENSIONS),
        "db_path": db_path,
        "generated_at": generated_at,
    }
    return _env().get_template("report.md.j2").render(**ctx)


def render_summary(
    run: RunReport,
    *,
    label: str,
    db_path: str,
    generated_at: str,
) -> str:
    ctx = {
        "run": run,
        "label": label,
        "dimensions": list(DIMENSIONS),
        "db_path": db_path,
        "generated_at": generated_at,
    }
    return _env().get_template("summary.md.j2").render(**ctx)
