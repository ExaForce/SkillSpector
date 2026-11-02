"""Assemble the comparison context and render it through the Jinja2 template."""

from __future__ import annotations

import pathlib
from collections.abc import Sequence

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from . import charts
from .compare import Comparison
from .data import DIMENSIONS, Breakdown, RunReport
from .extras import SIZE_KEYS, STB_KEYS, TIER_KEYS, Extras

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"

# Show the loud coverage-skew warning once the non-shared share of the two runs'
# scanned units exceeds this — below it the gap is immaterial to the deltas.
_COVERAGE_SKEW_PCT = 5.0


def _merge_dim(
    base_list: list[Breakdown],
    head_list: list[Breakdown],
    *,
    key_order: Sequence[str] | None = None,
) -> list[dict]:
    """Align two runs' per-value breakdowns by key, ordered by combined size.

    With ``key_order`` the rows follow that order instead (keys not in it go last,
    by combined size) -- for sections whose keys have a natural order, like size buckets.
    """
    by_key: dict[str, dict] = {}
    for bd in base_list:
        by_key.setdefault(bd.key, {"key": bd.key, "base": None, "head": None})["base"] = bd
    for bd in head_list:
        by_key.setdefault(bd.key, {"key": bd.key, "base": None, "head": None})["head"] = bd
    rows = list(by_key.values())
    rows.sort(
        key=lambda r: -((r["base"].n if r["base"] else 0) + (r["head"].n if r["head"] else 0))
    )
    if key_order is not None:
        rank = {k: i for i, k in enumerate(key_order)}
        rows.sort(key=lambda r: rank.get(r["key"], len(rank)))  # stable: size order kept
    return rows


def _merged_dists(base: RunReport, head: RunReport) -> dict[str, list[dict]]:
    return {dim: _merge_dim(base.dists[dim], head.dists[dim]) for dim in DIMENSIONS}


# Extras sections that are Breakdown lists, merged side by side in comparison mode,
# with their fixed row order (None: by combined size).
_EXTRAS_DIMS: dict[str, Sequence[str] | None] = {
    "stb_split": STB_KEYS,
    "validity_tiers": TIER_KEYS,
    "fp_by_size": SIZE_KEYS,
    "splits": None,
}


def _merged_extras(base: Extras, head: Extras) -> dict[str, list[dict] | None]:
    """Side-by-side rows per extras section; None when neither run has the section."""
    merged: dict[str, list[dict] | None] = {}
    for name, order in _EXTRAS_DIMS.items():
        b, h = getattr(base, name), getattr(head, name)
        if b is None and h is None:
            merged[name] = None
        else:
            merged[name] = _merge_dim(b or [], h or [], key_order=order)
    return merged


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
    base_extras: Extras,
    head_extras: Extras,
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
        "base_extras": base_extras,
        "head_extras": head_extras,
        "merged_extras": _merged_extras(base_extras, head_extras),
        "coverage_skewed": comparison.coverage.nonshared_pct >= _COVERAGE_SKEW_PCT,
        "dimensions": list(DIMENSIONS),
        "db_path": db_path,
        "generated_at": generated_at,
    }
    return _env().get_template("report.md.j2").render(**ctx)


def render_summary(
    run: RunReport,
    extras: Extras,
    *,
    label: str,
    db_path: str,
    generated_at: str,
) -> str:
    ctx = {
        "run": run,
        "extras": extras,
        "label": label,
        "dimensions": list(DIMENSIONS),
        "db_path": db_path,
        "generated_at": generated_at,
    }
    return _env().get_template("summary.md.j2").render(**ctx)
