"""Formatting helpers exposed to the template: unicode bars and deltas.

Everything here is plain text, so it renders identically in a GitHub PR
description, a local markdown preview, and a terminal.
"""

from __future__ import annotations

_FULL = "█"
_EMPTY = "░"


def bar(value: float | None, total: float | None, width: int = 18) -> str:
    """A fixed-width unicode bar for ``value`` out of ``total``."""
    if not total or value is None:
        return _EMPTY * width
    frac = max(0.0, min(1.0, value / total))
    filled = round(frac * width)
    return _FULL * filled + _EMPTY * (width - filled)


def pct(value: float | None, total: float | None) -> str:
    if not total or value is None:
        return "—"
    return f"{value / total * 100:.1f}%"


def metric(value: float | None) -> str:
    """Render a 0-1 metric as 3-dp, or an em dash when undefined."""
    return "—" if value is None else f"{value:.3f}"


def num(value: float | None) -> str:
    if value is None:
        return "—"
    if isinstance(value, float) and not value.is_integer():
        return f"{value:.2f}"
    return f"{int(value):,}"


def sub(value: float | None, base: float | None) -> float | None:
    """head − base, or None when either side is undefined -- lets the template
    subtract optional rates without a None guard before piping to ``delta``."""
    if value is None or base is None:
        return None
    return value - base


def delta(value: float | None, higher_is_better: bool = True, as_int: bool = False) -> str:
    """A signed delta with a direction marker reflecting better/worse.

    ▲ improvement, ▼ regression, ▬ no change. Sign is always shown so the raw
    direction is unambiguous regardless of the marker.
    """
    if value is None:
        return "—"
    if value == 0:
        return "▬ 0"
    better = (value > 0) == higher_is_better
    marker = "▲" if better else "▼"
    body = f"{value:+d}" if as_int else f"{value:+.3f}"
    return f"{marker} {body}"


def signed(value: int | None) -> str:
    """A signed integer with no good/bad marker -- for partition sub-rows whose
    individual direction isn't independently 'better' or 'worse'."""
    if value is None:
        return "—"
    return "0" if value == 0 else f"{value:+d}"


def duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"
