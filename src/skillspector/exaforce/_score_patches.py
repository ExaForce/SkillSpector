# SPDX-License-Identifier: Apache-2.0
"""Block threshold on the risk scorer (fork behavior, P6).

Wraps ``skillspector.nodes.report._compute_risk_score``. The flag is read on each call, so it
can be flipped at runtime.

``SKILLSPECTOR_EXA_BLOCK_THRESHOLD`` — unset (default) means 51, upstream's cut, and the patch
    passes upstream's result through unchanged. ``49`` is the value P6 chose (opt-in; it was the
    default from ``4e6863d1`` until the 2026-11-06 PR review, which judged its marginal trade of
    about 2.2 malicious catches per benign block too costly at real-world malware prevalence;
    see ``benchmark/results/recall-improvement-program.md``). An integer T in 21-80 blocks
    (``DO_NOT_INSTALL``) when score >= T. Away from 51 the returned score is clamped so every score-keyed upstream consumer (CLI exit code, MCP ``safe_to_install``,
    which cut at ``RISK_THRESHOLD`` = 50) agrees with the recommendation: a block returns
    ``max(score, 51)``, a non-block ``min(score, 50)``; band and recommendation then follow
    upstream's tables from the clamped score. A non-integer value is ignored with a warning; an
    integer outside 21-80 raises ``ValueError`` (logged first), because it would put the MEDIUM
    band below LOW.

The semantics mirror ``benchmark/benchmark/replay.py`` (``decide``), which chose the threshold
offline; ``benchmark/tests/test_replay_parity.py`` holds the two to the same verdicts.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from typing import Any

import skillspector.nodes.report as report
from skillspector.logging_config import get_logger

from ._patchlib import PatchDriftError, intercept_module_callable

logger = get_logger(__name__)

THRESHOLD_ENV = "SKILLSPECTOR_EXA_BLOCK_THRESHOLD"

BLOCK_RECOMMENDATION = "DO_NOT_INSTALL"
HIGH_FLOOR = 51  # floor of upstream's HIGH band; upstream blocks at score >= 51
DEFAULT_THRESHOLD = HIGH_FLOOR  # upstream's cut; P6's 49 is opt-in
MIN_THRESHOLD = 21  # floor of upstream's MEDIUM band
MAX_THRESHOLD = 80  # top of upstream's HIGH band

_EXPECTED_PARAMS = ("findings", "has_executable_scripts", "component_metadata")


def block_threshold() -> int:
    """The block threshold T: unset or non-integer gives the default 51; an integer outside 21-80 raises."""
    raw = os.environ.get(THRESHOLD_ENV, "").strip()
    if not raw:
        return DEFAULT_THRESHOLD
    try:
        value = int(raw)
    except ValueError:
        logger.warning("%s=%r is not an integer — using %d.", THRESHOLD_ENV, raw, DEFAULT_THRESHOLD)
        return DEFAULT_THRESHOLD
    if not MIN_THRESHOLD <= value <= MAX_THRESHOLD:
        message = f"{THRESHOLD_ENV}={value} is outside {MIN_THRESHOLD}-{MAX_THRESHOLD}."
        logger.error(message)
        raise ValueError(message)
    return value


def _band(score: int) -> str:
    for floor, band in report._RISK_SEVERITY_BANDS:
        if score >= floor:
            return band
    return "LOW"


def _apply_threshold(score: int, band: str, recommendation: str, threshold: int) -> tuple:
    """Clamp an upstream result at threshold T (see the module docstring)."""
    clamped = max(score, HIGH_FLOOR) if score >= threshold else min(score, HIGH_FLOOR - 1)
    if clamped == score:
        return score, band, recommendation
    new_band = _band(clamped)
    return clamped, new_band, report._RISK_RECOMMENDATION[new_band]


def _score_interceptor(original: Callable, args: tuple, kwargs: dict) -> Any:
    threshold = block_threshold()
    score, band, recommendation = original(*args, **kwargs)
    if threshold == HIGH_FLOOR:
        return score, band, recommendation
    return _apply_threshold(score, band, recommendation, threshold)


def _check_bands() -> None:
    bands = getattr(report, "_RISK_SEVERITY_BANDS", None)
    recommendations = getattr(report, "_RISK_RECOMMENDATION", None)
    try:
        has_high_floor = (HIGH_FLOOR, "HIGH") in [tuple(b) for b in bands]  # type: ignore[union-attr]
    except TypeError:
        has_high_floor = False
    if not has_high_floor:
        raise PatchDriftError(
            f"{report.__name__}._RISK_SEVERITY_BANDS no longer starts HIGH at {HIGH_FLOOR}; "
            "upstream changed — update the exaforce patch."
        )
    if not isinstance(recommendations, Mapping) or any(
        recommendations.get(b) != BLOCK_RECOMMENDATION for b in ("HIGH", "CRITICAL")
    ):
        raise PatchDriftError(
            f"{report.__name__}._RISK_RECOMMENDATION no longer maps HIGH/CRITICAL to "
            f"{BLOCK_RECOMMENDATION!r}; upstream changed — update the exaforce patch."
        )


def apply() -> None:
    _check_bands()
    intercept_module_callable(
        report,
        "_compute_risk_score",
        _score_interceptor,
        expected_params=_EXPECTED_PARAMS,
    )
