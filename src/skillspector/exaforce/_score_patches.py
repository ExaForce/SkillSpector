# SPDX-License-Identifier: Apache-2.0
"""Flag-gated semantic block gate and documentation-MEDIUM cap on the risk scorer (fork behavior).

Wraps ``skillspector.nodes.report._compute_risk_score``. Both behaviors are off by
default; every flag is read on each call so they can be flipped at runtime, and an
invalid value falls back to the default with a warning instead of raising.

``SKILLSPECTOR_EXA_SEMANTIC_GATE`` — ``off`` (default), ``any`` or ``confirmed``.
    A *hit* is a finding (any confidence) whose ``rule_id`` matches an entry of
    ``SKILLSPECTOR_EXA_GATE_RULES`` and whose severity is at least
    ``SKILLSPECTOR_EXA_GATE_MIN_SEVERITY``. In ``confirmed`` mode a finding tagged
    ``llm-unconfirmed`` does not hit (no tags counts as confirmed). On a hit the
    result is ``(max(score, 51), band(max(score, 51)), "DO_NOT_INSTALL")``;
    otherwise the upstream result is returned unchanged.
``SKILLSPECTOR_EXA_GATE_RULES`` — default ``SSD-1,SSD-2,SSD-3,SSD-4,P2``.
    Comma-separated; an entry ending in ``-`` is a prefix. Blank means no rules,
    hence no gate.
``SKILLSPECTOR_EXA_GATE_MIN_SEVERITY`` — default ``HIGH`` (CRITICAL > HIGH > MEDIUM > LOW).
``SKILLSPECTOR_EXA_DOC_MEDIUM_CAP`` — unset (default) means off. An integer N >= 0
    keeps only the first N MEDIUM findings from files whose component metadata says
    ``executable: False``, sorted by ``(rule_id, file, start_line)``; the rest are
    dropped from the list *scored*. Reported findings are unchanged.

The semantics mirror ``benchmark/benchmark/replay.py`` (``_gate_hit``,
``cap_doc_mediums``), which chose the policy offline;
``benchmark/tests/test_replay_parity.py`` holds the two to the same verdicts.
"""

from __future__ import annotations

import inspect
import os
from collections.abc import Callable, Iterable, Mapping
from typing import Any

import skillspector.nodes.report as report
from skillspector.logging_config import get_logger
from skillspector.models import Finding

from ._patchlib import PatchDriftError, intercept_module_callable

logger = get_logger(__name__)

GATE_ENV = "SKILLSPECTOR_EXA_SEMANTIC_GATE"
RULES_ENV = "SKILLSPECTOR_EXA_GATE_RULES"
MIN_SEVERITY_ENV = "SKILLSPECTOR_EXA_GATE_MIN_SEVERITY"
CAP_ENV = "SKILLSPECTOR_EXA_DOC_MEDIUM_CAP"

GATE_MODES = ("off", "any", "confirmed")
DEFAULT_GATE_RULES = ("SSD-1", "SSD-2", "SSD-3", "SSD-4", "P2")
DEFAULT_MIN_SEVERITY = "HIGH"
UNCONFIRMED_TAG = "llm-unconfirmed"
BLOCK_RECOMMENDATION = "DO_NOT_INSTALL"
GATE_MIN_SCORE = 51  # floor of upstream's HIGH band

# Same rank upstream ``_compute_risk_score`` uses; an unknown severity ranks below LOW.
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_UNKNOWN_SEVERITY_RANK = 4
_EXPECTED_PARAMS = ("findings", "has_executable_scripts", "component_metadata")


def _severity(finding: Finding) -> str:
    return (finding.severity or "LOW").upper()


def resolve_gate_mode() -> str:
    raw = os.environ.get(GATE_ENV, "").strip().lower()
    if not raw:
        return "off"
    if raw not in GATE_MODES:
        logger.warning("%s=%r is not one of %s — using 'off'.", GATE_ENV, raw, GATE_MODES)
        return "off"
    return raw


def resolve_gate_rules() -> tuple[str, ...]:
    raw = os.environ.get(RULES_ENV)
    if raw is None:
        return DEFAULT_GATE_RULES
    return tuple(entry.strip() for entry in raw.split(",") if entry.strip())


def resolve_min_severity() -> str:
    raw = os.environ.get(MIN_SEVERITY_ENV, "").strip().upper()
    if not raw:
        return DEFAULT_MIN_SEVERITY
    if raw not in _SEVERITY_RANK:
        logger.warning(
            "%s=%r is not one of %s — using %r.",
            MIN_SEVERITY_ENV,
            raw,
            list(_SEVERITY_RANK),
            DEFAULT_MIN_SEVERITY,
        )
        return DEFAULT_MIN_SEVERITY
    return raw


def resolve_doc_medium_cap() -> int | None:
    raw = os.environ.get(CAP_ENV, "").strip()
    if not raw:
        return None
    try:
        cap = int(raw)
    except ValueError:
        cap = -1
    if cap < 0:
        logger.warning("%s=%r is not an integer >= 0 — cap is off.", CAP_ENV, raw)
        return None
    return cap


def _rule_matches(rule_id: str, rules: Iterable[str]) -> bool:
    return any(rule_id.startswith(r) if r.endswith("-") else rule_id == r for r in rules)


def gate_hit(findings: list[Finding], rules: tuple[str, ...], min_severity: str, mode: str) -> bool:
    """Whether any finding blocks under the gate (any confidence; ``mode`` any|confirmed)."""
    if not rules:
        return False
    min_rank = _SEVERITY_RANK[min_severity]
    for f in findings:
        if not _rule_matches(f.rule_id or "", rules):
            continue
        if _SEVERITY_RANK.get(_severity(f), _UNKNOWN_SEVERITY_RANK) > min_rank:
            continue
        if mode == "confirmed" and UNCONFIRMED_TAG in (f.tags or []):
            continue
        return True
    return False


def _non_executable_files(component_metadata: Iterable[Mapping[str, Any]] | None) -> set[str]:
    """Paths whose metadata says not executable; a missing/None flag is neither."""
    files: set[str] = set()
    for cm in component_metadata or ():
        flag = cm.get("executable")
        if flag is not None and not flag:
            files.add(str(cm.get("path", "")))
    return files


def cap_doc_mediums(
    findings: list[Finding],
    component_metadata: list[dict[str, object]] | None,
    cap: int | None,
) -> list[Finding]:
    """``findings`` minus the documentation MEDIUMs past the first ``cap``.

    Documentation MEDIUMs are MEDIUM findings (any case, any confidence) in a file whose
    component metadata says ``executable: False``; a file with no metadata entry counts as
    executable. They are ordered by ``(rule_id, file, start_line)`` — a None start_line
    first, ties in input order — and all but the first ``cap`` dropped. Kept findings stay
    in input order. ``cap`` None, or no metadata, returns ``findings`` unchanged.
    """
    if cap is None:
        return findings
    non_executable = _non_executable_files(component_metadata)
    if not non_executable:
        return findings
    doc = [
        i for i, f in enumerate(findings) if _severity(f) == "MEDIUM" and f.file in non_executable
    ]
    doc.sort(
        key=lambda i: (
            findings[i].rule_id or "",
            findings[i].file or "",
            findings[i].start_line is not None,
            findings[i].start_line or 0,
        )
    )
    dropped = set(doc[cap:])
    if not dropped:
        return findings
    return [f for i, f in enumerate(findings) if i not in dropped]


def _band(score: int) -> str:
    for floor, band in report._RISK_SEVERITY_BANDS:
        if score >= floor:
            return band
    return "LOW"


def _score_interceptor(original: Callable, args: tuple, kwargs: dict) -> Any:
    mode = resolve_gate_mode()
    cap = resolve_doc_medium_cap()
    if mode == "off" and cap is None:
        return original(*args, **kwargs)

    bound = inspect.signature(original).bind(*args, **kwargs)
    bound.apply_defaults()
    findings = list(bound.arguments["findings"] or [])
    if cap is not None:
        bound.arguments["findings"] = cap_doc_mediums(
            findings, bound.arguments["component_metadata"], cap
        )
    score, band, recommendation = original(*bound.args, **bound.kwargs)

    if mode == "off":
        return score, band, recommendation
    if not gate_hit(findings, resolve_gate_rules(), resolve_min_severity(), mode):
        return score, band, recommendation
    gated = max(score, GATE_MIN_SCORE)
    return gated, _band(gated), BLOCK_RECOMMENDATION


def _check_bands() -> None:
    bands = getattr(report, "_RISK_SEVERITY_BANDS", None)
    recommendations = getattr(report, "_RISK_RECOMMENDATION", None)
    try:
        has_high_floor = (GATE_MIN_SCORE, "HIGH") in [tuple(b) for b in bands]  # type: ignore[union-attr]
    except TypeError:
        has_high_floor = False
    if not has_high_floor:
        raise PatchDriftError(
            f"{report.__name__}._RISK_SEVERITY_BANDS no longer starts HIGH at {GATE_MIN_SCORE}; "
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
