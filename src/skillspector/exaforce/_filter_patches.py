# SPDX-License-Identifier: Apache-2.0
"""Control how far the meta-analyzer LLM verdict overrides a finding's severity (fork behavior).

Upstream ``LLMMetaAnalyzer.apply_filter`` keeps CRITICAL/HIGH findings even when
the meta-analyzer LLM denies or omits them, tagging them ``llm-unconfirmed``.
That floor is a prompt-injection defense: a skill's content could talk the LLM
into dropping a real finding. It also applies to *every* upstream finding,
including the LLM-backed analyzers (semantic ``SQP-*``/``SDI-*``/``SSD-*`` and
the ``TP4`` description-behavior check), so in practice it shields first-pass
LLM findings from a second LLM's re-verification as much as it shields static
regex hits.

``SKILLSPECTOR_META_SEVERITY_FLOOR`` selects the policy, read on every
``apply_filter`` call so it can be flipped at runtime:

``none``
    Empty the floor. Every finding, any severity, is dropped unless the
    meta-analyzer confirms it. Fewest false positives, clearly worse recall.
``semantic``  (default)
    Keep the upstream floor for LLM-backed findings only; static findings of
    any severity follow the meta-analyzer verdict. This is the literal "trust
    the LLM over static": the meta-analyzer may overrule a regex, but one LLM
    does not silently overrule another.
``upstream``
    Leave the floor untouched.

The floor policy applies only to findings the LLM actually adjudicated.
Batches that raise or never return never reach ``apply_filter`` at all —
upstream routes them through ``_fallback_filtered`` itself. A batch that
*returns* an empty verdict list, however, counts to upstream as a successful
"nothing confirmed" response, so lifting the floor there would drop every one
of its findings: a truncated or degenerate decode that still validates against
the schema would silently clear a file. Those findings therefore keep the
upstream floor — CRITICAL/HIGH retained and tagged ``llm-unconfirmed``,
MEDIUM/LOW dropped, exactly as ``upstream`` mode — and the event is logged.
Deciding it that way rather than diverting them to ``_fallback_filtered``
keeps the fork's change confined to the floor: MEDIUM/LOW handling and the
``llm-unconfirmed`` tag stay bit-for-bit upstream in the no-verdict case.

Measured 2026-09-02 on nvidia.nemotron-super-3-120b, same-day, two replicates
each, re-scanning the 94 borderline units (87 malicious / 7 benign) that a
900-unit ``none`` run had got wrong (188 unit-scans per mode):

    mode       TP   FP   correct
    upstream   68   10   72
    semantic   65    7   72      <- default: upstream accuracy, 30 % fewer FPs
    none       54    3   65

The ``none`` losses are not "correct": spot-checked drops included obfuscated
PowerShell download-and-execute and Fernet-decrypted ``exec()`` in ``setup.py``
that the semantic analyzers had flagged CRITICAL at confidence >= 0.9 and the
meta-analyzer then rejected.
"""

from __future__ import annotations

import functools
import inspect
import os
from typing import Any

import skillspector.nodes.meta_analyzer as meta
from skillspector.logging_config import get_logger
from skillspector.models import Finding

from ._patchlib import PatchDriftError

logger = get_logger(__name__)

ENV_VAR = "SKILLSPECTOR_META_SEVERITY_FLOOR"
MODES = ("none", "semantic", "upstream")
DEFAULT_MODE = "semantic"

_UPSTREAM_FLOOR = frozenset({"CRITICAL", "HIGH"})
_MISSING = object()

# ``Finding.category`` is the discriminator: every static finding acquires one
# (``static_runner.analyzer_finding_to_finding`` falls back to
# ``get_category``, which returns "Security" for an unmapped rule id, and the
# MCP analyzers pass ``category=`` explicitly), while ``LLMFinding.to_finding``
# — and the fork's pruned replacement in ``_schema_patches`` — set none. Rule
# ids are not used as the primary signal because they are free-form LLM output,
# never validated or normalized: a semantic analyzer that emitted ``SSD_1``
# instead of ``SSD-2`` would lose the floor, which is the recall loss this
# module exists to avoid. ``TP4`` is the one LLM-backed finding built by hand
# with a category, so it is matched by id; the prefixes are kept as a
# belt-and-braces signal in case a future upstream starts populating
# ``category`` on LLM findings. Both extra checks can only *add* the floor, so
# the failure direction is a retained false positive, never a silent drop.
LLM_RULE_PREFIXES = ("SQP-", "SDI-", "SSD-")
LLM_RULE_IDS = frozenset({"TP4"})


def resolve_mode() -> str:
    raw = os.environ.get(ENV_VAR, "").strip().lower()
    if not raw:
        return DEFAULT_MODE
    if raw not in MODES:
        logger.warning("%s=%r is not one of %s — using %r.", ENV_VAR, raw, MODES, DEFAULT_MODE)
        return DEFAULT_MODE
    return raw


def is_llm_finding(finding: Finding) -> bool:
    """Whether *finding* came from an LLM-backed analyzer rather than a static rule."""
    if getattr(finding, "category", None) is None:
        return True
    rule_id = (finding.rule_id or "").strip().upper()
    return rule_id in LLM_RULE_IDS or rule_id.startswith(LLM_RULE_PREFIXES)


def _no_verdict_finding_ids(batch_results: list[Any], mode: str) -> set[str]:
    """Ids of findings whose batch returned successfully but adjudicated nothing.

    Upstream treats an empty verdict list as "nothing confirmed", so with the
    floor lifted every finding in such a batch would be dropped. The LLM never
    actually ruled on them, so they keep the upstream floor instead.
    """
    ids: set[str] = set()
    for batch, llm_items in batch_results:
        if batch.findings and not llm_items:
            logger.warning(
                "Meta-analyzer returned no verdicts for %s (%d findings); under "
                "%s=%s they keep the upstream severity floor rather than being dropped.",
                batch.file_path,
                len(batch.findings),
                ENV_VAR,
                mode,
            )
            ids.update(f.finding_id for f in batch.findings)
    return ids


def _mode_dispatching_apply_filter(original: Any) -> Any:
    """Wrap upstream ``apply_filter`` to apply the env-selected floor policy per call.

    Upstream reads the floor via ``self._HIGH_SEVERITY_FLOOR``; an instance
    attribute shadows the class-level frozenset for the duration of one call and
    any prior instance value is restored in ``finally``, so a raise inside
    upstream code cannot leave the analyzer mis-configured.
    """

    @functools.wraps(original)
    def apply_filter(
        self: Any,
        findings: list[Finding],
        batch_results: list[tuple[Any, list[dict[str, Any]]]],
    ) -> list[Finding]:
        mode = resolve_mode()
        if mode == "upstream":
            return list(original(self, findings, batch_results))
        # Consumed more than once below, so materialize before the first pass.
        batch_results = list(batch_results)
        no_verdict_ids = _no_verdict_finding_ids(batch_results, mode)

        def keeps_floor(finding: Finding) -> bool:
            if finding.finding_id in no_verdict_ids:
                return True  # never adjudicated; fail closed
            return mode == "semantic" and is_llm_finding(finding)

        floored = [f for f in findings if keeps_floor(f)]
        unfloored = [f for f in findings if not keeps_floor(f)]
        kept: list[Finding] = []
        previous = self.__dict__.get("_HIGH_SEVERITY_FLOOR", _MISSING)
        try:
            if floored:
                self._HIGH_SEVERITY_FLOOR = _UPSTREAM_FLOOR
                kept.extend(original(self, floored, batch_results))
            self._HIGH_SEVERITY_FLOOR = frozenset()
            kept.extend(original(self, unfloored, batch_results))
        finally:
            if previous is _MISSING:
                self.__dict__.pop("_HIGH_SEVERITY_FLOOR", None)
            else:
                self._HIGH_SEVERITY_FLOOR = previous
        # Upstream forwards ``finding_id`` unchanged, so restore the caller's
        # ordering by it — keeps the contract identical to upstream's single pass.
        order = {f.finding_id: i for i, f in enumerate(findings)}
        kept.sort(key=lambda f: order.get(f.finding_id, len(order)))
        return kept

    apply_filter._exaforce_wrapped = True  # type: ignore[attr-defined]
    return apply_filter


def apply() -> None:
    cls = meta.LLMMetaAnalyzer
    qual = f"{cls.__module__}.{cls.__qualname__}"
    if cls.__dict__.get("_HIGH_SEVERITY_FLOOR") != _UPSTREAM_FLOOR:
        raise PatchDriftError(
            f"{qual}._HIGH_SEVERITY_FLOOR is not {sorted(_UPSTREAM_FLOOR)}; "
            "upstream changed — update the exaforce patch."
        )
    current = cls.__dict__.get("apply_filter")
    if current is None:
        raise PatchDriftError(
            f"{qual}.apply_filter is missing; upstream changed — update the exaforce patch."
        )
    if getattr(current, "_exaforce_wrapped", False):
        return  # already applied
    # The per-call shadowing above only works if upstream reads the floor
    # through the instance. Fail at import time if that access path changes.
    try:
        source = inspect.getsource(current)
    except OSError:
        # No source on disk: zipimport, a frozen build, a .pyc-only deploy.
        # The guard is unverifiable there, but refusing to import would take
        # the whole CLI down, so proceed and say so.
        logger.warning(
            "Cannot read the source of %s.apply_filter to verify it still reads "
            "self._HIGH_SEVERITY_FLOOR; applying the exaforce floor patch unverified.",
            qual,
        )
    else:
        if "self._HIGH_SEVERITY_FLOOR" not in source:
            raise PatchDriftError(
                f"{qual}.apply_filter no longer reads self._HIGH_SEVERITY_FLOOR; "
                "upstream changed — update the exaforce patch."
            )
    setattr(cls, "apply_filter", _mode_dispatching_apply_filter(current))  # noqa: B010
