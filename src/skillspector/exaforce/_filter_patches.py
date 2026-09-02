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

Batches that raise or never return are unaffected in every mode: upstream
routes those findings through its no-verdict fallback before ``apply_filter``
sees them. A batch that *returns* an empty verdict list is treated by upstream
as a successful "nothing confirmed" response, and under ``none``/``semantic``
that now drops the batch's static findings where upstream kept CRITICAL/HIGH;
the wrapper logs a warning when that happens so it is observable.

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

# ``Finding`` carries no source-analyzer field, so the rule id is the only
# stable discriminator for LLM-backed findings. Prefixes cover the three
# semantic analyzers; ``TP4`` is emitted by mcp_tool_poisoning from a
# ``chat_completion`` reply. Matching is case-insensitive on the stripped id
# because the semantic analyzers' rule ids are free-form LLM output and the
# benchmark corpus shows rare variants such as ``ssd-2`` or ``SQP-2 L160``.
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
    rule_id = (finding.rule_id or "").strip().upper()
    return rule_id in LLM_RULE_IDS or rule_id.startswith(LLM_RULE_PREFIXES)


def _warn_on_empty_verdicts(batch_results: Any) -> None:
    for batch, llm_items in batch_results:
        if batch.findings and not llm_items:
            logger.warning(
                "Meta-analyzer returned no verdicts for %s (%d findings); under "
                "%s=%s its unconfirmed static findings will be dropped.",
                batch.file_path,
                len(batch.findings),
                ENV_VAR,
                resolve_mode(),
            )


def _mode_dispatching_apply_filter(original: Any) -> Any:
    """Wrap upstream ``apply_filter`` to apply the env-selected floor policy per call.

    Upstream reads the floor via ``self._HIGH_SEVERITY_FLOOR``; an instance
    attribute shadows the class-level frozenset for the duration of one call
    and is removed in ``finally`` so a raise inside upstream code cannot leave
    the analyzer mis-configured.
    """

    @functools.wraps(original)
    def apply_filter(self: Any, findings: list[Finding], batch_results: Any) -> list[Finding]:
        mode = resolve_mode()
        if mode == "upstream":
            return list(original(self, findings, batch_results))
        _warn_on_empty_verdicts(batch_results)
        if mode == "none":
            floored: list[Finding] = []
            unfloored = list(findings)
        else:  # semantic
            floored = [f for f in findings if is_llm_finding(f)]
            unfloored = [f for f in findings if not is_llm_finding(f)]
        kept: list[Finding] = []
        try:
            if floored:
                self._HIGH_SEVERITY_FLOOR = _UPSTREAM_FLOOR
                kept.extend(original(self, floored, batch_results))
            self._HIGH_SEVERITY_FLOOR = frozenset()
            kept.extend(original(self, unfloored, batch_results))
        finally:
            self.__dict__.pop("_HIGH_SEVERITY_FLOOR", None)
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
    if "self._HIGH_SEVERITY_FLOOR" not in inspect.getsource(current):
        raise PatchDriftError(
            f"{qual}.apply_filter no longer reads self._HIGH_SEVERITY_FLOOR; "
            "upstream changed — update the exaforce patch."
        )
    setattr(cls, "apply_filter", _mode_dispatching_apply_filter(current))  # noqa: B010
