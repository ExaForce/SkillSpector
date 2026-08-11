# SPDX-License-Identifier: Apache-2.0
"""Apply a small frequency penalty to OpenAI-compatible chat models (fork behavior).

Why: under strict ``json_schema`` structured output, nemotron-super-3-120b
intermittently falls into a degenerate decode state and emits whitespace until
it hits ``max_completion_tokens`` — JSON permits unlimited whitespace between
tokens, so the grammar never forces a stop. The call then raises
``LengthFinishReasonError``, ``arun_batches`` drops the batch, and agentguard
discards the whole scan's LLM findings.

Measured on ``nvidia.nemotron-super-3-120b`` via bedrock-mantle (5,400 paired
calls over a prod-shaped corpus, plus an independent 3,000-call two-arm run):

    penalty  runaway rate   malformed rule_id
      0.0    0.78 %         0.00 %
      0.05   0.22 %         0.00 %
      0.1    0.00 %         0.00 %     <- default
      0.2    0.11 %         0.00 %
      0.3    0.22 %         1.05 %
      0.5    0.00 %         1.49 %

Pooled any-penalty vs none: 0.78 % -> 0.11 %, Fisher p = 0.0013.

0.1 is the smallest value that reached zero runaways with no observed damage to
structured output. Higher values corrupt ``rule_id`` (``''``, ``'SQ'``,
``'SQP-'``) because the penalty discounts tokens already emitted and a findings
response repeats ``rule_id``/``severity``/``start_line`` once per finding — so
the corruption grows with findings per response (0 % at 1-2 findings, ~3 % at
4+), i.e. it is worst on exactly the files with the most to report.

Set ``SKILLSPECTOR_FREQUENCY_PENALTY`` to override; ``0`` disables the patch.
"""

from __future__ import annotations

import os

from langchain_core.language_models.chat_models import BaseChatModel

import skillspector.llm_analyzer_base as llm_base
import skillspector.llm_utils as llm_utils
from skillspector.logging_config import get_logger

from ._patchlib import wrap_module_callable

logger = get_logger(__name__)

DEFAULT_FREQUENCY_PENALTY = 0.1
ENV_VAR = "SKILLSPECTOR_FREQUENCY_PENALTY"
# OpenAI-compatible endpoints accept [-2.0, 2.0]; anything outside is a 400 at
# request time, which would surface as a batch failure — the thing this patch
# exists to prevent. Clamp instead.
_MIN, _MAX = -2.0, 2.0


def resolve_frequency_penalty() -> float | None:
    """Return the penalty to apply, or ``None`` to leave models untouched."""
    raw = os.environ.get(ENV_VAR, "").strip()
    if not raw:
        return DEFAULT_FREQUENCY_PENALTY
    try:
        value = float(raw)
    except ValueError:
        logger.warning(
            "%s=%r is not a number — using the default %s.",
            ENV_VAR,
            raw,
            DEFAULT_FREQUENCY_PENALTY,
        )
        return DEFAULT_FREQUENCY_PENALTY
    if value == 0.0:
        return None
    clamped = min(max(value, _MIN), _MAX)
    if clamped != value:
        logger.warning("%s=%s is out of range — clamped to %s.", ENV_VAR, value, clamped)
    return clamped


def _with_frequency_penalty(model: object) -> object:
    """Set ``frequency_penalty`` on *model* when the model supports it.

    Providers whose chat models have no such field (Anthropic, Bedrock Converse,
    and the agent-CLI adapter) are returned untouched, so the patch is a no-op
    outside OpenAI-compatible endpoints rather than a source of 400s.
    """
    penalty = resolve_frequency_penalty()
    if penalty is None or not isinstance(model, BaseChatModel):
        return model
    if "frequency_penalty" not in type(model).model_fields:
        return model
    if model.frequency_penalty is not None:  # type: ignore[attr-defined]
        return model  # an explicit upstream/caller value wins
    model.frequency_penalty = penalty  # type: ignore[attr-defined]
    logger.debug("Applied frequency_penalty=%s to %s", penalty, type(model).__name__)
    return model


def apply() -> None:
    # Both LLM entry points live in llm_utils, but llm_analyzer_base binds
    # ``get_chat_model`` by value at import time, so patching llm_utils alone
    # would miss every analyzer. ``chat_completion`` (mcp_tool_poisoning's TP4
    # check) resolves ``get_chat_model`` from llm_utils globals at call time and
    # is therefore covered by the llm_utils patch.
    for module in (llm_utils, llm_base):
        wrap_module_callable(
            module,
            "get_chat_model",
            _with_frequency_penalty,
            expected_params=("model",),
        )
