# SPDX-License-Identifier: Apache-2.0
"""ExaForce fork-local runtime patches.

Keeps fork behavior — pruning unused LLM structured-output keys and prompt text
to shrink requests and reduce LLM timeouts, trusting the meta-analyzer LLM
verdict over static severity, and the flag-gated semantic block gate and
documentation-finding cap on the risk score — out of upstream-tracked source
files. All mutations are guarded: an upstream rename/rewrite raises ``PatchDriftError``
at import time rather than silently going stale.
"""

from __future__ import annotations

from . import (
    _build_context_patches,
    _context_patches,
    _filter_patches,
    _hidden_text,
    _instruction_flow,
    _prompt_patches,
    _sampling_patches,
    _schema_patches,
    _score_patches,
)

_PATCHED = False


def apply_patches() -> None:
    """Idempotently apply all fork-local runtime patches."""
    global _PATCHED
    if _PATCHED:
        return
    _schema_patches.apply()
    _prompt_patches.apply()
    _sampling_patches.apply()
    _filter_patches.apply()
    _score_patches.apply()
    _build_context_patches.apply()
    _hidden_text.apply()
    _context_patches.apply()
    _instruction_flow.apply()
    _PATCHED = True
