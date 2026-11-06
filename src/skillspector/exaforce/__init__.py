# SPDX-License-Identifier: Apache-2.0
"""ExaForce fork-local runtime patches.

Keeps fork behavior — pruning unused LLM structured-output keys and prompt text
to shrink requests and reduce LLM timeouts, trusting the meta-analyzer LLM
verdict over static severity, the block threshold on the risk score, and the
lure-rule static analyzer — out of upstream-tracked source
files. All mutations are guarded: an upstream rename/rewrite raises ``PatchDriftError``
at import time rather than silently going stale.
"""

from __future__ import annotations

from . import (
    _filter_patches,
    _lure_rules,
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
    _lure_rules.apply()
    _PATCHED = True
