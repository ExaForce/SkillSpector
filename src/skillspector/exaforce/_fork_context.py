# SPDX-License-Identifier: Apache-2.0
"""Shared ``static_runner.is_code_example`` bypass for fork static analyzers.

Upstream ``static_runner`` drops a markdown/text finding whose context "looks like an example"
(contains "such as", "e.g.", ...). A fork analyzer whose finding contexts start with
``FORK_CONTEXT_PREFIX`` is exempt from that drop. For the lure rules the context is the matched
line, so the reason is evasion: an attacker can append "# e.g." or "such as" to the lure line in
a non-executable file and the drop would hide the finding.
"""

from __future__ import annotations

import inspect

from skillspector.nodes.analyzers import static_runner

from ._patchlib import PatchDriftError, intercept_module_callable

FORK_CONTEXT_PREFIX = "[exaforce: "


def _code_example_interceptor(original, args: tuple, kwargs: dict) -> object:
    # apply() checked that ``context`` is the first parameter, so no per-call binding.
    context = args[0] if args else kwargs.get("context")
    if isinstance(context, str) and context.startswith(FORK_CONTEXT_PREFIX):
        return False
    return original(*args, **kwargs)


def apply() -> None:
    """Install the bypass (idempotent)."""
    params = list(inspect.signature(static_runner.is_code_example).parameters)
    if params[:1] != ["context"]:
        raise PatchDriftError(
            "static_runner.is_code_example no longer takes `context` first; "
            "upstream changed — update the exaforce patch."
        )
    # static_runner._scan_path calls its module-global is_code_example by name.
    intercept_module_callable(
        static_runner, "is_code_example", _code_example_interceptor, expected_params=("context",)
    )
