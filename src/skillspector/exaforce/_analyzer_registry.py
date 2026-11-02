# SPDX-License-Identifier: Apache-2.0
"""Register fork-owned analyzer nodes into the upstream workflow graph.

Upstream ``graph.create_graph()`` iterates ``nodes.analyzers.ANALYZER_NODE_IDS`` and
``ANALYZER_NODES`` at call time, so a fork analyzer is added by mutating both in place.
The package ``skillspector/__init__`` compiles the module-level ``graph`` *before*
``apply_patches()`` runs, and the CLI / benchmark runner invoke that object, so every
new registration also rebuilds it.

Each registered node is wrapped with an ``enabled()`` check read on every call; when it
is false the node reports the same "disabled by configuration" status upstream's LLM
analyzers report under ``use_llm=False``, keeping the inspection ledger consistent.
"""

from __future__ import annotations

import functools
import sys
from collections.abc import Callable
from types import ModuleType

from skillspector.inspection_ledger import LedgerReason, analyzer_status_event
from skillspector.nodes import analyzers

from ._patchlib import PatchDriftError

_MARK = "_exaforce_analyzer_id"


def _disabled_response(analyzer_id: str) -> dict[str, object]:
    return {
        "findings": [],
        "inspection_ledger": [],
        "analyzer_status_events": [
            analyzer_status_event(
                analyzer_id=analyzer_id,
                status="disabled",
                reason=LedgerReason.DISABLED_BY_CONFIGURATION,
            )
        ],
    }


def _wrap(analyzer_id: str, node: Callable, enabled: Callable[[], bool]) -> Callable:
    @functools.wraps(node)
    def wrapper(state):
        if not enabled():
            return _disabled_response(analyzer_id)
        return node(state)

    setattr(wrapper, _MARK, analyzer_id)
    wrapper._exaforce_node = node  # type: ignore[attr-defined]
    wrapper._exaforce_enabled = enabled  # type: ignore[attr-defined]
    return wrapper


def _rebuild_compiled_graphs() -> None:
    """Recompile the module-level graph (and the package re-export) from the registry."""
    graph_mod = sys.modules.get("skillspector.graph")
    if graph_mod is None:
        return  # not imported yet: create_graph() will read the mutated registry
    compiled = graph_mod.create_graph()
    graph_mod.graph = compiled
    package = sys.modules.get("skillspector")
    if package is not None and not isinstance(
        getattr(package, "graph", None), (ModuleType, type(None))
    ):
        package.graph = compiled


def register_analyzer(analyzer_id: str, node: Callable, *, enabled: Callable[[], bool]) -> None:
    """Idempotently add ``node`` as analyzer ``analyzer_id``, gated by ``enabled()``.

    Re-registering the same ``node`` and ``enabled`` objects is a no-op; a different
    ``node`` or ``enabled`` replaces the fork wrapper and rebuilds the graph. Raises
    ``PatchDriftError`` if upstream already owns ``analyzer_id``.
    """
    ids, nodes = analyzers.ANALYZER_NODE_IDS, analyzers.ANALYZER_NODES
    if not isinstance(ids, list) or not isinstance(nodes, dict):
        raise PatchDriftError(
            "skillspector.nodes.analyzers registry is no longer a list/dict; "
            "upstream changed — update the exaforce patch."
        )
    existing = nodes.get(analyzer_id)
    if existing is not None:
        if getattr(existing, _MARK, None) != analyzer_id:
            raise PatchDriftError(
                f"analyzer id {analyzer_id!r} is already registered upstream; "
                "rename the exaforce analyzer."
            )
        if (
            getattr(existing, "_exaforce_node", None) is node
            and getattr(existing, "_exaforce_enabled", None) is enabled
            and ids.count(analyzer_id) == 1
        ):
            return
    nodes[analyzer_id] = _wrap(analyzer_id, node, enabled)
    if analyzer_id not in ids:
        ids.append(analyzer_id)
    _rebuild_compiled_graphs()
