"""Tests for the fork analyzer registry (register_analyzer) and graph rebuild."""

import sys

import pytest

import skillspector
import skillspector.exaforce  # noqa: F401  (applies the patches)
from skillspector.graph import create_graph
from skillspector.inspection_ledger import LedgerReason, analyzer_status_event
from skillspector.nodes import analyzers

HIDDEN_ID = "exaforce_hidden_text"
DUMMY_ID = "exaforce_test_dummy"


def _graph_node_ids(compiled) -> set[str]:
    return set(compiled.get_graph().nodes)


@pytest.fixture
def restore_registry():
    """Undo any registration a test makes, restoring the original compiled graphs."""
    ids = list(analyzers.ANALYZER_NODE_IDS)
    nodes = dict(analyzers.ANALYZER_NODES)
    graph_mod = sys.modules["skillspector.graph"]
    module_graph, package_graph = graph_mod.graph, skillspector.graph
    yield
    analyzers.ANALYZER_NODE_IDS[:] = ids
    analyzers.ANALYZER_NODES.clear()
    analyzers.ANALYZER_NODES.update(nodes)
    graph_mod.graph, skillspector.graph = module_graph, package_graph


def _dummy_node(state):
    return {"findings": [], "inspection_ledger": [], "analyzer_status_events": ["ran"]}


def test_register_analyzer_adds_node_once(restore_registry):
    from skillspector.exaforce._analyzer_registry import register_analyzer

    register_analyzer(DUMMY_ID, _dummy_node, enabled=lambda: True)
    first_graph = sys.modules["skillspector.graph"].graph
    register_analyzer(DUMMY_ID, _dummy_node, enabled=lambda: True)

    assert analyzers.ANALYZER_NODE_IDS.count(DUMMY_ID) == 1
    assert DUMMY_ID in analyzers.ANALYZER_NODES
    # Rebuilt once on the new registration; the idempotent repeat does not rebuild.
    assert sys.modules["skillspector.graph"].graph is first_graph
    assert DUMMY_ID in _graph_node_ids(first_graph)
    assert skillspector.graph is first_graph


def test_register_analyzer_rejects_foreign_id(restore_registry):
    from skillspector.exaforce._analyzer_registry import register_analyzer
    from skillspector.exaforce._patchlib import PatchDriftError

    with pytest.raises(PatchDriftError):
        register_analyzer("static_patterns_ssrf", _dummy_node, enabled=lambda: True)


def test_registered_node_disabled_returns_disabled_status(restore_registry):
    from skillspector.exaforce._analyzer_registry import register_analyzer

    on = {"value": False}
    register_analyzer(DUMMY_ID, _dummy_node, enabled=lambda: on["value"])
    wrapped = analyzers.ANALYZER_NODES[DUMMY_ID]

    assert wrapped({}) == {
        "findings": [],
        "inspection_ledger": [],
        "analyzer_status_events": [
            analyzer_status_event(
                analyzer_id=DUMMY_ID,
                status="disabled",
                reason=LedgerReason.DISABLED_BY_CONFIGURATION,
            )
        ],
    }
    on["value"] = True
    assert wrapped({})["analyzer_status_events"] == ["ran"]


def test_hidden_text_node_disabled_without_flag(monkeypatch):
    monkeypatch.delenv("SKILLSPECTOR_EXA_HIDDEN_TEXT", raising=False)
    response = analyzers.ANALYZER_NODES[HIDDEN_ID]({"components": ["SKILL.md"]})
    assert response["findings"] == []
    assert response["analyzer_status_events"][0]["status"] == "disabled"


def test_graph_includes_registered_node():
    assert analyzers.ANALYZER_NODE_IDS.count(HIDDEN_ID) == 1
    assert HIDDEN_ID in _graph_node_ids(create_graph())
    # The graph compiled at package import time (before apply_patches) is rebuilt.
    assert HIDDEN_ID in _graph_node_ids(sys.modules["skillspector.graph"].graph)
    assert HIDDEN_ID in _graph_node_ids(skillspector.graph)


def test_fresh_interpreter_module_graph_has_node(run_in_subprocess):
    out = run_in_subprocess(
        """
        from skillspector.graph import graph
        from skillspector import cli
        print("exaforce_hidden_text" in graph.get_graph().nodes)
        print("exaforce_hidden_text" in cli.graph.get_graph().nodes)
        """
    )
    assert out.split() == ["True", "True"]
