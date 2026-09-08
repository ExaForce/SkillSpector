# SPDX-License-Identifier: Apache-2.0
"""Fork-owned pytest hook: xfail the upstream tests the exaforce patches invert.

``exaforce/_schema_patches`` prunes keys from the LLM structured-output schema,
so the upstream tests that assert the un-pruned shape fail.

Fork policy is to keep upstream test files byte-identical — no deselect
markers, no ``xfail`` decorators, no edits — so an upstream sync never
conflicts in them. This file satisfies that: it lives at the repo root, is not
upstream-tracked, and attaches the marker at collection time.

``strict=True`` is the point. A doc that merely lists the expected failures
cannot tell a genuine regression from the expected noise, and cannot notice
when an upstream sync makes one of these pass again. Under strict xfail both
show up: an unexpected failure elsewhere in the file still fails the run, and
an XPASS here fails too — meaning the fork patch no longer changes this
behavior, so re-check the patch and drop the entry.

``exaforce/_filter_patches`` needs no entry in its default ``semantic`` mode.
It lifts the CRITICAL/HIGH floor only for a finding that both carries a
``category`` (i.e. came from a static rule) and was actually adjudicated by the
meta-analyzer; every fixture in upstream's ``TestApplyFilterSeverityFloor``
fails one of those two conditions, so those tests still pass. Under the opt-in
``SKILLSPECTOR_META_SEVERITY_FLOOR=none`` the floor is empty for everything,
which does invert one of them — marked conditionally below, so the run stays
green and strictly checked in that mode too. Fork-side coverage lives in
``tests/exaforce/test_patches.py``.

Keep this list in sync with ``docs/superpowers/EXPECTED_TEST_FAILURES.md``.
"""

from __future__ import annotations

import pytest

_SCHEMA_PRUNING_REASON = (
    "exaforce _schema_patches prunes explanation/remediation/intent from the "
    "LLM structured-output schema; upstream asserts the un-pruned shape"
)

_NO_FLOOR_REASON = (
    "SKILLSPECTOR_META_SEVERITY_FLOOR=none empties the floor for every finding, "
    "including LLM-backed ones; upstream asserts the floor"
)

_SCHEMA_PRUNING = (
    "tests/nodes/test_llm_analyzer_base.py::TestLLMAnalysisResult::test_to_finding",
    "tests/nodes/test_llm_analyzer_base.py::TestLLMAnalysisResult::test_model_dump",
    "tests/nodes/test_llm_analyzer_base.py::TestMetaAnalyzerResult::test_intent_validation",
    "tests/nodes/test_semantic_quality_policy.py::TestFixtureMaliciousSkill"
    "::test_malicious_skill_findings_preserve_metadata",
)

# Only inverted by the fully-empty floor; passes under "semantic" and "upstream".
_NO_FLOOR_ONLY = (
    "tests/nodes/test_llm_analyzer_base.py::TestApplyFilterSeverityFloor"
    "::test_critical_unconfirmed_kept_with_llm_unconfirmed_tag",
)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Attach ``xfail(strict=True)`` to the upstream tests the fork patches invert."""
    from skillspector.exaforce._filter_patches import resolve_mode

    expected = dict.fromkeys(_SCHEMA_PRUNING, _SCHEMA_PRUNING_REASON)
    if resolve_mode() == "none":
        expected.update(dict.fromkeys(_NO_FLOOR_ONLY, _NO_FLOOR_REASON))
    for item in items:
        reason = expected.get(item.nodeid)
        if reason is not None:
            item.add_marker(pytest.mark.xfail(reason=reason, strict=True))
