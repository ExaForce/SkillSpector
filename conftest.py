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

``exaforce/_analyzer_registry`` appends fork analyzers to ``ANALYZER_NODE_IDS``
on every import, so upstream's exact-list registry assertion is inverted in all
modes.

``exaforce/_score_patches`` defaults the block threshold to 49, so a score of 50
bands HIGH / ``DO_NOT_INSTALL`` where upstream's ``test_report`` tests expect
MEDIUM / ``CAUTION``, and the score is clamped to 51 (a block) where they expect 50. Marked conditionally below, only while the effective
threshold (``block_threshold()``) is <= 50. The entries are calibrated for the default
(49) and for 51 (upstream, unmarked, passes); other values are not guaranteed green.

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

_ANALYZER_REGISTRY_REASON = (
    "exaforce _analyzer_registry appends fork analyzers (exaforce_lure_rules) to "
    "ANALYZER_NODE_IDS; upstream asserts the fixed upstream list"
)

_SCHEMA_PRUNING = (
    "tests/nodes/test_llm_analyzer_base.py::TestLLMAnalysisResult::test_to_finding",
    "tests/nodes/test_llm_analyzer_base.py::TestLLMAnalysisResult::test_model_dump",
    "tests/nodes/test_llm_analyzer_base.py::TestMetaAnalyzerResult::test_intent_validation",
    "tests/nodes/test_semantic_quality_policy.py::TestFixtureMaliciousSkill"
    "::test_malicious_skill_findings_preserve_metadata",
)

_ANALYZER_REGISTRY = (
    "tests/nodes/analyzers/test_registry.py::TestAnalyzerRegistry"
    "::test_analyzer_node_ids_match_expected",
)

# Only inverted by the fully-empty floor; passes under "semantic" and "upstream".
_NO_FLOOR_ONLY = (
    "tests/nodes/test_llm_analyzer_base.py::TestApplyFilterSeverityFloor"
    "::test_critical_unconfirmed_kept_with_llm_unconfirmed_tag",
)

_BLOCK_THRESHOLD_REASON = (
    "exaforce _score_patches blocks at a threshold of 49 by default, so a score of 50 "
    "bands HIGH/DO_NOT_INSTALL (score lifted to 51); upstream asserts 50, MEDIUM/CAUTION"
)

# Only inverted while the effective block threshold is <= 50.
_BLOCK_THRESHOLD_ONLY = (
    "tests/nodes/test_report.py::TestReportNode::test_report_critical_finding_medium_band",
    "tests/nodes/test_report.py::test_report_doc_findings_no_multiplier",
    "tests/nodes/test_report.py::TestComputeRiskScoreBasic"
    "::test_single_finding_full_confidence_scores_base_points[CRITICAL-50]",
    "tests/nodes/test_report.py::test_report_baseline_keeps_unmatched_finding",
    "tests/nodes/test_report.py::test_report_no_baseline_unchanged",
)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Attach ``xfail(strict=True)`` to the upstream tests the fork patches invert."""
    from skillspector.exaforce._filter_patches import resolve_mode
    from skillspector.exaforce._score_patches import block_threshold

    expected = dict.fromkeys(_SCHEMA_PRUNING, _SCHEMA_PRUNING_REASON)
    expected.update(dict.fromkeys(_ANALYZER_REGISTRY, _ANALYZER_REGISTRY_REASON))
    if resolve_mode() == "none":
        expected.update(dict.fromkeys(_NO_FLOOR_ONLY, _NO_FLOOR_REASON))
    if block_threshold() <= 50:
        expected.update(dict.fromkeys(_BLOCK_THRESHOLD_ONLY, _BLOCK_THRESHOLD_REASON))
    for item in items:
        reason = expected.get(item.nodeid)
        if reason is not None:
            item.add_marker(pytest.mark.xfail(reason=reason, strict=True))
