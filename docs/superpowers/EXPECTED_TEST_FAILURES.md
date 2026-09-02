# Expected test failures (fork: exaforce runtime patches)

These upstream tests are kept at upstream parity on purpose and therefore
assert the *un-pruned* schema, which the exaforce runtime patch removes. They
are expected to FAIL. A failure here is only a problem if the failure is NOT an
assertion about a pruned key (e.g. an import/collection error).

Captured from:
`uv run pytest tests/nodes/test_llm_analyzer_base.py tests/nodes/test_semantic_quality_policy.py -q`

- tests/nodes/test_llm_analyzer_base.py::TestLLMAnalysisResult::test_to_finding
- tests/nodes/test_llm_analyzer_base.py::TestLLMAnalysisResult::test_model_dump
- tests/nodes/test_llm_analyzer_base.py::TestMetaAnalyzerResult::test_intent_validation
- tests/nodes/test_semantic_quality_policy.py::TestFixtureMaliciousSkill::test_malicious_skill_findings_preserve_metadata

All four fail with an `AssertionError` (or `KeyError`) about a pruned key
(`explanation`, `intent`) being absent — not an import/collection error.

## Severity floor (added 2026-09-02, `exaforce/_filter_patches.py`)

Upstream asserts that CRITICAL/HIGH *static* findings survive LLM filtering,
tagged `llm-unconfirmed`. The fork keeps that floor only for LLM-backed
findings (`SQP-*`, `SDI-*`, `SSD-*`, `TP4`) and lets the meta-analyzer overrule
static rules, so these fail under the default
`SKILLSPECTOR_META_SEVERITY_FLOOR=semantic` (and pass with `=upstream`):

- tests/nodes/test_llm_analyzer_base.py::TestApplyFilterSeverityFloor::test_critical_unconfirmed_kept_with_llm_unconfirmed_tag
- tests/nodes/test_llm_analyzer_base.py::TestApplyFilterSeverityFloor::test_high_unconfirmed_kept_with_llm_unconfirmed_tag
- tests/nodes/test_llm_analyzer_base.py::TestApplyFilterSeverityFloor::test_llm_unconfirmed_tag_not_duplicated
- tests/nodes/test_llm_analyzer_base.py::TestApplyFilterSeverityFloor::test_llm_unconfirmed_tag_surfaced_in_to_dict

Each fails on `assert len(result) == 1` / a missing `llm-unconfirmed` tag —
not an import/collection error. Note `.github/workflows/ci.yml` runs the full
suite via `make test-ci`, so fork CI is red by design (8 failures). Do not deselect, xfail, or
edit these upstream tests — that creates conflicts on every upstream sync.
Confirmed bounded to these two files via `uv run pytest -q -rf`:

```
8 failed, 1917 passed, 13 skipped, 38 deselected, 4 xfailed   (2026-09-02)
```
