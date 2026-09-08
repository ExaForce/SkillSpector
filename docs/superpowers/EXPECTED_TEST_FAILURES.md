# Expected test failures (fork: exaforce runtime patches)

`exaforce/_schema_patches` prunes keys from the LLM structured-output schema, so
the four upstream tests that assert the un-pruned shape fail. Those tests are
kept at upstream parity on purpose — no deselect markers, no `xfail`
decorators, no edits — so an upstream sync never conflicts in them.

They are marked `xfail(strict=True)` at collection time by the fork-owned
`conftest.py` at the repo root, which is not upstream-tracked. CI
(`.github/workflows/ci.yml` → `make test-ci`) therefore stays green, and the
expectation is machine-checked in both directions:

- a genuine new failure in one of these files still fails the run, instead of
  hiding inside a documented block of expected noise;
- if an upstream sync ever makes one of these pass again, `strict` turns the
  XPASS into a failure — so the stale entry gets noticed rather than quietly
  masking the fact that the fork patch no longer changes anything.

Keep this list in sync with `conftest.py`.

## Schema pruning (`exaforce/_schema_patches.py`)

Each fails with an `AssertionError` (or `KeyError`) about a pruned key
(`explanation`, `intent`) being absent — never an import/collection error.

- `tests/nodes/test_llm_analyzer_base.py::TestLLMAnalysisResult::test_to_finding`
- `tests/nodes/test_llm_analyzer_base.py::TestLLMAnalysisResult::test_model_dump`
- `tests/nodes/test_llm_analyzer_base.py::TestMetaAnalyzerResult::test_intent_validation`
- `tests/nodes/test_semantic_quality_policy.py::TestFixtureMaliciousSkill::test_malicious_skill_findings_preserve_metadata`

## Severity floor (`exaforce/_filter_patches.py`) — none in the default mode

`_filter_patches` lifts the CRITICAL/HIGH floor only for a finding that both
carries a `category` — i.e. came from a static rule, since `LLMFinding.to_finding`
sets none — and was actually adjudicated by the meta-analyzer. Every fixture in
upstream's `TestApplyFilterSeverityFloor` fails one of those two conditions:
the fixtures build a bare `Finding` with no `category`, and the omission cases
pass an empty verdict list, which keeps the upstream floor by design (see the
module docstring). So under the default `SKILLSPECTOR_META_SEVERITY_FLOOR=semantic`,
and under `=upstream`, upstream's assertions all still hold — and they still
exercise the floored path rather than passing vacuously.

The opt-in `=none` empties the floor for every finding regardless of source,
which inverts exactly one of them:

- `tests/nodes/test_llm_analyzer_base.py::TestApplyFilterSeverityFloor::test_critical_unconfirmed_kept_with_llm_unconfirmed_tag`

`conftest.py` marks that one only when the resolved mode is `none`, so the run
is green and strictly checked in all three modes.

Fork-side coverage of the three modes, the empty-verdict case, and the
`category` invariant that makes this work lives in
`tests/exaforce/test_patches.py`.

## Captured

`uv run pytest -m "not integration and not provider" tests/ -q` (2026-09-08):

```
1924 passed, 13 skipped, 38 deselected, 8 xfailed
```

The 8 xfailed are the 4 schema-pruning entries above plus 4 pre-existing
upstream xfails. With `SKILLSPECTOR_META_SEVERITY_FLOOR=none` it is
1923 passed / 9 xfailed. Nothing fails in any mode.
