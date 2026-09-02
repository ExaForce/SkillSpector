def test_apply_patches_prunes_model_schemas(run_in_subprocess):
    out = run_in_subprocess(
        """
        import skillspector
        from skillspector.exaforce import apply_patches
        apply_patches()
        from skillspector.llm_analyzer_base import LLMFinding, LLMAnalysisResult
        from skillspector.nodes.meta_analyzer import (
            MetaAnalyzerFinding,
            MetaAnalyzerResult,
        )
        lf = set(LLMFinding.model_json_schema()["properties"])
        assert "explanation" not in lf and "remediation" not in lf, lf
        mf = set(MetaAnalyzerFinding.model_json_schema()["properties"])
        assert "intent" not in mf and "impact" not in mf, mf
        mr = set(MetaAnalyzerResult.model_json_schema()["properties"])
        assert "overall_assessment" not in mr, mr
        # Container schema (what the LLM actually receives) is pruned too:
        nested = LLMAnalysisResult.model_json_schema()["$defs"]["LLMFinding"]["properties"]
        assert "explanation" not in nested, nested
        nested_meta = MetaAnalyzerResult.model_json_schema()["$defs"]["MetaAnalyzerFinding"]["properties"]
        assert "intent" not in nested_meta and "impact" not in nested_meta, nested_meta
        print("OK")
        """
    )
    assert "OK" in out


def test_apply_patches_prunes_to_finding_and_dump(run_in_subprocess):
    out = run_in_subprocess(
        """
        import skillspector
        from skillspector.exaforce import apply_patches
        apply_patches()
        from skillspector.llm_analyzer_base import LLMFinding
        f = LLMFinding(rule_id="R", message="m", severity="LOW", start_line=3)
        assert "explanation" not in f.model_dump()
        assert "remediation" not in f.model_dump()
        fin = f.to_finding("x.py")
        assert fin.explanation is None
        assert fin.remediation is None
        assert fin.rule_id == "R" and fin.start_line == 3
        print("OK")
        """
    )
    assert "OK" in out


def test_apply_patches_trims_prompts(run_in_subprocess):
    out = run_in_subprocess(
        """
        import skillspector
        from skillspector.exaforce import apply_patches
        apply_patches()
        from skillspector.nodes.analyzers import semantic_developer_intent as d
        from skillspector.nodes.analyzers import semantic_quality_policy as q
        from skillspector.nodes import meta_analyzer as m
        assert "Reference the L-prefixed line numbers" not in d.ANALYZER_PROMPT
        assert "Reference the L-prefixed line numbers" not in q.ANALYZER_PROMPT
        assert "What is the likely intent" not in m.PER_FILE_ANALYSIS_PROMPT
        assert "What is the potential impact" not in m.PER_FILE_ANALYSIS_PROMPT
        assert "Use the rule IDs exactly as listed." in d.ANALYZER_PROMPT
        print("OK")
        """
    )
    assert "OK" in out


def test_apply_patches_is_idempotent(run_in_subprocess):
    out = run_in_subprocess(
        """
        import skillspector
        from skillspector.exaforce import apply_patches
        apply_patches()
        apply_patches()
        apply_patches()
        print("OK")
        """
    )
    assert "OK" in out


_FLOOR_HARNESS = """
    import os
    os.environ["SKILLSPECTOR_META_SEVERITY_FLOOR"] = {mode!r}
    from unittest.mock import MagicMock, patch
    import skillspector
    from skillspector.exaforce import apply_patches
    apply_patches()
    from skillspector.llm_analyzer_base import Batch
    from skillspector.models import Finding
    from skillspector.nodes.meta_analyzer import LLMMetaAnalyzer

    def _finding(rule_id, severity, line):
        return Finding(
            rule_id=rule_id, message="msg", severity=severity,
            confidence=0.8, file="skill.md", start_line=line,
        )

    with patch("skillspector.llm_analyzer_base.get_chat_model", lambda **kw: MagicMock()):
        analyzer = LLMMetaAnalyzer(model="test-model")

    # Static rules (regex/YARA style ids) and semantic rules (SQP/SDI/SSD), each
    # with a CRITICAL the LLM explicitly denies, a HIGH the LLM omits, and a
    # MEDIUM the LLM confirms.
    findings = [
        _finding("E2", "CRITICAL", 10), _finding("PE3", "HIGH", 11), _finding("P1", "MEDIUM", 12),
        _finding("SDI-1", "CRITICAL", 20), _finding("SSD-1", "HIGH", 21), _finding("SQP-2", "MEDIUM", 22),
        _finding("TP4", "HIGH", 30),  # LLM-backed but not prefix-named; LLM omits it
    ]
    batch = Batch(file_path="skill.md", content="code", findings=findings)
    llm_items = [
        {{"pattern_id": "E2", "start_line": 10, "is_vulnerability": False, "confidence": 0.2, "_file": "skill.md"}},
        {{"pattern_id": "P1", "start_line": 12, "is_vulnerability": True, "confidence": 0.9, "_file": "skill.md"}},
        {{"pattern_id": "SDI-1", "start_line": 20, "is_vulnerability": False, "confidence": 0.2, "_file": "skill.md"}},
        {{"pattern_id": "SQP-2", "start_line": 22, "is_vulnerability": True, "confidence": 0.9, "_file": "skill.md"}},
    ]
    result = analyzer.apply_filter(findings, [(batch, llm_items)])
    kept = [f.rule_id for f in result]
    unconfirmed = sorted(f.rule_id for f in result if "llm-unconfirmed" in f.tags)
    assert kept == {expected_kept!r}, kept
    assert unconfirmed == {expected_unconfirmed!r}, unconfirmed
    print("OK")
"""


def test_floor_mode_none_drops_every_unconfirmed_finding(run_in_subprocess):
    out = run_in_subprocess(
        _FLOOR_HARNESS.format(
            mode="none",
            expected_kept=["P1", "SQP-2"],
            expected_unconfirmed=[],
        )
    )
    assert "OK" in out


def test_floor_mode_semantic_keeps_only_semantic_high_severity(run_in_subprocess):
    """Static CRITICAL/HIGH follow the LLM verdict; semantic CRITICAL/HIGH keep the
    upstream floor. Output order matches input order despite the two-pass filter."""
    out = run_in_subprocess(
        _FLOOR_HARNESS.format(
            mode="semantic",
            expected_kept=["P1", "SDI-1", "SSD-1", "SQP-2", "TP4"],
            expected_unconfirmed=["SDI-1", "SSD-1", "TP4"],
        )
    )
    assert "OK" in out


def test_floor_mode_upstream_is_untouched(run_in_subprocess):
    out = run_in_subprocess(
        _FLOOR_HARNESS.format(
            mode="upstream",
            expected_kept=["E2", "PE3", "P1", "SDI-1", "SSD-1", "SQP-2", "TP4"],
            expected_unconfirmed=["E2", "PE3", "SDI-1", "SSD-1", "TP4"],
        )
    )
    assert "OK" in out


def test_floor_mode_default_is_semantic_and_switchable_at_runtime(run_in_subprocess):
    """Mode is read per apply_filter call, so an in-process A/B can flip it after import."""
    out = run_in_subprocess(
        """
        import os
        os.environ.pop("SKILLSPECTOR_META_SEVERITY_FLOOR", None)
        from unittest.mock import MagicMock, patch
        import skillspector
        from skillspector.exaforce import _filter_patches
        from skillspector.llm_analyzer_base import Batch
        from skillspector.models import Finding
        from skillspector.nodes.meta_analyzer import LLMMetaAnalyzer
        assert _filter_patches.resolve_mode() == "semantic"
        assert getattr(LLMMetaAnalyzer.apply_filter, "_exaforce_wrapped", False)
        with patch("skillspector.llm_analyzer_base.get_chat_model", lambda **kw: MagicMock()):
            analyzer = LLMMetaAnalyzer(model="test-model")
        f = Finding(rule_id="E2", message="m", severity="CRITICAL", confidence=0.8,
                    file="skill.md", start_line=1)
        batch = Batch(file_path="skill.md", content="c", findings=[f])
        denied = [{"pattern_id": "E2", "start_line": 1, "is_vulnerability": False,
                   "confidence": 0.1, "_file": "skill.md"}]
        assert analyzer.apply_filter([f], [(batch, denied)]) == []           # semantic: static dropped
        os.environ["SKILLSPECTOR_META_SEVERITY_FLOOR"] = "upstream"
        assert len(analyzer.apply_filter([f], [(batch, denied)])) == 1       # upstream: floor kept
        os.environ["SKILLSPECTOR_META_SEVERITY_FLOOR"] = "none"
        assert analyzer.apply_filter([f], [(batch, denied)]) == []
        assert "_HIGH_SEVERITY_FLOOR" not in analyzer.__dict__               # instance state restored
        print("OK")
        """
    )
    assert "OK" in out
