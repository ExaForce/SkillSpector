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

    # ``category`` is what separates the two sources, so the fixture mirrors how
    # findings are really built: static analyzers always end up with one
    # (``analyzer_finding_to_finding`` falls back to "Security"), the semantic
    # analyzers' ``LLMFinding.to_finding`` sets none, and ``TP4`` is hand-built
    # with one. See test_llm_findings_have_no_category for the invariant.
    def _finding(rule_id, severity, line, category="Security"):
        return Finding(
            rule_id=rule_id, message="msg", severity=severity,
            confidence=0.8, file="skill.md", start_line=line, category=category,
        )

    with patch("skillspector.llm_analyzer_base.get_chat_model", lambda **kw: MagicMock()):
        analyzer = LLMMetaAnalyzer(model="test-model")

    # Static rules (regex/YARA style ids) and semantic rules (SQP/SDI/SSD), each
    # with a CRITICAL the LLM explicitly denies, a HIGH the LLM omits, and a
    # MEDIUM the LLM confirms.
    findings = [
        _finding("E2", "CRITICAL", 10), _finding("PE3", "HIGH", 11), _finding("P1", "MEDIUM", 12),
        _finding("SDI-1", "CRITICAL", 20, None), _finding("SSD-1", "HIGH", 21, None),
        _finding("SQP-2", "MEDIUM", 22, None),
        _finding("TP4", "HIGH", 30),  # LLM-backed, but carries a category; LLM omits it
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
                    file="skill.md", start_line=1, category="Security")
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


def test_empty_verdict_batch_keeps_the_upstream_floor(run_in_subprocess):
    """A batch that returns successfully but adjudicates nothing must not clear the file.

    Upstream counts an empty verdict list as "nothing confirmed", so lifting the
    floor would drop every finding in that batch — a truncated or degenerate
    decode that still validates against the schema would silently report a
    malicious file clean. Those findings keep the upstream floor instead:
    CRITICAL/HIGH retained and tagged, MEDIUM/LOW dropped, exactly as upstream.
    """
    out = run_in_subprocess(
        """
        import os
        os.environ["SKILLSPECTOR_META_SEVERITY_FLOOR"] = "none"   # the most aggressive mode
        from unittest.mock import MagicMock, patch
        import skillspector
        from skillspector.llm_analyzer_base import Batch
        from skillspector.models import Finding
        from skillspector.nodes.meta_analyzer import LLMMetaAnalyzer

        with patch("skillspector.llm_analyzer_base.get_chat_model", lambda **kw: MagicMock()):
            analyzer = LLMMetaAnalyzer(model="test-model")

        def _finding(rule_id, severity, file, line):
            return Finding(rule_id=rule_id, message="m", severity=severity,
                           confidence=0.8, file=file, start_line=line,
                           category="Security")

        # a.py: the LLM returned an empty verdict list. b.py: a real denial.
        empty = [_finding("E2", "CRITICAL", "a.py", 1), _finding("P1", "MEDIUM", "a.py", 2)]
        adjudicated = [_finding("PE3", "HIGH", "b.py", 5)]
        batch_a = Batch(file_path="a.py", content="c", findings=empty)
        batch_b = Batch(file_path="b.py", content="c", findings=adjudicated)
        denied_b = [{"pattern_id": "PE3", "start_line": 5, "is_vulnerability": False,
                     "confidence": 0.1, "_file": "b.py"}]

        result = analyzer.apply_filter(
            empty + adjudicated, [(batch_a, []), (batch_b, denied_b)]
        )
        kept = [f.rule_id for f in result]
        # E2 survives the empty verdict on the floor and is tagged; P1 is MEDIUM so
        # the floor does not cover it; PE3 was genuinely adjudicated and follows the
        # verdict even though it is HIGH.
        assert kept == ["E2"], kept
        assert "llm-unconfirmed" in result[0].tags, result[0].tags
        print("OK")
        """
    )
    assert "OK" in out


def test_llm_findings_have_no_category_and_static_findings_do(run_in_subprocess):
    """The invariant ``is_llm_finding`` relies on, asserted against real constructors.

    If an upstream sync starts setting ``category`` on LLM findings, or stops
    setting it on static ones, the semantic mode silently mis-routes findings.
    This fails instead.
    """
    out = run_in_subprocess(
        """
        import skillspector           # applies the fork patches, incl. pruned to_finding
        from skillspector.exaforce._filter_patches import is_llm_finding
        from skillspector.llm_analyzer_base import LLMFinding
        from skillspector.nodes.analyzers.static_runner import analyzer_finding_to_finding
        from skillspector.models import AnalyzerFinding, Location, Severity

        llm = LLMFinding(rule_id="SSD-2", message="m", severity="CRITICAL",
                         confidence=0.9, start_line=1).to_finding("skill.md")
        assert llm.category is None, llm.category
        assert is_llm_finding(llm)

        # A rule id no LLM prefix matches still routes as LLM-backed on category
        # alone — the fail-safe direction (floor retained, never silently lost).
        odd = LLMFinding(rule_id="Semantic-Prompt-Injection", message="m",
                         severity="CRITICAL", confidence=0.9, start_line=1).to_finding("s.md")
        assert is_llm_finding(odd)

        static = analyzer_finding_to_finding(
            AnalyzerFinding(rule_id="YR1", message="m", severity=Severity.HIGH,
                            confidence=0.9, location=Location(file="SKILL.md", start_line=65))
        )
        assert static.category is not None, static.category
        assert not is_llm_finding(static)

        # An unmapped static rule id must still get a category, so it does not
        # fall through to the LLM branch by accident.
        unmapped = analyzer_finding_to_finding(
            AnalyzerFinding(rule_id="ZZ-999", message="m", severity=Severity.HIGH,
                            confidence=0.9, location=Location(file="SKILL.md", start_line=1))
        )
        assert unmapped.category is not None, unmapped.category
        print("OK")
        """
    )
    assert "OK" in out


def test_import_survives_unreadable_apply_filter_source(run_in_subprocess):
    """The drift guard reads ``inspect.getsource``; no source must not kill the CLI.

    Under zipimport, a frozen build, or a ``.pyc``-only deploy, ``getsource``
    raises ``OSError``. That must not propagate out of ``import skillspector``.
    """
    out = run_in_subprocess(
        """
        import inspect
        _real = inspect.getsource
        def _boom(obj):
            raise OSError("could not get source code")
        inspect.getsource = _boom
        try:
            import skillspector          # must not raise
            from skillspector.nodes.meta_analyzer import LLMMetaAnalyzer
            assert getattr(LLMMetaAnalyzer.apply_filter, "_exaforce_wrapped", False)
        finally:
            inspect.getsource = _real
        print("OK")
        """
    )
    assert "OK" in out
