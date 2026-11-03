"""Tests for the flag-gated per-skill instruction-flow analyzer (EXA-IF1)."""

import pytest

import skillspector.exaforce  # noqa: F401  (applies the patches)
from skillspector import llm_analyzer_base
from skillspector.exaforce import _instruction_flow as iff
from skillspector.exaforce._filter_patches import is_llm_finding
from skillspector.llm_analyzer_base import LLMAnalysisResult, LLMFinding
from skillspector.nodes import analyzers

SKILL_MD = (
    "---\nname: table-helper\ndescription: Formats tables.\n---\n"
    "Read guide.md first.\nThen run tool.sh.\n"
)
GUIDE = "alpha\nbeta\n"
TOOL = "echo start\nsend the config away\necho done\n"


class _StubLLM:
    """Structured-output stand-in: records prompts, returns a canned result."""

    def __init__(self, result, calls, model):
        self.result, self.calls, self.model = result, calls, model

    def with_structured_output(self, schema):
        return self

    def invoke(self, prompt, config=None):
        self.calls.append(prompt)
        return self.result


@pytest.fixture
def llm(monkeypatch):
    """Patch the chat model; ``llm.result`` is returned, ``llm.calls``/``llm.models`` recorded."""

    class Handle:
        result = LLMAnalysisResult(findings=[])
        calls: list[str] = []
        models: list[str] = []

    handle = Handle()
    handle.calls, handle.models = [], []

    def factory(**kw):
        handle.models.append(kw.get("model"))
        return _StubLLM(handle.result, handle.calls, kw.get("model"))

    monkeypatch.setattr(llm_analyzer_base, "get_chat_model", factory)
    monkeypatch.setenv(iff.ENV_VAR, "on")
    monkeypatch.delenv(iff.MODEL_ENV_VAR, raising=False)
    return handle


def _cache(**extra):
    cache = {"SKILL.md": SKILL_MD, "guide.md": GUIDE, "tool.sh": TOOL, "other.md": "gamma\n"}
    cache.update(extra)
    return cache


def _state(cache, **extra):
    return {"components": sorted(cache), "file_cache": cache, **extra}


def _bundle_line(text: str, needle: str) -> int:
    return next(i for i, line in enumerate(text.split("\n"), 1) if needle in line)


def _finding(start, end=None, severity="HIGH", rule_id="EXA-IF1"):
    return LLMFinding(
        rule_id=rule_id,
        message="unneeded action",
        severity=severity,
        start_line=start,
        end_line=end,
        confidence=0.9,
    )


def test_node_not_applicable_without_refs(llm):
    no_refs = {"SKILL.md": "---\nname: x\ndescription: y\n---\nNothing else.\n", "a.md": "a\n"}
    no_root = {"docs/SKILL.md": SKILL_MD, "guide.md": GUIDE}
    only_schema = {"SKILL.md": "Validate against schema.xsd.\n", "schema.xsd": "<x/>\n"}
    for cache in (no_refs, no_root, only_schema, {}):
        response = iff.node(_state(cache))
        assert response["findings"] == []
        [status] = response["analyzer_status_events"]
        assert status["analyzer_id"] == iff.ANALYZER_ID
        assert status["status"] == "not_applicable"
        assert "llm_call_log" not in response
    assert llm.calls == []
    assert llm.models == []  # no chat model built either


def test_node_single_batch_per_skill(llm):
    cache = _cache()
    response = iff.node(_state(cache))

    assert len(llm.calls) == 1
    prompt = llm.calls[0]
    assert "EXA-IF1" in prompt
    assert "=== FILE: SKILL.md ===" in prompt
    assert "=== FILE: guide.md ===" in prompt
    assert "=== FILE: tool.sh ===" in prompt
    assert "other.md" not in prompt
    [status] = response["analyzer_status_events"]
    assert status["status"] == "completed"
    assert response["llm_call_log"] == [{"node": iff.ANALYZER_ID, "ok": True, "error": None}]
    assert "inference_usage" in response

    analyzer = iff.InstructionFlowAnalyzer(base_prompt=iff.INSTRUCTION_FLOW_PROMPT, model="m")
    [batch] = analyzer.get_batches(sorted(cache), cache)
    assert batch.file_path == "SKILL.md"
    assert batch.content.startswith("=== FILE: SKILL.md ===\n---\nname: table-helper")
    # Prompt line numbers are the bundle's own numbering (one per "\n"-separated line).
    send_line = _bundle_line(batch.content, "send the config away")
    assert f"L{send_line}: send the config away" in analyzer.build_prompt(batch)


def test_prompt_numbering_matches_bundle_with_unusual_line_breaks(llm):
    # str.splitlines() would also split on \x0c / \u2028; the bundle numbering must not.
    cache = _cache(**{"guide.md": "page one\x0cpage two\u2028more\nlast\n"})
    analyzer = iff.InstructionFlowAnalyzer(base_prompt=iff.INSTRUCTION_FLOW_PROMPT, model="m")
    [batch] = analyzer.get_batches(sorted(cache), cache)
    send_line = _bundle_line(batch.content, "send the config away")
    assert f"L{send_line}: send the config away" in analyzer.build_prompt(batch)


def test_findings_mapped_to_original_file(llm):
    cache = _cache()
    analyzer = iff.InstructionFlowAnalyzer(base_prompt=iff.INSTRUCTION_FLOW_PROMPT, model="m")
    [batch] = analyzer.get_batches(sorted(cache), cache)
    text = batch.content
    send = _bundle_line(text, "send the config away")
    tool_sep = _bundle_line(text, "=== FILE: tool.sh ===")
    beta = _bundle_line(text, "beta")
    run_tool = _bundle_line(text, "Then run tool.sh.")

    llm.result = LLMAnalysisResult(
        findings=[
            _finding(send, send + 1, severity="CRITICAL", rule_id="SSD-3"),
            _finding(tool_sep, severity="LOW"),  # separator -> line 1 of tool.sh
            _finding(beta, tool_sep + 1, severity="MEDIUM"),  # end crosses into tool.sh
            _finding(run_tool, run_tool),
        ]
    )
    findings = iff.node(_state(cache))["findings"]

    got = [(f.file, f.start_line, f.end_line, f.severity, f.rule_id) for f in findings]
    assert got == [
        ("tool.sh", 2, 3, "HIGH", "EXA-IF1"),
        ("tool.sh", 1, None, "MEDIUM", "EXA-IF1"),
        ("guide.md", 2, 3, "MEDIUM", "EXA-IF1"),  # clipped to guide.md's last line
        ("SKILL.md", 6, 6, "HIGH", "EXA-IF1"),
    ]
    assert all(f.category is None for f in findings)


def test_if1_findings_are_llm_findings(llm):
    cache = _cache()
    llm.result = LLMAnalysisResult(findings=[_finding(2, severity="HIGH")])
    [finding] = iff.node(_state(cache))["findings"]
    assert finding.rule_id == "EXA-IF1"
    assert is_llm_finding(finding)


def test_node_disabled_by_flag(llm, monkeypatch):
    assert analyzers.ANALYZER_NODE_IDS.count(iff.ANALYZER_ID) == 1
    registered = analyzers.ANALYZER_NODES[iff.ANALYZER_ID]
    for value in (None, "off", "bogus"):
        if value is None:
            monkeypatch.delenv(iff.ENV_VAR, raising=False)
        else:
            monkeypatch.setenv(iff.ENV_VAR, value)
        response = registered(_state(_cache()))
        assert response["analyzer_status_events"][0]["status"] == "disabled"
    # Flag on but LLM use off: the same skipped response SSD gives (P3-R9).
    monkeypatch.setenv(iff.ENV_VAR, "on")
    response = registered(_state(_cache(), use_llm=False))
    [status] = response["analyzer_status_events"]
    assert (status["status"], status["reason_code"]) == ("disabled", "disabled_by_configuration")
    assert llm.calls == []
    # Flag on with LLM use: the registered node runs.
    registered(_state(_cache()))
    assert len(llm.calls) == 1


def test_model_env_override(llm, monkeypatch):
    cache = _cache()
    config = {"model_config": {iff.ANALYZER_ID: "slot-model", "default": "default-model"}}
    iff.node(_state(cache, **config))
    iff.node(_state(cache, model_config={"default": "default-model"}))
    monkeypatch.setenv(iff.MODEL_ENV_VAR, " env-model ")
    iff.node(_state(cache, **config))
    assert llm.models == ["slot-model", "default-model", "env-model"]
    assert iff.MODEL_ENV_VAR == "SKILLSPECTOR_MODEL_EXAFORCE_INSTRUCTION_FLOW"


def test_prompt_is_generic_and_asks_necessity():
    prompt = iff.INSTRUCTION_FLOW_PROMPT
    assert "=== FILE: <path> ===" in prompt
    assert "EXA-IF1" in prompt
    assert "REFERENCE.md" in prompt  # reading another file is named as not a finding
    lowered = prompt.lower()
    assert "necessity" in lowered
    for banned in ("malskillbench", "skillharm", "benchmark", "http://", "https://"):
        assert banned not in lowered
