"""Tests for the flag-gated per-skill necessity analyzer (EXA-NE1)."""

import pytest

import skillspector.exaforce  # noqa: F401  (applies the patches)
from skillspector import llm_analyzer_base
from skillspector.exaforce import _necessity as ne
from skillspector.exaforce._filter_patches import is_llm_finding
from skillspector.exaforce._necessity_prompt import NECESSITY_QUESTIONS
from skillspector.llm_analyzer_base import LLMAnalysisResult, LLMFinding
from skillspector.nodes import analyzers

SKILL_MD = (
    "---\nname: table-helper\ndescription: Formats tables.\n---\n"
    "# Table helper\nRun the formatter.\nThen report the result.\n"
)


class _StubLLM:
    def __init__(self, result, calls, model):
        self.result, self.calls, self.model = result, calls, model

    def with_structured_output(self, schema):
        return self

    def invoke(self, prompt, config=None):
        self.calls.append(prompt)
        return self.result


@pytest.fixture
def llm(monkeypatch):
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
    monkeypatch.setenv(ne.ENV_VAR, "on")
    monkeypatch.delenv(ne.MODEL_ENV_VAR, raising=False)
    return handle


def _state(cache, **extra):
    return {"components": sorted(cache), "file_cache": cache, **extra}


def _finding(start=1, severity="HIGH", rule_id="EXA-NE1"):
    return LLMFinding(
        rule_id=rule_id,
        message="unneeded step",
        severity=severity,
        start_line=start,
        confidence=0.9,
    )


def test_purpose_from_frontmatter():
    assert ne.skill_purpose(SKILL_MD) == "table-helper: Formats tables."
    long_desc = "---\nname: n\ndescription: " + "x" * 2000 + "\n---\nbody\n"
    assert len(ne.skill_purpose(long_desc)) == 600


def test_purpose_fallback_without_description():
    no_desc = (
        "---\nname: table-helper\n---\n# Table helper\n\nFormats tables\nfor people.\n\nMore.\n"
    )
    assert ne.skill_purpose(no_desc) == "Table helper: Formats tables for people."
    no_frontmatter = "intro\n# Title\nFirst para.\n\nSecond.\n"
    assert ne.skill_purpose(no_frontmatter) == "Title: First para."
    assert len(ne.skill_purpose("# T\n" + "y" * 2000)) == 600
    assert ne.skill_purpose("") == ""


def test_ne1_prompt_includes_purpose_first(llm):
    ne.node(_state({"SKILL.md": SKILL_MD}))
    [prompt] = llm.calls
    assert "EXA-NE1" in prompt
    purpose_at = prompt.index("Skill purpose: table-helper: Formats tables.")
    q1 = prompt.index("1. Does the skill's stated purpose require this step or rule?")
    assert purpose_at < q1
    q_positions = [
        prompt.index(f"\n{n}. {text}")
        for n, text in (
            (2, "Does it touch anything outside"),
            (3, "Does it change facts"),
            (4, "Is it framed as mandatory"),
        )
    ]
    assert q1 < min(q_positions)
    assert NECESSITY_QUESTIONS in prompt
    lowered = ne.NECESSITY_PROMPT.lower()
    for banned in ("malskillbench", "skillharm", "benchmark", "http://", "https://"):
        assert banned not in lowered


def test_necessity_chunks_keep_purpose(llm):
    body = "".join(f"Step {i}: do an ordinary thing with the data.\n" for i in range(40000))
    skill = "---\nname: big\ndescription: Does big things.\n---\n" + body
    analyzer = ne.NecessityAnalyzer(base_prompt=ne.NECESSITY_PROMPT, model="stub")
    analyzer.purpose = ne.skill_purpose(skill)
    batches = analyzer.get_batches(["SKILL.md"], {"SKILL.md": skill})
    assert len(batches) >= 2
    for batch in batches:
        prompt = analyzer.build_prompt(batch)
        assert "Skill purpose: big: Does big things." in prompt
    # End to end through the node: every call carries the purpose header.
    ne.node(_state({"SKILL.md": skill}))
    assert len(llm.calls) >= 2
    assert all("Skill purpose: big: Does big things." in c for c in llm.calls)


def test_node_skill_md_only_and_not_applicable(llm):
    cache = {"SKILL.md": SKILL_MD, "other.md": "do the secret thing\n", "run.sh": "echo hi\n"}
    response = ne.node(_state(cache))
    assert len(llm.calls) == 1
    assert "secret thing" not in llm.calls[0]
    assert response["llm_call_log"] == [{"node": ne.ANALYZER_ID, "ok": True, "error": None}]
    assert response["analyzer_status_events"][0]["status"] == "completed"
    llm.calls.clear()
    ne.node(_state({"skill.md": SKILL_MD}))
    assert len(llm.calls) == 1  # lowercase fallback
    llm.calls.clear()
    for cache in ({}, {"docs/SKILL.md": SKILL_MD}, {"a.md": "x\n"}):
        response = ne.node(_state(cache))
        assert response["analyzer_status_events"][0]["status"] == "not_applicable"
        assert "llm_call_log" not in response
    assert llm.calls == []


def test_ne1_are_llm_findings(llm):
    llm.result = LLMAnalysisResult(
        findings=[
            _finding(5, "CRITICAL", rule_id="SSD-3"),
            _finding(6, "LOW"),
            _finding(7, "MEDIUM"),
            _finding(8, "HIGH"),
        ]
    )
    findings = ne.node(_state({"SKILL.md": SKILL_MD}))["findings"]
    assert [(f.rule_id, f.severity, f.file) for f in findings] == [
        ("EXA-NE1", "HIGH", "SKILL.md"),
        ("EXA-NE1", "MEDIUM", "SKILL.md"),
        ("EXA-NE1", "MEDIUM", "SKILL.md"),
        ("EXA-NE1", "HIGH", "SKILL.md"),
    ]
    assert all(f.category is None and is_llm_finding(f) for f in findings)


def test_node_disabled_by_flag(llm, monkeypatch):
    assert analyzers.ANALYZER_NODE_IDS.count(ne.ANALYZER_ID) == 1
    registered = analyzers.ANALYZER_NODES[ne.ANALYZER_ID]
    cache = {"SKILL.md": SKILL_MD}
    for value in (None, "off", "bogus"):
        if value is None:
            monkeypatch.delenv(ne.ENV_VAR, raising=False)
        else:
            monkeypatch.setenv(ne.ENV_VAR, value)
        response = registered(_state(cache))
        assert response["analyzer_status_events"][0]["status"] == "disabled"
    monkeypatch.setenv(ne.ENV_VAR, "on")
    [status] = registered(_state(cache, use_llm=False))["analyzer_status_events"]
    assert (status["status"], status["reason_code"]) == ("disabled", "disabled_by_configuration")
    assert llm.calls == []
    registered(_state(cache))
    assert len(llm.calls) == 1


def test_model_env_override(llm, monkeypatch):
    cache = {"SKILL.md": SKILL_MD}
    config = {"model_config": {ne.ANALYZER_ID: "slot-model", "default": "default-model"}}
    ne.node(_state(cache, **config))
    ne.node(_state(cache, model_config={"default": "default-model"}))
    monkeypatch.setenv(ne.MODEL_ENV_VAR, " env-model ")
    ne.node(_state(cache, **config))
    assert llm.models == ["slot-model", "default-model", "env-model"]
    assert ne.MODEL_ENV_VAR == "SKILLSPECTOR_MODEL_EXAFORCE_NECESSITY"
