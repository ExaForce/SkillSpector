"""Tests for the flag-gated SSD-5 prompt patch."""

import logging
from unittest.mock import patch

import pytest

import skillspector.exaforce  # noqa: F401  (applies the patches)
import skillspector.nodes.analyzers.semantic_security_discovery as ssd
from skillspector.exaforce import _necessity_prompt as np_
from skillspector.exaforce._patchlib import PatchDriftError
from skillspector.llm_analyzer_base import Batch, LLMAnalysisResult, LLMAnalyzerBase, LLMFinding


@pytest.fixture(autouse=True)
def _no_llm():
    with (
        patch("skillspector.llm_analyzer_base.get_chat_model"),
        patch("skillspector.llm_analyzer_base.get_max_input_tokens", return_value=100000),
    ):
        yield


def _build(node, prompt=None):
    return LLMAnalyzerBase(base_prompt=prompt or ssd.ANALYZER_PROMPT, model="m", node=node)


def test_ssd5_prompt_inserts_after_ssd4():
    out = np_.ssd5_prompt(np_.ANALYZER_PROMPT_BASE)
    assert out.index("SSD-4 –") < out.index("SSD-5 – Unnecessary or purpose-violating instruction")
    assert out.index("SSD-5 –") < out.index("Report only findings you are confident about")
    assert "ONE of these five categories" in out
    assert "four categories" not in out
    assert np_.NECESSITY_QUESTIONS in out
    assert "Report a finding only when Q1 = no and Q2, Q3 or Q4 = yes" in out
    assert "HIGH when (Q2 or Q3 = yes) and Q4 = yes; MEDIUM otherwise" in out
    assert "only to instructions written in natural language" in out
    assert out.index("1. Does the skill's stated purpose") < out.index("2. Does it touch")


def test_ssd5_patch_drift():
    with pytest.raises(PatchDriftError):
        np_.ssd5_prompt(np_.ANALYZER_PROMPT_BASE.replace("SSD-4 – Narrative", "SSD-4 - Other"))
    with pytest.raises(PatchDriftError):
        np_.ssd5_prompt(np_.ANALYZER_PROMPT_BASE.replace("four categories", "4 categories"))


def test_ssd_analyzer_uses_patched_prompt_only_when_on(monkeypatch):
    monkeypatch.delenv("SKILLSPECTOR_EXA_SSD5", raising=False)
    assert _build(ssd.ANALYZER_ID).base_prompt == ssd.ANALYZER_PROMPT
    monkeypatch.setenv("SKILLSPECTOR_EXA_SSD5", "off")
    assert _build(ssd.ANALYZER_ID).base_prompt == ssd.ANALYZER_PROMPT
    monkeypatch.setenv("SKILLSPECTOR_EXA_SSD5", "on")
    assert _build(ssd.ANALYZER_ID).base_prompt == np_.ANALYZER_PROMPT_SSD5
    monkeypatch.setenv("SKILLSPECTOR_EXA_SSD5", "off")  # read per construction, not cached
    assert _build(ssd.ANALYZER_ID).base_prompt == ssd.ANALYZER_PROMPT


def test_other_analyzers_unaffected(monkeypatch):
    monkeypatch.setenv("SKILLSPECTOR_EXA_SSD5", "on")
    assert _build("semantic_developer_intent", "other prompt").base_prompt == "other prompt"
    assert _build("llm_analyzer", "x").base_prompt == "x"


def _resp(*rule_ids):
    return LLMAnalysisResult(
        findings=[
            LLMFinding(rule_id=r, message="m", severity="MEDIUM", start_line=1) for r in rule_ids
        ]
    )


def test_ssd5_non_md_counted(monkeypatch, caplog):
    monkeypatch.setenv("SKILLSPECTOR_EXA_SSD5", "on")
    analyzer = _build(ssd.ANALYZER_ID)
    lg = logging.getLogger(np_.logger.name)
    monkeypatch.setattr(lg, "propagate", True)
    with caplog.at_level(logging.INFO, logger=lg.name):
        kept = analyzer.parse_response(_resp("SSD-5", "SSD-1"), Batch("scripts/run.py", "x"))
        assert [f.rule_id for f in kept] == ["SSD-5", "SSD-1"]  # kept, not dropped
        assert "1 SSD-5 finding(s) on non-markdown/text file scripts/run.py" in caplog.text
        caplog.clear()
        analyzer.parse_response(_resp("SSD-5"), Batch("SKILL.md", "x"))
        analyzer.parse_response(_resp("SSD-1"), Batch("run.py", "x"))
        assert caplog.text == ""


def test_parse_not_counted_for_other_analyzers(monkeypatch, caplog):
    monkeypatch.setenv("SKILLSPECTOR_EXA_SSD5", "on")
    analyzer = _build("semantic_developer_intent", "p")
    lg = logging.getLogger(np_.logger.name)
    monkeypatch.setattr(lg, "propagate", True)
    with caplog.at_level(logging.INFO, logger=lg.name):
        assert len(analyzer.parse_response(_resp("SSD-5"), Batch("run.py", "x"))) == 1
        assert caplog.text == ""
