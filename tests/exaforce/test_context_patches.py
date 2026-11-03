"""Tests for the flag-gated skill-context header on referenced files."""

import pytest

import skillspector.exaforce  # noqa: F401  (applies the patches)
from skillspector import llm_analyzer_base
from skillspector.exaforce import _context_patches as cp

SSD = "semantic_security_discovery"
SDI = "semantic_developer_intent"
SQP = "semantic_quality_policy"

SKILL_MD = (
    "---\nname: demo-skill\ndescription: Does demo things.\n---\nIntro\nRead guide.md first.\n"
)


class _StubLLM:
    def with_structured_output(self, schema):
        return self


@pytest.fixture(autouse=True)
def _stub_llm(monkeypatch):
    monkeypatch.setattr(llm_analyzer_base, "get_chat_model", lambda **kw: _StubLLM())
    monkeypatch.delenv(cp.ENV_VAR, raising=False)


def _analyzer(node):
    return llm_analyzer_base.LLMAnalyzerBase(base_prompt="BASE", model="stub-model", node=node)


def _cache(extra=None):
    cache = {"SKILL.md": SKILL_MD, "guide.md": "alpha\nbeta\n", "other.md": "gamma\n"}
    cache.update(extra or {})
    return cache


def _prompts(node, cache=None):
    cache = cache or _cache()
    a = _analyzer(node)
    paths = sorted(cache)
    return {b.file_path: a.build_prompt(b) for b in a.get_batches(paths, cache)}


def test_header_added_for_referenced_file_ssd_only(monkeypatch):
    monkeypatch.setenv(cp.ENV_VAR, "ssd")
    ssd = _prompts(SSD)
    assert ssd["guide.md"].startswith('[skill context] This file belongs to skill "demo-skill"')
    assert "6: Read guide.md first." in ssd["guide.md"]
    assert "other.md" in ssd and "[skill context]" not in ssd["other.md"]
    assert "\n\n" in ssd["guide.md"]
    assert "[skill context]" not in _prompts(SDI)["guide.md"]
    assert "[skill context]" not in _prompts(SQP)["guide.md"]


def test_header_not_added_when_off(monkeypatch):
    for value in (None, "off", "bogus"):
        if value is None:
            monkeypatch.delenv(cp.ENV_VAR, raising=False)
        else:
            monkeypatch.setenv(cp.ENV_VAR, value)
        assert "[skill context]" not in _prompts(SSD)["guide.md"]


def test_header_on_every_chunk(monkeypatch):
    monkeypatch.setenv(cp.ENV_VAR, "ssd")
    big = "\n".join(f"line {i} " + "x" * 80 for i in range(2000))
    cache = _cache({"guide.md": big})
    a = _analyzer(SSD)
    a._input_budget = 1
    batches = a.get_batches(sorted(cache), cache)
    chunks = [b for b in batches if b.file_path == "guide.md"]
    assert len(chunks) > 1
    for b in chunks:
        prompt = a.build_prompt(b)
        assert prompt.startswith("[skill context]")
        assert f"{b.start_line}: line {b.start_line - 1} " in prompt.split("Judge this file")[1]


def test_semantic_mode_covers_sdi_and_sqp(monkeypatch):
    monkeypatch.setenv(cp.ENV_VAR, "semantic")
    for node in (SSD, SDI, SQP):
        assert "[skill context]" in _prompts(node)["guide.md"]
    assert "[skill context]" not in _prompts("meta_analyzer")["guide.md"]


def test_skill_md_itself_never_gets_header(monkeypatch):
    monkeypatch.setenv(cp.ENV_VAR, "semantic")
    cache = _cache({"SKILL.md": SKILL_MD + "See SKILL.md for more.\n"})
    assert "[skill context]" not in _prompts(SSD, cache)["SKILL.md"]


def test_no_skill_md_no_header(monkeypatch):
    monkeypatch.setenv(cp.ENV_VAR, "semantic")
    cache = {"guide.md": "x\n"}
    assert "[skill context]" not in _prompts(SSD, cache)["guide.md"]


def test_unparseable_manifest_still_emits_header(monkeypatch):
    monkeypatch.setenv(cp.ENV_VAR, "ssd")
    cache = _cache({"SKILL.md": "---\nname: [oops\n---\nRead guide.md\n"})
    assert 'belongs to skill "": .' in _prompts(SSD, cache)["guide.md"]


def test_node_recorded_on_instance():
    assert _analyzer(SDI)._exa_node == SDI


def test_headers_map_is_thread_safe(monkeypatch):
    import sys
    import threading

    monkeypatch.setenv(cp.ENV_VAR, "ssd")
    errors: list[BaseException] = []
    cache = _cache()
    paths = sorted(cache)

    def work():
        try:
            a = _analyzer(SSD)
            for _ in range(150):
                batches = a.get_batches(paths, cache)
                for b in batches:
                    a.build_prompt(b)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        threads = [threading.Thread(target=work) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(old)
    assert errors == []
