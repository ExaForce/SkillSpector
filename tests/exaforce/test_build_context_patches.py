"""Tests for the flag-gated extracted-text patches on build_context and static_runner."""

import zlib

import pytest

import skillspector.exaforce  # noqa: F401  (applies the patches)
from skillspector.nodes import build_context as bc
from skillspector.nodes.analyzers import static_runner

HEADER = "[exaforce: text extracted from .pdf"
HIDDEN = "hidden instruction text that is long enough to count"


def _pdf() -> bytes:
    content = f"BT /F1 12 Tf (visible words) Tj 1 1 1 rg ({HIDDEN}) Tj ET".encode()
    body = zlib.compress(content)
    return (
        b"%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode /Length "
        + str(len(body)).encode()
        + b" >>\nstream\n"
        + body
        + b"\nendstream\nendobj\n%%EOF\n"
    )


@pytest.fixture
def skill_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("SKILLSPECTOR_EXA_DOC_TEXT", raising=False)
    monkeypatch.delenv("SKILLSPECTOR_EXA_HIDDEN_TEXT", raising=False)
    (tmp_path / "SKILL.md").write_text("# Skill\n")
    (tmp_path / "guide.pdf").write_bytes(_pdf())
    return tmp_path


def _cache(skill_dir):
    cache, _ = bc._read_file_cache(skill_dir, ["SKILL.md", "guide.pdf"])
    return cache


def test_cache_replaced_when_flag_on(skill_dir, monkeypatch):
    monkeypatch.setenv("SKILLSPECTOR_EXA_DOC_TEXT", "on")
    cache = _cache(skill_dir)
    assert cache["guide.pdf"].startswith(HEADER)
    assert "visible words" in cache["guide.pdf"]
    assert cache["SKILL.md"] == "# Skill\n"


def test_cache_untouched_when_flag_off(skill_dir, monkeypatch):
    assert not _cache(skill_dir)["guide.pdf"].startswith(HEADER)
    monkeypatch.setenv("SKILLSPECTOR_EXA_DOC_TEXT", "ON")
    assert not _cache(skill_dir)["guide.pdf"].startswith(HEADER)


def test_hidden_markers_follow_hidden_flag(skill_dir, monkeypatch):
    monkeypatch.setenv("SKILLSPECTOR_EXA_DOC_TEXT", "on")
    plain = _cache(skill_dir)["guide.pdf"]
    assert "[hidden] " not in plain and "0 hidden spans" in plain
    monkeypatch.setenv("SKILLSPECTOR_EXA_HIDDEN_TEXT", "on")
    marked = _cache(skill_dir)["guide.pdf"]
    assert f"[hidden] {HIDDEN}" in marked and "1 hidden spans" in marked


def test_missing_and_oversize_pdf_left_alone(skill_dir, monkeypatch):
    monkeypatch.setenv("SKILLSPECTOR_EXA_DOC_TEXT", "on")
    cache, events = bc._read_file_cache(skill_dir, ["gone.pdf"])
    assert "gone.pdf" not in cache and events
    (skill_dir / "big.pdf").write_bytes(b"%PDF" + b"0" * 5_000_000)
    cache, _ = bc._read_file_cache(skill_dir, ["big.pdf"])
    assert "extraction skipped: limits" in cache["big.pdf"]


def test_build_context_node_end_to_end(skill_dir, monkeypatch):
    monkeypatch.setenv("SKILLSPECTOR_EXA_DOC_TEXT", "on")
    out = bc.build_context({"skill_path": str(skill_dir)})
    assert out["file_cache"]["guide.pdf"].startswith(HEADER)
    assert "visible words" in out["file_cache"]["guide.pdf"]


def test_is_binary_file_extracted_header(monkeypatch):
    extracted = HEADER + "; 0 hidden spans]\nhello"
    monkeypatch.setenv("SKILLSPECTOR_EXA_DOC_TEXT", "on")
    assert static_runner._is_binary_file("guide.pdf", extracted) is False
    assert static_runner._is_binary_file("guide.pdf", "%PDF-1.4\x00\x01") is True
    monkeypatch.setenv("SKILLSPECTOR_EXA_DOC_TEXT", "off")
    assert static_runner._is_binary_file("guide.pdf", extracted) is True
    monkeypatch.delenv("SKILLSPECTOR_EXA_DOC_TEXT")
    assert static_runner._is_binary_file("guide.pdf", extracted) is True


def _state(skill_dir):
    cache = _cache(skill_dir)
    return {"components": ["SKILL.md", "guide.pdf"], "file_cache": cache}


@pytest.mark.parametrize("flag,expected", [("on", True), ("off", False)])
def test_static_runner_passes_extracted_pdf_to_analyzer(skill_dir, monkeypatch, flag, expected):
    monkeypatch.setenv("SKILLSPECTOR_EXA_DOC_TEXT", flag)
    seen: list[str] = []

    class Mod:
        ANALYZER_ID = "recorder"

        @staticmethod
        def analyze(*, content, file_path, file_type):
            seen.append(file_path)
            return []

    state = _state(skill_dir)
    static_runner.run_static_patterns_with_ledger(state, [Mod])
    assert ("guide.pdf" in seen) is expected
    seen.clear()
    static_runner.run_static_patterns(state, [Mod])
    assert ("guide.pdf" in seen) is expected
