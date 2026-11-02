# SPDX-License-Identifier: Apache-2.0
"""Fork-side coverage for ``exaforce/_score_patches``: the semantic gate and doc-MEDIUM cap."""

from __future__ import annotations

import inspect
import json

import pytest

import skillspector  # noqa: F401  (import applies the exaforce patches)
from skillspector.exaforce import _score_patches
from skillspector.exaforce._patchlib import PatchDriftError
from skillspector.models import Finding
from skillspector.nodes import meta_analyzer, report

_FLAGS = (
    "SKILLSPECTOR_EXA_SEMANTIC_GATE",
    "SKILLSPECTOR_EXA_GATE_RULES",
    "SKILLSPECTOR_EXA_GATE_MIN_SEVERITY",
    "SKILLSPECTOR_EXA_DOC_MEDIUM_CAP",
)

_DOC_META = [
    {"path": "SKILL.md", "executable": False},
    {"path": "README.md", "executable": False},
    {"path": "run.sh", "executable": True},
]


@pytest.fixture(autouse=True)
def _clean_flags(monkeypatch):
    for name in _FLAGS:
        monkeypatch.delenv(name, raising=False)


def _f(rule_id, severity, confidence=0.9, file="SKILL.md", start_line=1, tags=()):
    return Finding(
        rule_id=rule_id,
        message="msg",
        severity=severity,
        confidence=confidence,
        file=file,
        start_line=start_line,
        tags=list(tags),
    )


def _score(findings, has_exec=False, meta=None):
    return report._compute_risk_score(findings, has_exec, meta)


def _upstream(findings, has_exec=False, meta=None):
    return report._compute_risk_score.__wrapped__(findings, has_exec, meta)


def test_patch_is_installed():
    assert getattr(report._compute_risk_score, "_exaforce_wrapped", False)


def test_gate_off_is_identity(monkeypatch):
    cases = [
        [],
        [_f("SSD-2", "HIGH")],
        [_f("SSD-1", "CRITICAL", 1.0), _f("P2", "HIGH", 0.4, tags=["llm-unconfirmed"])],
        [_f("SC1", "MEDIUM", 1.0, file=f"{i}.md", start_line=i) for i in range(8)],
    ]
    for value in (None, "off", "OFF", " off "):
        if value is None:
            monkeypatch.delenv("SKILLSPECTOR_EXA_SEMANTIC_GATE", raising=False)
        else:
            monkeypatch.setenv("SKILLSPECTOR_EXA_SEMANTIC_GATE", value)
        for findings in cases:
            assert _score(findings, True, _DOC_META) == _upstream(findings, True, _DOC_META)


def test_gate_any_blocks_single_high_ssd(monkeypatch):
    findings = [_f("SSD-2", "HIGH", 0.9)]
    assert _upstream(findings) == (22, "MEDIUM", "CAUTION")
    monkeypatch.setenv("SKILLSPECTOR_EXA_SEMANTIC_GATE", "any")
    assert _score(findings) == (51, "HIGH", "DO_NOT_INSTALL")


def test_gate_any_counts_unconfirmed(monkeypatch):
    monkeypatch.setenv("SKILLSPECTOR_EXA_SEMANTIC_GATE", "any")
    findings = [_f("SSD-1", "HIGH", tags=["llm-unconfirmed"])]
    assert _score(findings) == (51, "HIGH", "DO_NOT_INSTALL")


def test_confirmed_mode_skips_unconfirmed(monkeypatch):
    monkeypatch.setenv("SKILLSPECTOR_EXA_SEMANTIC_GATE", "confirmed")
    findings = [
        _f("SSD-1", "HIGH", tags=["llm-unconfirmed"]),
        _f("P2", "CRITICAL", 0.2, tags=["other", "llm-unconfirmed"]),
    ]
    assert _score(findings) == _upstream(findings)
    assert _score(findings)[2] != "DO_NOT_INSTALL"


def test_confirmed_mode_untagged_counts(monkeypatch):
    monkeypatch.setenv("SKILLSPECTOR_EXA_SEMANTIC_GATE", "confirmed")
    assert _score([_f("SSD-3", "HIGH", tags=[])]) == (51, "HIGH", "DO_NOT_INSTALL")
    assert _score([_f("P2", "HIGH", tags=["other"])]) == (51, "HIGH", "DO_NOT_INSTALL")
    # one confirmed hit among unconfirmed ones is enough
    mixed = [_f("SSD-4", "HIGH", tags=["llm-unconfirmed"]), _f("SSD-4", "HIGH", start_line=2)]
    assert _score(mixed)[2] == "DO_NOT_INSTALL"


def test_gate_keeps_higher_score(monkeypatch):
    monkeypatch.setenv("SKILLSPECTOR_EXA_SEMANTIC_GATE", "any")
    findings = [_f("SSD-1", "CRITICAL", 1.0), _f("P1", "MEDIUM", 1.0)]
    assert _upstream(findings) == (60, "HIGH", "DO_NOT_INSTALL")
    assert _score(findings) == (60, "HIGH", "DO_NOT_INSTALL")
    findings = [_f("SSD-1", "CRITICAL", 1.0), _f("E2", "CRITICAL", 1.0)]
    assert _score(findings) == (100, "CRITICAL", "DO_NOT_INSTALL")


def test_gate_ignores_other_rules_and_low_severity(monkeypatch):
    monkeypatch.setenv("SKILLSPECTOR_EXA_SEMANTIC_GATE", "any")
    findings = [_f("SDI-1", "CRITICAL", 0.5), _f("SSD-10", "HIGH"), _f("SSD-1", "MEDIUM")]
    assert _score(findings) == _upstream(findings)


def test_gate_min_severity_and_prefix_rules(monkeypatch):
    monkeypatch.setenv("SKILLSPECTOR_EXA_SEMANTIC_GATE", "any")
    monkeypatch.setenv("SKILLSPECTOR_EXA_GATE_RULES", " SDI- , P2 ")
    monkeypatch.setenv("SKILLSPECTOR_EXA_GATE_MIN_SEVERITY", "medium")
    assert _score([_f("SDI-7", "MEDIUM")])[2] == "DO_NOT_INSTALL"
    assert _score([_f("P2", "MEDIUM")])[2] == "DO_NOT_INSTALL"
    assert _score([_f("P2", "LOW")]) == _upstream([_f("P2", "LOW")])
    assert _score([_f("SSD-1", "CRITICAL", 0.1)]) == _upstream([_f("SSD-1", "CRITICAL", 0.1)])


def test_gate_rules_blank(monkeypatch):
    monkeypatch.setenv("SKILLSPECTOR_EXA_SEMANTIC_GATE", "any")
    findings = [_f("SSD-1", "CRITICAL", 0.5)]
    for blank in ("", "   ", " , ,"):
        monkeypatch.setenv("SKILLSPECTOR_EXA_GATE_RULES", blank)
        assert _score(findings) == _upstream(findings)


def test_invalid_flag_values_never_crash(monkeypatch):
    findings = [_f("SSD-1", "HIGH")]
    monkeypatch.setenv("SKILLSPECTOR_EXA_SEMANTIC_GATE", "yes-please")
    assert _score(findings) == _upstream(findings)
    monkeypatch.setenv("SKILLSPECTOR_EXA_SEMANTIC_GATE", "any")
    monkeypatch.setenv("SKILLSPECTOR_EXA_GATE_MIN_SEVERITY", "severe")  # -> HIGH
    assert _score(findings)[2] == "DO_NOT_INSTALL"
    assert _score([_f("SSD-1", "MEDIUM")]) == _upstream([_f("SSD-1", "MEDIUM")])
    monkeypatch.delenv("SKILLSPECTOR_EXA_SEMANTIC_GATE")
    mediums = [_f(f"R{i}", "MEDIUM", 1.0, start_line=i) for i in range(5)]
    for bad in ("", " ", "two", "-1", "2.5"):
        monkeypatch.setenv("SKILLSPECTOR_EXA_DOC_MEDIUM_CAP", bad)
        assert _score(mediums, False, _DOC_META) == _upstream(mediums, False, _DOC_META)


def test_flags_read_on_every_call(monkeypatch):
    findings = [_f("SSD-2", "HIGH")]
    assert _score(findings)[2] == "CAUTION"
    monkeypatch.setenv("SKILLSPECTOR_EXA_SEMANTIC_GATE", "any")
    assert _score(findings)[2] == "DO_NOT_INSTALL"
    monkeypatch.setenv("SKILLSPECTOR_EXA_SEMANTIC_GATE", "off")
    assert _score(findings)[2] == "CAUTION"


def test_cap_drops_excess_doc_mediums(monkeypatch):
    monkeypatch.setenv("SKILLSPECTOR_EXA_DOC_MEDIUM_CAP", "2")
    by_rule = {
        "A1": _f("A1", "MEDIUM", 1.0, start_line=9),
        "A2": _f("A2", "MEDIUM", 0.8, start_line=3),
        "A3": _f("A3", "MEDIUM", 0.5),
        "A4": _f("A4", "MEDIUM", 0.5),
        "A5": _f("A5", "MEDIUM", 0.5),
    }
    findings = [by_rule[r] for r in ("A5", "A3", "A1", "A4", "A2")]
    assert _upstream(findings, False, _DOC_META) == (33, "MEDIUM", "CAUTION")
    expected = _upstream([by_rule["A1"], by_rule["A2"]], False, _DOC_META)
    assert expected == (18, "LOW", "SAFE")
    assert _score(findings, False, _DOC_META) == expected
    # keyword call, as upstream callers might
    assert (
        report._compute_risk_score(
            findings=findings, has_executable_scripts=False, component_metadata=_DOC_META
        )
        == expected
    )
    assert len(findings) == 5  # the caller's list is untouched


def test_cap_orders_by_rule_file_then_line(monkeypatch):
    monkeypatch.setenv("SKILLSPECTOR_EXA_DOC_MEDIUM_CAP", "2")
    # README.md sorts before SKILL.md; within a file a None start_line sorts first
    a = _f("R", "MEDIUM", 1.0, start_line=None)
    b = _f("R", "MEDIUM", 0.3, start_line=2)
    c = _f("R", "MEDIUM", 0.6, file="README.md", start_line=7)
    expected = _upstream([c, a], False, _DOC_META)
    assert expected != _upstream([b, c], False, _DOC_META)
    assert expected != _upstream([b, a], False, _DOC_META)
    assert _score([b, c, a], False, _DOC_META) == expected


def test_cap_skips_executable_and_unknown_files(monkeypatch):
    monkeypatch.setenv("SKILLSPECTOR_EXA_DOC_MEDIUM_CAP", "0")
    kept = [
        _f("X1", "MEDIUM", 1.0, file="run.sh"),
        _f("X2", "MEDIUM", 1.0, file="unlisted.md"),
        _f("X3", "HIGH", 1.0, file="SKILL.md"),
        _f("X4", "LOW", 1.0, file="SKILL.md"),
    ]
    dropped = [_f("X5", "MEDIUM", 1.0, file="SKILL.md"), _f("X6", "medium", 1.0)]
    assert _score(kept + dropped, True, _DOC_META) == _upstream(kept, True, _DOC_META)


def test_cap_without_metadata_is_noop(monkeypatch):
    monkeypatch.setenv("SKILLSPECTOR_EXA_DOC_MEDIUM_CAP", "1")
    findings = [_f(f"R{i}", "MEDIUM", 1.0, start_line=i) for i in range(5)]
    assert _score(findings, False, None) == _upstream(findings, False, None)
    assert _score(findings, False, []) == _upstream(findings, False, [])
    assert report._compute_risk_score(findings, False) == _upstream(findings, False, None)


def test_gate_sees_findings_the_cap_drops(monkeypatch):
    monkeypatch.setenv("SKILLSPECTOR_EXA_SEMANTIC_GATE", "any")
    monkeypatch.setenv("SKILLSPECTOR_EXA_GATE_MIN_SEVERITY", "MEDIUM")
    monkeypatch.setenv("SKILLSPECTOR_EXA_DOC_MEDIUM_CAP", "0")
    assert _score([_f("SSD-1", "MEDIUM")], False, _DOC_META) == (51, "HIGH", "DO_NOT_INSTALL")


def test_helpers():
    unconfirmed = _f("SSD-1", "HIGH", tags=["llm-unconfirmed"])
    assert _score_patches.gate_hit([unconfirmed], ("SSD-1",), "HIGH", "any")
    assert not _score_patches.gate_hit([unconfirmed], ("SSD-1",), "HIGH", "confirmed")
    assert not _score_patches.gate_hit([unconfirmed], (), "HIGH", "any")
    mediums = [_f(f"R{i}", "MEDIUM", start_line=i) for i in range(4)]
    assert _score_patches.cap_doc_mediums(mediums, _DOC_META, 2) == mediums[:2]
    assert _score_patches.cap_doc_mediums(mediums, _DOC_META, None) == mediums
    assert _score_patches.cap_doc_mediums(mediums, None, 0) == mediums


def test_score_patch_drift(monkeypatch):
    def renamed(items, has_executable_scripts, component_metadata=None):
        return 0, "LOW", "SAFE"

    monkeypatch.setattr(report, "_compute_risk_score", renamed)
    with pytest.raises(PatchDriftError):
        _score_patches.apply()


def test_score_patch_drift_bands(monkeypatch):
    bands = report._RISK_SEVERITY_BANDS
    monkeypatch.setattr(report, "_RISK_SEVERITY_BANDS", [(81, "CRITICAL"), (50, "HIGH")])
    with pytest.raises(PatchDriftError):
        _score_patches.apply()
    monkeypatch.setattr(report, "_RISK_SEVERITY_BANDS", bands)
    monkeypatch.delattr(report, "_RISK_RECOMMENDATION")
    with pytest.raises(PatchDriftError):
        _score_patches.apply()


def _report_state(finding):
    return {
        "findings": [finding],
        "effective_finding_ids": [finding.finding_id],
        "component_metadata": [{"path": "SKILL.md", "type": "markdown", "executable": False}],
        "has_executable_scripts": False,
        "manifest": {"name": "gate-e2e"},
        "skill_path": "gate-e2e",
        "output_format": "json",
        "use_llm": False,
    }


def test_gate_reaches_report_node(monkeypatch):
    finding = _f("SSD-1", "HIGH", 0.9)

    monkeypatch.setenv("SKILLSPECTOR_EXA_SEMANTIC_GATE", "off")
    off = json.loads(report.report(_report_state(finding))["report_body"])
    assert off["risk_assessment"]["recommendation"] in {"SAFE", "CAUTION"}

    monkeypatch.setenv("SKILLSPECTOR_EXA_SEMANTIC_GATE", "any")
    on = json.loads(report.report(_report_state(finding))["report_body"])
    assert on["risk_assessment"] == {
        "score": 51,
        "severity": "HIGH",
        "recommendation": "DO_NOT_INSTALL",
    }
    assert [i["id"] for i in on["issues"]] == ["SSD-1"]  # reported findings unchanged


def test_unconfirmed_tag_is_the_one_upstream_emits():
    """Upstream spells the tag as a literal (no constant to import), so pin that it still does."""
    assert _score_patches.UNCONFIRMED_TAG == "llm-unconfirmed"
    assert f'"{_score_patches.UNCONFIRMED_TAG}"' in inspect.getsource(meta_analyzer)
