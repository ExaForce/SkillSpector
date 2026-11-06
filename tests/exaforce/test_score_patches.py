# SPDX-License-Identifier: Apache-2.0
"""Fork-side coverage for ``exaforce/_score_patches``: the block threshold and score clamp."""

from __future__ import annotations

import json

import pytest

import skillspector  # noqa: F401  (import applies the exaforce patches)
from skillspector.exaforce import _score_patches
from skillspector.exaforce._patchlib import PatchDriftError
from skillspector.models import Finding
from skillspector.nodes import report

_DOC_META = [
    {"path": "SKILL.md", "executable": False},
    {"path": "README.md", "executable": False},
    {"path": "run.sh", "executable": True},
]


@pytest.fixture(autouse=True)
def _clean_flags(monkeypatch):
    # Pin the upstream cut; the default (unset -> 49) has its own tests below.
    monkeypatch.setenv("SKILLSPECTOR_EXA_BLOCK_THRESHOLD", "51")


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


# --- block threshold -------------------------------------------------------------------

_THRESHOLD_ENV = "SKILLSPECTOR_EXA_BLOCK_THRESHOLD"


def _score_near(target):
    """Findings (HIGH, distinct rules, doc file) whose upstream score is exactly ``target``."""
    for n in range(1, 5):
        for conf in (c / 100 for c in range(1, 101)):
            findings = [_f(f"SC{i}", "HIGH", conf) for i in range(n)]
            if _upstream(findings)[0] == target:
                return findings
    raise AssertionError(target)


def test_threshold_51_is_identity():
    findings = _score_near(40)
    assert _score(findings) == _upstream(findings) == (40, "MEDIUM", "CAUTION")


def test_threshold_below_51_blocks_and_bands_high(monkeypatch):
    monkeypatch.setenv(_THRESHOLD_ENV, "35")
    assert _score(_score_near(40)) == (51, "HIGH", "DO_NOT_INSTALL")
    assert _score(_score_near(34)) == (34, "MEDIUM", "CAUTION")
    assert _score(_score_near(35)) == (51, "HIGH", "DO_NOT_INSTALL")


def test_band_matches_recommendation(monkeypatch):
    monkeypatch.setenv(_THRESHOLD_ENV, "49")
    score, band, recommendation = _score(_score_near(49))
    assert (score, band, recommendation) == (51, "HIGH", "DO_NOT_INSTALL")
    assert report._RISK_RECOMMENDATION[band] == recommendation


def test_threshold_above_51_demotes(monkeypatch):
    monkeypatch.setenv(_THRESHOLD_ENV, "70")
    findings = [_f(f"SC{i}", "HIGH", 1.0, file="run.sh") for i in range(2)]
    score = _upstream(findings, True, _DOC_META)[0]
    assert 51 <= score < 70, score
    assert _score(findings, True, _DOC_META) == (50, "MEDIUM", "CAUTION")


@pytest.mark.parametrize("value", ["20", "81", "0", "-5", "1000"])
def test_threshold_out_of_range(monkeypatch, caplog, value):
    monkeypatch.setenv(_THRESHOLD_ENV, value)
    with caplog.at_level("ERROR"), pytest.raises(ValueError, match=_THRESHOLD_ENV):
        _score_patches.block_threshold()
    assert _THRESHOLD_ENV in caplog.text
    with pytest.raises(ValueError):
        _score([_f("SC1", "HIGH")])


@pytest.mark.parametrize("value", ["21", "49", "80"])
def test_threshold_range_edges_accepted(monkeypatch, value):
    monkeypatch.setenv(_THRESHOLD_ENV, value)
    assert _score_patches.block_threshold() == int(value)


@pytest.mark.parametrize("value", ["abc", "49.5", "4 9"])
def test_threshold_non_integer_ignored(monkeypatch, caplog, value):
    monkeypatch.setenv(_THRESHOLD_ENV, value)
    with caplog.at_level("WARNING"):
        assert _score_patches.block_threshold() == 49
    assert _THRESHOLD_ENV in caplog.text
    assert _score(_score_near(49)) == (51, "HIGH", "DO_NOT_INSTALL")
    assert _score(_score_near(48)) == _upstream(_score_near(48))


def test_threshold_blank_is_default(monkeypatch):
    monkeypatch.setenv(_THRESHOLD_ENV, "  ")
    assert _score_patches.block_threshold() == 49


def test_threshold_unset_defaults_to_49(monkeypatch):
    monkeypatch.delenv(_THRESHOLD_ENV)
    assert _score_patches.block_threshold() == 49
    assert _score(_score_near(49)) == (51, "HIGH", "DO_NOT_INSTALL")
    assert _score(_score_near(48)) == _upstream(_score_near(48))


def _random_findings(rng):
    rules = ("SSD-1", "SSD-2", "P2", "SC1", "SC2", "X")
    severities = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    files = ("SKILL.md", "README.md", "run.sh")
    return [
        _f(
            rng.choice(rules),
            rng.choice(severities),
            rng.choice((0.2, 0.5, 0.7, 0.9, 1.0)),
            file=rng.choice(files),
            start_line=rng.randint(1, 9),
        )
        for _ in range(rng.randint(0, 10))
    ]


@pytest.mark.parametrize("threshold", range(21, 81))
def test_block_iff_score_above_risk_threshold(monkeypatch, threshold):
    """Upstream consumers cut on ``risk_score > RISK_THRESHOLD``; the block must agree."""
    import random

    from skillspector.constants import RISK_THRESHOLD

    monkeypatch.setenv(_THRESHOLD_ENV, str(threshold))
    rng = random.Random(threshold)
    blocked = unblocked = 0
    for _ in range(150):
        score, band, recommendation = _score(_random_findings(rng), True, _DOC_META)
        assert (recommendation == "DO_NOT_INSTALL") == (score > RISK_THRESHOLD)
        assert report._RISK_RECOMMENDATION[band] == recommendation or recommendation == "CAUTION"
        blocked += recommendation == "DO_NOT_INSTALL"
        unblocked += recommendation != "DO_NOT_INSTALL"
    assert blocked and unblocked  # both sides exercised


def test_scores_between_threshold_and_51_are_lifted_to_51(monkeypatch):
    monkeypatch.setenv(_THRESHOLD_ENV, "49")
    assert _score(_score_near(49)) == (51, "HIGH", "DO_NOT_INSTALL")


def test_scores_between_51_and_threshold_are_capped_at_50(monkeypatch):
    monkeypatch.setenv(_THRESHOLD_ENV, "70")
    findings = [_f(f"SC{i}", "HIGH", 1.0, file="run.sh") for i in range(2)]
    assert _score(findings, True, _DOC_META) == (50, "MEDIUM", "CAUTION")


def _report_state(findings):
    return {
        "findings": findings,
        "effective_finding_ids": [f.finding_id for f in findings],
        "component_metadata": [{"path": "SKILL.md", "type": "markdown", "executable": False}],
        "has_executable_scripts": False,
        "manifest": {"name": "threshold-e2e"},
        "skill_path": "threshold-e2e",
        "output_format": "json",
        "use_llm": False,
    }


def test_threshold_reaches_report_node(monkeypatch):
    findings = _score_near(49)

    off = json.loads(report.report(_report_state(findings))["report_body"])
    assert off["risk_assessment"]["recommendation"] == "CAUTION"

    monkeypatch.setenv("SKILLSPECTOR_EXA_BLOCK_THRESHOLD", "49")
    on = json.loads(report.report(_report_state(findings))["report_body"])
    assert on["risk_assessment"] == {
        "score": 51,
        "severity": "HIGH",
        "recommendation": "DO_NOT_INSTALL",
    }
    assert len(on["issues"]) == len(findings)  # reported findings unchanged


def test_threshold_read_on_every_call(monkeypatch):
    findings = _score_near(49)
    assert _score(findings)[2] == "CAUTION"
    monkeypatch.setenv("SKILLSPECTOR_EXA_BLOCK_THRESHOLD", "49")
    assert _score(findings)[2] == "DO_NOT_INSTALL"
    monkeypatch.setenv("SKILLSPECTOR_EXA_BLOCK_THRESHOLD", "51")
    assert _score(findings)[2] == "CAUTION"
