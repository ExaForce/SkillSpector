# SPDX-License-Identifier: Apache-2.0
"""Parity: offline ``replay`` and the classifier's patched scorer reach the same verdict.

P6 chose the block threshold offline with ``replay`` and the classifier applies it through
``SKILLSPECTOR_EXA_BLOCK_THRESHOLD`` (``skillspector/exaforce/_score_patches``). That only
transfers if both decide every finding list the same way, so random lists are scored by both
and the verdict, score, band and recommendation compared. Replay's gate and doc-MEDIUM cap
options (P1, rejected) have no classifier counterpart any more and are not checked here.
"""

from __future__ import annotations

import random

import pytest
import skillspector.exaforce
from skillspector.models import Finding
from skillspector.nodes import report

from benchmark.replay import Policy, decide, rescore

_RULES = ("SSD-1", "SSD-10", "SSD-2", "P20", "SSD-3", "SSD-4", "P2", "SDI-1", "SC1", "X")
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "medium", "high", "INFO")
_CONFIDENCES = (0.0, 0.1, 0.3, 0.5, 0.7, 0.9, 1.0, 1.4, -0.2)
_TAGS = ((), ("llm-unconfirmed",), ("other",), ("other", "llm-unconfirmed"))
_START_LINES = (None, 1, 2, 5, 40)
# README.md / SKILL.md are docs, run.sh / tool.py executable; notes.md has no metadata row.
_METADATA = [
    {"path": "SKILL.md", "executable": False},
    {"path": "README.md", "executable": False},
    {"path": "run.sh", "executable": True},
    {"path": "tool.py", "executable": True},
]
_FILES = ("SKILL.md", "README.md", "run.sh", "tool.py", "notes.md")
_EXECUTABLE = frozenset(c["path"] for c in _METADATA if c["executable"])
_NON_EXECUTABLE = frozenset(c["path"] for c in _METADATA if not c["executable"])


def _random_lists(n: int = 200) -> list[list[dict]]:
    """Mixed lists; every other one is doc-MEDIUM heavy, so scores spread across the cut."""
    rng = random.Random(1)
    lists = []
    for i in range(n):
        doc_heavy = i % 2 == 1
        severity_weights = (1, 2, 6, 1, 2, 1, 1) if doc_heavy else (1,) * len(_SEVERITIES)
        file_weights = (4, 4, 1, 1, 1) if doc_heavy else (1,) * len(_FILES)
        # a short rule pool per list, so repeats (diminishing weights) are common
        rules = _RULES[: rng.randint(2, len(_RULES))]
        lists.append(
            [
                {
                    "rule_id": rng.choice(rules),
                    "severity": rng.choices(_SEVERITIES, severity_weights)[0],
                    "confidence": rng.choice(_CONFIDENCES),
                    "file": rng.choices(_FILES, file_weights)[0],
                    "start_line": rng.choice(_START_LINES),
                    "tags": list(rng.choice(_TAGS)),
                }
                for _ in range(rng.randint(0, 24 if doc_heavy else 14))
            ]
        )
    return lists


_LISTS = _random_lists()


def _replay_decision(findings: list[dict], policy: Policy) -> tuple[bool, int, str, str]:
    """``(verdict, score, band, recommendation)`` replay gives; the band/rec come from ``decide``."""
    score = min(100, max(0, int(rescore(findings, _EXECUTABLE, policy, _NON_EXECUTABLE))))
    return decide(score, False, policy.threshold)


def _replay_verdict(findings: list[dict], policy: Policy) -> bool:
    return _replay_decision(findings, policy)[0]


def _classifier_result(findings: list[dict]) -> tuple[int, str, str]:
    objs = [
        Finding(rule_id=f["rule_id"], message="m", **{k: f[k] for k in f if k != "rule_id"})
        for f in findings
    ]
    return report._compute_risk_score(objs, True, _METADATA)


def _classifier_verdict(findings: list[dict]) -> bool:
    objs = [
        Finding(rule_id=f["rule_id"], message="m", **{k: f[k] for k in f if k != "rule_id"})
        for f in findings
    ]
    _score, _band, recommendation = report._compute_risk_score(objs, True, _METADATA)
    return recommendation == "DO_NOT_INSTALL"


@pytest.fixture(autouse=True)
def _patched(monkeypatch):
    skillspector.exaforce.apply_patches()
    assert getattr(report._compute_risk_score, "_exaforce_wrapped", False)
    # Policy() is the upstream scorer (51); the classifier defaults to 49, so pin it.
    monkeypatch.setenv("SKILLSPECTOR_EXA_BLOCK_THRESHOLD", "51")


def test_replay_and_classifier_agree_at_upstream_cut():
    mismatches = [
        (i, findings)
        for i, findings in enumerate(_LISTS)
        if _replay_verdict(findings, Policy()) != _classifier_verdict(findings)
    ]
    assert not mismatches, f"{len(mismatches)} lists disagree; first: {mismatches[0]}"


_THRESHOLDS = tuple(range(31, 62, 2))


@pytest.mark.parametrize("threshold", _THRESHOLDS)
def test_replay_and_classifier_agree_on_threshold(monkeypatch, threshold):
    """Verdict, score, band and recommendation agree for every T in the sweep grid."""
    policy = Policy(threshold=threshold)
    monkeypatch.setenv("SKILLSPECTOR_EXA_BLOCK_THRESHOLD", str(threshold))
    mismatches = []
    for i, findings in enumerate(_LISTS):
        replayed = _replay_decision(findings, policy)
        c_score, c_band, c_rec = _classifier_result(findings)
        if replayed != (c_rec == "DO_NOT_INSTALL", c_score, c_band, c_rec):
            mismatches.append((i, replayed, (c_score, c_band, c_rec)))
    assert not mismatches, f"{len(mismatches)} lists disagree; first: {mismatches[0]}"


def test_threshold_lists_exercise_every_threshold():
    """Some lists flip at each side of 51, so threshold agreement is not vacuous."""
    base = [_replay_verdict(f, Policy()) for f in _LISTS]
    for threshold in (t for t in _THRESHOLDS if t != 51):
        flipped = sum(
            _replay_verdict(f, Policy(threshold=threshold)) != b
            for f, b in zip(_LISTS, base, strict=True)
        )
        assert flipped > 0, threshold


def test_unset_flag_equals_threshold_49(monkeypatch):
    """The classifier's unset default is T = 49, i.e. ``Policy(threshold=49)`` on the lists."""
    monkeypatch.delenv("SKILLSPECTOR_EXA_BLOCK_THRESHOLD")
    policy = Policy(threshold=49)
    for findings in _LISTS:
        c_score, c_band, c_rec = _classifier_result(findings)
        assert _replay_decision(findings, policy) == (
            c_rec == "DO_NOT_INSTALL",
            c_score,
            c_band,
            c_rec,
        )
    assert any(
        _replay_verdict(f, policy) != _replay_verdict(f, Policy()) for f in _LISTS
    )  # not vacuous
