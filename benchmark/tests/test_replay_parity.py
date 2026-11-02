# SPDX-License-Identifier: Apache-2.0
"""Parity: offline ``replay`` and the classifier's patched scorer reach the same verdict.

P1 chooses its gate/cap policy offline with ``replay`` and then turns it on in the
classifier through ``SKILLSPECTOR_EXA_*`` flags (``skillspector/exaforce/_score_patches``).
That only transfers if both decide every finding list the same way, so random lists are
scored by both under each policy and the block/no-block verdicts compared.
"""

from __future__ import annotations

import random

import pytest
import skillspector.exaforce
from skillspector.exaforce import _score_patches
from skillspector.models import Finding
from skillspector.nodes import report

from benchmark.replay import GATE_MIN_SCORE, UNCONFIRMED_TAG, Policy, _gate_hit, rescore

_FLAGS = (
    "SKILLSPECTOR_EXA_SEMANTIC_GATE",
    "SKILLSPECTOR_EXA_GATE_RULES",
    "SKILLSPECTOR_EXA_GATE_MIN_SEVERITY",
    "SKILLSPECTOR_EXA_DOC_MEDIUM_CAP",
)
# The classifier's default rule list, so a drift in it shows up as a replay mismatch here.
_GATE_RULES = _score_patches.DEFAULT_GATE_RULES

# SSD-10 / P20 start with a gate entry's text but are different rules (an exact entry is not a prefix).
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

# (policy, flags): flags left out are unset, so the gate's rule list is the flag default.
_POLICIES = {
    "default": (Policy(), {}),
    "gate-any": (
        Policy(gate_rules=_GATE_RULES, gate_mode="any"),
        {"SKILLSPECTOR_EXA_SEMANTIC_GATE": "any"},
    ),
    "gate-confirmed": (
        Policy(gate_rules=_GATE_RULES, gate_mode="confirmed"),
        {"SKILLSPECTOR_EXA_SEMANTIC_GATE": "confirmed"},
    ),
    "cap-3": (Policy(doc_medium_cap=3), {"SKILLSPECTOR_EXA_DOC_MEDIUM_CAP": "3"}),
}


def _random_lists(n: int = 200) -> list[list[dict]]:
    """Mixed lists; every other one is doc-MEDIUM heavy so the cap can change a verdict."""
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


def _replay_verdict(findings: list[dict], policy: Policy) -> bool:
    score = min(100, max(0, int(rescore(findings, _EXECUTABLE, policy, _NON_EXECUTABLE))))
    gated = _gate_hit(findings, policy)
    if gated:
        score = max(score, GATE_MIN_SCORE)
    return gated or score >= policy.threshold


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
    for name in _FLAGS:
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("name", list(_POLICIES))
def test_replay_and_classifier_agree(monkeypatch, name):
    policy, flags = _POLICIES[name]
    for key, value in flags.items():
        monkeypatch.setenv(key, value)
    mismatches = [
        (i, findings)
        for i, findings in enumerate(_LISTS)
        if _replay_verdict(findings, policy) != _classifier_verdict(findings)
    ]
    assert not mismatches, f"{len(mismatches)} lists disagree under {name}; first: {mismatches[0]}"


def test_parity_lists_exercise_every_policy():
    """Each non-default policy flips some verdicts, so agreement above is not vacuous."""
    base = [_replay_verdict(f, Policy()) for f in _LISTS]
    assert 0 < sum(base) < len(_LISTS)
    for name in ("gate-any", "gate-confirmed", "cap-3"):
        policy = _POLICIES[name][0]
        flipped = sum(_replay_verdict(f, policy) != b for f, b in zip(_LISTS, base, strict=True))
        assert flipped > 0, name
    any_hits = {i for i, f in enumerate(_LISTS) if _gate_hit(f, _POLICIES["gate-any"][0])}
    confirmed = {i for i, f in enumerate(_LISTS) if _gate_hit(f, _POLICIES["gate-confirmed"][0])}
    assert confirmed < any_hits


def _finding(rule_id, severity, confidence, file, start_line=1, tags=()):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "confidence": confidence,
        "file": file,
        "start_line": start_line,
        "tags": list(tags),
    }


def test_tag_and_default_rules_match_classifier():
    assert UNCONFIRMED_TAG == _score_patches.UNCONFIRMED_TAG
    assert set(_GATE_RULES) == {"SSD-1", "SSD-2", "SSD-3", "SSD-4", "P2"}


@pytest.mark.parametrize("rule_id", ["SSD-10", "P20"])
def test_exact_gate_entry_is_not_a_prefix(monkeypatch, rule_id):
    """``SSD-1`` must not gate ``SSD-10``; only an entry ending in ``-`` is a prefix."""
    monkeypatch.setenv("SKILLSPECTOR_EXA_SEMANTIC_GATE", "any")
    policy = _POLICIES["gate-any"][0]
    findings = [_finding(rule_id, "HIGH", 0.3, "tool.py")]
    assert not _gate_hit(findings, policy)
    assert not _replay_verdict(findings, policy)
    assert not _classifier_verdict(findings)
    # the control: the exact id does gate under the same policy
    exact = [_finding("SSD-1", "HIGH", 0.3, "tool.py")]
    assert _gate_hit(exact, policy)
    assert _classifier_verdict(exact)


def test_file_without_metadata_is_never_capped(monkeypatch):
    """The cap only touches known non-executable files; ``notes.md`` has no metadata row."""
    monkeypatch.setenv("SKILLSPECTOR_EXA_DOC_MEDIUM_CAP", "0")
    policy = Policy(doc_medium_cap=0)
    findings = [_finding(f"R{i}", "MEDIUM", 1.0, "notes.md", i) for i in range(1, 9)]
    assert _replay_verdict(findings, Policy())  # scored, and blocks, without the cap
    assert _replay_verdict(findings, policy)
    assert _classifier_verdict(findings)
    # the control: the same findings in a known doc are capped away
    docs = [dict(f, file="README.md") for f in findings]
    assert not _replay_verdict(docs, policy)
    assert not _classifier_verdict(docs)
