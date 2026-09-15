# SPDX-License-Identifier: Apache-2.0
"""The two anchored patterns, asserted end to end and from both directions.

A fork override is only worth having if it still applies after an upstream
merge and still rejects what it was written to reject. The important assertions
here run the real ``analyze()`` rather than the pattern strings: if upstream
refactored to pre-compile its patterns at import, ``replace_pattern`` would
still swap the string, a string-level test would still pass, and the patch
would be silently inert in a real scan.
"""

from __future__ import annotations

import pytest

import skillspector.nodes.analyzers.static_patterns_harmful_content as harmful
import skillspector.nodes.analyzers.static_patterns_privilege_escalation as privesc
from skillspector.exaforce import _pattern_patches
from skillspector.exaforce._patchlib import PatchDriftError, replace_pattern

# The exact evidence the two fleet rows carried.
SKILL_SOMEONE = (
    "`jama-docstring-style` is part of this family now, not a separate "
    "optional skill someone might remember to run."
)
PROCESS_ENV = "Access environment variables safely via process.env "


@pytest.fixture(autouse=True)
def _applied():
    _pattern_patches.apply()


def _rules(module, content: str, file_path: str) -> list[str]:
    return [f.rule_id for f in module.analyze(content, file_path, "markdown")]


# --- the false positives the patch exists for --------------------------------


def test_p5_no_longer_fires_on_kill_inside_skill():
    assert "P5" not in _rules(harmful, SKILL_SOMEONE, "SKILL.md")


def test_pe3_no_longer_fires_on_process_env():
    assert "PE3" not in _rules(privesc, PROCESS_ENV, "STYLE.md")


# --- what the patch must not break -------------------------------------------


@pytest.mark.parametrize("text", ["how to kill someone", "poison a person", "murder people"])
def test_p5_still_fires_on_real_harmful_instructions(text):
    assert "P5" in _rules(harmful, text, "SKILL.md")


@pytest.mark.parametrize("text", ["cat .env ", "read ~/.env ", "source .env.production ", ".env\n"])
def test_pe3_still_fires_on_real_dotenv_access(text):
    assert "PE3" in _rules(privesc, text, "SKILL.md")


# --- surviving an upstream merge ---------------------------------------------


def test_applying_twice_is_a_no_op():
    before = list(harmful.DANGEROUS_ACTIONS)
    _pattern_patches.apply()
    assert harmful.DANGEROUS_ACTIONS == before


def test_the_anchored_patterns_are_actually_installed():
    assert _pattern_patches.P5_HARM_NEW in [p for p, _ in harmful.DANGEROUS_ACTIONS]
    assert _pattern_patches.PE3_ENV_NEW in [p for p, _ in privesc.PE3_PATTERNS]


def test_a_rewritten_upstream_pattern_raises_rather_than_going_stale():
    # The case this guards: upstream edits the pattern, our `old` string stops
    # matching, and without the raise the fork would ship a correction that no
    # longer applies while the tests still passed.
    module = type(harmful)("fake")
    module.PATTERNS = [(r"upstream rewrote this", 0.9)]
    with pytest.raises(PatchDriftError, match="no longer contains"):
        replace_pattern(module, "PATTERNS", "the old pattern", "the new one")


def test_an_upstream_fix_identical_to_ours_is_accepted_silently():
    # Nothing for a human to decide: the correction is in force either way,
    # and this is what keeps apply() idempotent.
    module = type(harmful)("fake")
    module.PATTERNS = [("already fixed", 0.9)]
    replace_pattern(module, "PATTERNS", "the old pattern", "already fixed")
    assert module.PATTERNS == [("already fixed", 0.9)]


def test_a_missing_upstream_list_raises():
    module = type(harmful)("fake")
    with pytest.raises(PatchDriftError, match="not a list"):
        replace_pattern(module, "GONE", "a", "b")


def test_confidence_is_preserved():
    # These patches change what a pattern matches, never how much a match is
    # believed -- a confidence drift would move scores for unrelated reasons.
    installed = dict(harmful.DANGEROUS_ACTIONS)
    assert installed[_pattern_patches.P5_HARM_NEW] == 0.95
    assert dict(privesc.PE3_PATTERNS)[_pattern_patches.PE3_ENV_NEW] == 0.6


@pytest.mark.parametrize(
    ("module", "attr", "old", "new", "rule", "evidence", "path"),
    [
        (
            harmful,
            "DANGEROUS_ACTIONS",
            _pattern_patches.P5_HARM_OLD,
            _pattern_patches.P5_HARM_NEW,
            "P5",
            SKILL_SOMEONE,
            "SKILL.md",
        ),
        (
            privesc,
            "PE3_PATTERNS",
            _pattern_patches.PE3_ENV_OLD,
            _pattern_patches.PE3_ENV_NEW,
            "PE3",
            PROCESS_ENV,
            "STYLE.md",
        ),
    ],
)
def test_the_patch_is_what_removes_the_finding(module, attr, old, new, rule, evidence, path):
    """The negative tests above must not be able to pass vacuously.

    ``skillspector`` applies the fork's patches at package import, so a test
    that only asserts "no finding" would read the same whether the patch did
    the work or the analyzer never fired. This restores the upstream pattern,
    observes the false positive, and puts ours back.
    """
    patterns = getattr(module, attr)
    original = list(patterns)
    try:
        patterns[:] = [(old if p == new else p, c) for p, c in patterns]
        assert rule in _rules(module, evidence, path)
    finally:
        patterns[:] = original
    assert rule not in _rules(module, evidence, path)
