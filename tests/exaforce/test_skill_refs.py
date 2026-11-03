"""Tests for skill reference detection and instruction-flow bundle building."""

import pytest

from skillspector.exaforce._skill_refs import (
    Bundle,
    build_bundle,
    context_header,
    map_line,
    referenced_files,
)
from skillspector.llm_analyzer_base import estimate_tokens


def test_referenced_by_path():
    md = "# Skill\nRead docs/guide.md first.\nThen run scripts/run.sh now\nrun.sh again"
    comps = ["docs/guide.md", "scripts/run.sh", "other/unused.md"]
    refs = referenced_files(md, comps)
    assert list(refs) == ["docs/guide.md", "scripts/run.sh"]
    assert refs["docs/guide.md"] == [(2, "Read docs/guide.md first.")]
    # Unique basename also matches, on its own line.
    assert refs["scripts/run.sh"] == [(3, "Then run scripts/run.sh now"), (4, "run.sh again")]


def test_referenced_boundaries_and_case():
    md = "see myguide.md and Guide.MD and xguide.md"
    assert referenced_files(md, ["guide.md"]) == {}
    assert referenced_files("see guide.md.", ["guide.md"]) == {"guide.md": [(1, "see guide.md.")]}


def test_ambiguous_basename_not_matched():
    md = "Open README.md please\nSee a/README.md too"
    refs = referenced_files(md, ["a/README.md", "b/README.md"])
    assert list(refs) == ["a/README.md"]
    assert refs["a/README.md"] == [(2, "See a/README.md too")]


def test_referenced_missing_file_ignored():
    md = "Read gone.md and docs/other.md"
    assert referenced_files(md, ["docs/real.md"]) == {}
    bundle = build_bundle("SKILL.md", {"SKILL.md": md}, {"gone.md": [(1, md)]})
    assert "=== FILE: gone.md ===" not in bundle.text
    assert [p for _, p, _ in bundle.offsets] == ["SKILL.md"]


def test_referenced_order_first_line_then_path():
    md = "b.md and a.md\nc.md\n"
    refs = referenced_files(md, ["c.md", "b.md", "a.md"])
    assert list(refs) == ["a.md", "b.md", "c.md"]


def test_header_exact_template():
    manifest = {"name": "demo", "description": "line one\n  line   two"}
    refs = [(3, "use a.md  \t"), (9, "x" * 400)]
    assert context_header(manifest, refs) == (
        '[skill context] This file belongs to skill "demo": line one line two.\n'
        "SKILL.md refers to it in these lines (the agent will act on this file as instructed there):\n"
        "3: use a.md\n"
        f"9: {'x' * 300}\n"
        "Judge this file as instructions the agent will follow, not as passive documentation.\n"
    )


def test_header_missing_fields_and_limits():
    h = context_header({}, [(i, f"l{i}") for i in range(1, 12)])
    assert h.startswith('[skill context] This file belongs to skill "": .\n')
    assert "8: l8\n" in h and "9: l9" not in h
    long = context_header({"name": "n", "description": "d" * 500}, [(1, "a")])
    assert f'"n": {"d" * 300}.\n' in long


def test_bundle_skips_schemas_and_caps_tokens():
    cache = {
        "SKILL.md": "intro\nuse a.md b.md c.md f.md d.xsd e.xml big.md",
        "a.md": "A\n",
        "d.xsd": "<x/>",
        "e.xml": "<x/>",
        "big.md": "z" * 50_001,
        "b.md": "B" * 45_000,
        "c.md": "C" * 45_000,
        "f.md": "F" * 45_000,
    }
    refs = referenced_files(cache["SKILL.md"], [k for k in cache if k != "SKILL.md"])
    bundle = build_bundle("SKILL.md", cache, refs)
    assert "=== FILE: d.xsd ===" not in bundle.text
    assert "=== FILE: e.xml ===" not in bundle.text
    assert "=== FILE: big.md ===" not in bundle.text
    paths = [p for _, p, _ in bundle.offsets]
    assert paths == ["SKILL.md", "a.md", "b.md", "c.md"]  # f.md dropped whole by the cap
    assert estimate_tokens(bundle.text) <= 24_000
    assert bundle.text.startswith("=== FILE: SKILL.md ===\n")


def test_bundle_truncates_skill_md_by_whole_lines():
    md = "\n".join("x" * 99 for _ in range(2000))
    bundle = build_bundle("SKILL.md", {"SKILL.md": md}, {})
    assert estimate_tokens(bundle.text) <= 24_000
    assert all(line in ("", "x" * 99) or line.startswith("===") for line in bundle.text.split("\n"))


def test_bundle_line_mapping():
    cache = {"SKILL.md": "s1\ns2\ns3", "a.md": "a1\na2", "b.md": "b1\nb2\nb3"}
    refs = {"a.md": [(1, "")], "b.md": [(2, "")]}
    bundle = build_bundle("SKILL.md", cache, refs)
    assert isinstance(bundle, Bundle)
    lines = bundle.text.split("\n")
    assert lines == [
        "=== FILE: SKILL.md ===", "s1", "s2", "s3",
        "=== FILE: a.md ===", "a1", "a2",
        "=== FILE: b.md ===", "b1", "b2", "b3",
    ]  # fmt: skip
    expected = {
        1: ("SKILL.md", 1), 2: ("SKILL.md", 1), 4: ("SKILL.md", 3),
        5: ("a.md", 1), 6: ("a.md", 1), 7: ("a.md", 2),
        8: ("b.md", 1), 9: ("b.md", 1), 11: ("b.md", 3),
        99: ("b.md", 3),
    }  # fmt: skip
    for line, want in expected.items():
        assert map_line(bundle, line) == want, line


def test_parent_directory_prefix_not_matched():
    comps = ["README.md", "references/README.md"]
    assert list(referenced_files("See references/README.md", comps)) == ["references/README.md"]
    assert list(referenced_files("See x/docs/a.md", ["docs/a.md", "y/a.md"])) == []


def test_dot_slash_prefix_matches_root():
    comps = ["README.md", "references/README.md"]
    assert list(referenced_files("See ./README.md", comps)) == ["README.md"]
    assert list(referenced_files("See ../README.md", comps)) == []


def _old_truncate(lines):
    lines = list(lines)
    while len(lines) > 1 and estimate_tokens("\n".join(lines)) > 24_000:
        lines.pop()
    return lines


@pytest.mark.parametrize(
    "md",
    [
        "",
        "short",
        "\n".join("x" * 99 for _ in range(2000)),
        "\n".join("ab" * (i % 7 + 1) for i in range(50_000)),
        "y" * 200_000,
        "\n\n\n" * 40_000,
    ],
)
def test_skill_md_truncation_matches_old_algorithm(md):
    expected = "\n".join(_old_truncate(["=== FILE: SKILL.md ===", *md.split("\n")]))
    assert build_bundle("SKILL.md", {"SKILL.md": md}, {}).text == expected


def test_skill_md_truncation_exact_boundary():
    header = "=== FILE: SKILL.md ==="
    # header + "\n" + body is exactly 24_000 * 4 + 3 chars (still 24_000 tokens), then one more char.
    for extra in (0, 1, 4):
        body_len = 24_000 * 4 + 3 - len(header) - 1 + extra
        md = "a" * (body_len // 2) + "\n" + "a" * (body_len - body_len // 2 - 1)
        expected = "\n".join(_old_truncate([header, *md.split("\n")]))
        assert build_bundle("SKILL.md", {"SKILL.md": md}, {}).text == expected


def test_large_skill_md_of_short_lines_bundles_quickly():
    import time

    md = "\n".join("line" for _ in range(250_000))
    assert len(md) > 1_000_000
    start = time.perf_counter()
    bundle = build_bundle("SKILL.md", {"SKILL.md": md}, {})
    assert time.perf_counter() - start < 1.0
    assert estimate_tokens(bundle.text) <= 24_000
