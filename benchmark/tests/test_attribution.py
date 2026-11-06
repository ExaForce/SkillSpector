from pathlib import Path

from benchmark.attribution import injected_files


def _w(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def test_injected_files_diff(tmp_path):
    clean = _w(tmp_path / "clean", {"SKILL.md": "a", "a.py": "x"})
    unit = _w(tmp_path / "unit", {"SKILL.md": "b", "a.py": "x", "runbook.pdf": "p"})
    assert injected_files(unit, [clean], None) == (["SKILL.md", "runbook.pdf"], "diff")


def test_injected_files_picks_closest_clean(tmp_path):
    far = _w(tmp_path / "far", {"SKILL.md": "z", "a.py": "q"})
    near = _w(tmp_path / "near", {"SKILL.md": "a", "a.py": "x"})
    unit = _w(tmp_path / "unit", {"SKILL.md": "b", "a.py": "x"})
    assert injected_files(unit, [far, near], None) == (["SKILL.md"], "diff")


def test_injected_files_nested_paths_sorted(tmp_path):
    clean = _w(tmp_path / "clean", {"SKILL.md": "a"})
    unit = _w(tmp_path / "unit", {"SKILL.md": "a", "scripts/z.py": "1", "scripts/a.py": "2"})
    assert injected_files(unit, [clean], None)[0] == ["scripts/a.py", "scripts/z.py"]


def test_injected_files_fallback(tmp_path):
    unit = _w(tmp_path / "unit", {"SKILL.md": "b"})
    assert injected_files(unit, [], "environment/skills/pdf/SKILL.md") == (
        ["SKILL.md"],
        "target_path",
    )


def test_add_new_pdfs(tmp_path):
    from benchmark.attribution import add_new_pdfs

    unit = _w(tmp_path / "unit", {"SKILL.md": "b", "a.pdf": "p", "scripts/x.py": "1"})
    pats = ["redirect_to_new_pdf"]
    assert add_new_pdfs(unit, ["SKILL.md"], "target_path", pats) == (
        ["SKILL.md", "a.pdf"],
        "target_path+new_pdf",
    )
    assert add_new_pdfs(unit, ["SKILL.md"], "target_path", ["other"]) == (
        ["SKILL.md"],
        "target_path",
    )
    assert add_new_pdfs(unit, ["SKILL.md"], "target_path", None) == (["SKILL.md"], "target_path")
    assert add_new_pdfs(unit, ["a.pdf"], "diff", pats) == (["a.pdf"], "diff")
