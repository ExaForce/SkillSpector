"""Derive which files of each malicious SkillHarm unit are the injected payload."""

import hashlib
import json
import re
from pathlib import Path

import click

_TARGET_PREFIX = re.compile(r"^environment/skills/[^/]+/")


def _hashes(root: Path) -> dict[str, str]:
    return {
        p.relative_to(root).as_posix(): hashlib.sha1(p.read_bytes()).hexdigest()
        for p in root.rglob("*")
        if p.is_file()
    }


def injected_files(
    unit_dir: Path, clean_dirs: list[Path], target_path: str | None
) -> tuple[list[str], str]:
    """Return (sorted relative paths, method) for the injected files of a unit.

    Diff against the closest clean counterpart (fewest differing files); with no
    counterpart, fall back to ``target_path`` minus its ``environment/skills/<skill>/`` prefix.
    """
    if clean_dirs:
        unit_h = _hashes(unit_dir)
        best: list[str] | None = None
        for clean in clean_dirs:
            clean_h = _hashes(clean)
            diff = sorted(rel for rel, h in unit_h.items() if clean_h.get(rel) != h)
            if best is None or len(diff) < len(best):
                best = diff
        return best or [], "diff"
    if not target_path:
        return [], "target_path"
    return [_TARGET_PREFIX.sub("", target_path, count=1)], "target_path"


@click.command()
@click.argument("dataset_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
def main(dataset_dir: Path) -> None:
    """Write Skills/_skillharm_injected.jsonl for every malicious SkillHarm unit."""
    skills = dataset_dir / "Skills"
    clean_by_skill: dict[str, list[Path]] = {}
    for d in sorted((skills / "benign").glob("*__skillharm-clean-*")):
        clean_by_skill.setdefault(d.name.split("__", 1)[0], []).append(d)

    rows = []
    with (skills / "_external_labels.jsonl").open() as f:
        for line in f:
            rec = json.loads(line)
            if rec.get("source_dataset") != "SkillHarm" or not rec.get("is_malicious"):
                continue
            unit = rec["unit"]
            skill = unit.rsplit("/", 1)[-1].split("__", 1)[0]
            target = (rec.get("splits") or {}).get("target_path")
            files, method = injected_files(skills / unit, clean_by_skill.get(skill, []), target)
            rows.append({"unit_path": f"Skills/{unit}", "files": files, "method": method})

    out = skills / "_skillharm_injected.jsonl"
    out.write_text("".join(json.dumps(r) + "\n" for r in rows))
    click.echo(f"wrote {len(rows)} rows to {out}")
