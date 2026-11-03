"""Pure helpers: which files SKILL.md points at, and how to present that to an LLM.

No flags, no patching, no LLM. ``referenced_files`` finds the components SKILL.md
mentions, ``context_header`` renders the per-file prompt header, and
``build_bundle`` / ``map_line`` build and read back the instruction-flow bundle.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from skillspector.llm_analyzer_base import estimate_tokens

MAX_HEADER_LINES = 8
MAX_FIELD_CHARS = 300
MAX_FILE_CHARS = 50_000
MAX_BUNDLE_TOKENS = 24_000
_SKIPPED_SUFFIXES = (".xsd", ".xml")
_SKILL_MD_NAMES = ("SKILL.md", "skill.md")


def _matcher(token: str) -> re.Pattern[str]:
    return re.compile(rf"(?<!\w){re.escape(token)}(?!\w)")


def _path_matcher(path: str) -> re.Pattern[str]:
    # Not preceded by a word char or "/" (so "references/README.md" is not "README.md"),
    # except for a leading "./" which still names the same root-relative path.
    return re.compile(rf"(?:(?<![\w/])|(?<=(?<![\w./])\./)){re.escape(path)}(?!\w)")


def referenced_files(skill_md: str, components: list[str]) -> dict[str, list[tuple[int, str]]]:
    """Map each component SKILL.md mentions to its referencing ``(line_no, line)`` pairs.

    A component is referenced when its relative path, or its basename when that
    basename is unique among ``components``, occurs in SKILL.md with no word
    character immediately before or after (case-sensitive). A path must also not
    be preceded by ``/`` (a leading ``./`` is fine); basenames keep the word rule. SKILL.md itself is
    never a referenced file. Order: first referencing line, ties by path.
    """
    basename_counts: dict[str, int] = {}
    for comp in components:
        base = comp.rsplit("/", 1)[-1]
        basename_counts[base] = basename_counts.get(base, 0) + 1

    lines = skill_md.split("\n")
    found: dict[str, list[tuple[int, str]]] = {}
    for comp in sorted(set(components)):
        if comp in _SKILL_MD_NAMES:
            continue
        base = comp.rsplit("/", 1)[-1]
        pats = [_path_matcher(comp)]
        if base != comp and basename_counts[base] == 1:
            pats.append(_matcher(base))
        hits = [(i, line) for i, line in enumerate(lines, 1) if any(p.search(line) for p in pats)]
        if hits:
            found[comp] = hits
    return dict(sorted(found.items(), key=lambda kv: (kv[1][0][0], kv[0])))


def context_header(manifest: dict, refs: list[tuple[int, str]]) -> str:
    """Render the per-file context header (at most 8 referencing lines, 300 chars each)."""
    name = str(manifest.get("name") or "")
    desc = " ".join(str(manifest.get("description") or "").split())[:MAX_FIELD_CHARS]
    ref_lines = "".join(
        f"{no}: {line.rstrip()[:MAX_FIELD_CHARS]}\n" for no, line in refs[:MAX_HEADER_LINES]
    )
    return (
        f'[skill context] This file belongs to skill "{name}": {desc}.\n'
        "SKILL.md refers to it in these lines (the agent will act on this file as instructed there):\n"
        f"{ref_lines}"
        "Judge this file as instructions the agent will follow, not as passive documentation.\n"
    )


@dataclass
class Bundle:
    """Instruction-flow bundle text plus the map back to source files.

    ``offsets`` holds ``(bundle start line, path, file start line)`` per file, in
    bundle order. The bundle start line is the 1-based line of the file's
    ``=== FILE: <path> ===`` separator and the file start line is always 0, so a
    bundle line L maps to file line ``L - start + file_start`` clamped to >= 1:
    the separator maps to line 1 of the file it introduces, as does the file's
    first content line.
    """

    text: str
    offsets: list[tuple[int, str, int]]


def _section(path: str, content: str) -> list[str]:
    return [f"=== FILE: {path} ===", *content.split("\n")]


def build_bundle(skill_md_path: str, file_cache: dict[str, str], refs: dict[str, list]) -> Bundle:
    """SKILL.md then its referenced files (in ``refs`` order), under the token cap.

    Each file is preceded by a separator line. Files absent from ``file_cache``,
    over 50,000 characters, or ``.xsd``/``.xml`` are left out. Trailing files are
    dropped whole to stay within 24,000 estimated tokens; SKILL.md alone is
    truncated by whole lines if it exceeds the cap.
    """
    skill_lines = _section(skill_md_path, file_cache.get(skill_md_path, ""))
    while len(skill_lines) > 1 and estimate_tokens("\n".join(skill_lines)) > MAX_BUNDLE_TOKENS:
        skill_lines.pop()
    lines = list(skill_lines)
    offsets = [(1, skill_md_path, 0)]

    for path in refs:
        content = file_cache.get(path)
        if (
            content is None
            or path == skill_md_path
            or path.lower().endswith(_SKIPPED_SUFFIXES)
            or len(content) > MAX_FILE_CHARS
        ):
            continue
        section = _section(path, content)
        if estimate_tokens("\n".join([*lines, *section])) > MAX_BUNDLE_TOKENS:
            break
        offsets.append((len(lines) + 1, path, 0))
        lines.extend(section)
    return Bundle("\n".join(lines), offsets)


def map_line(bundle: Bundle, line: int) -> tuple[str, int]:
    """Map a 1-based bundle line to ``(path, file line)``; see ``Bundle`` for the convention.

    Lines past the end map to the last file's last line.
    """
    total = bundle.text.count("\n") + 1
    line = min(max(line, 1), total)
    start, path, file_start = bundle.offsets[0]
    for entry in bundle.offsets:
        if entry[0] > line:
            break
        start, path, file_start = entry
    return path, max(1, line - start + file_start)
