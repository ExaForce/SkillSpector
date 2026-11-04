# SPDX-License-Identifier: Apache-2.0
"""Hidden-text static analyzer (EXA-HT1..3), gated by ``SKILLSPECTOR_EXA_HIDDEN_TEXT=on``.

Content a human reviewer does not see but an agent reads:

- ``EXA-HT1`` (HIGH): extracted ``.pdf/.docx/.pptx/.xlsx`` text (``_build_context_patches``)
  holding at least 40 characters of runs marked ``[hidden] `` (white, invisible-render-mode or tiny
  text). Needs ``SKILLSPECTOR_EXA_DOC_TEXT=on`` as well, which produces the markers.
- ``EXA-HT2`` (MEDIUM): at least 3 invisible formatting characters (zero-width, bidi
  override/embedding, word-joiner family, BOM past offset 0) in a ``.md``/``.txt`` file,
  outside fenced code blocks. A zero-width joiner between two non-ASCII letters, marks or
  symbols (emoji sequences, Indic conjuncts), or a zero-width non-joiner between two
  non-ASCII letters or marks (Persian word forms), is legitimate shaping and is not counted.
- ``EXA-HT3`` (MEDIUM): an HTML comment in a ``.md`` file, outside fenced code blocks,
  whose text (at least 40 characters) opens with an imperative directed at an agent. An
  unclosed comment hides the rest of the file and is checked too. At most 20 per file.

Markdown is scanned in one linear pass that tracks fences and comments together, so a
fence marker inside a comment cannot hide later content, and crafted input cannot make
the comment search quadratic.

The node runs through upstream ``static_runner`` like every static pattern analyzer, so
findings get the usual ledger events and documentation-path confidence handling. Their
contexts carry ``CONTEXT_MARKER`` so the runner's "looks like a code example" drop, which
an attacker could trigger with phrases such as "for example", does not apply to them.
"""

from __future__ import annotations

import inspect
import os
import re
import sys
import unicodedata

from skillspector.models import AnalyzerFinding, Location, Severity
from skillspector.nodes.analyzers import pattern_defaults, static_runner
from skillspector.nodes.analyzers.pattern_defaults import PatternCategory
from skillspector.state import AnalyzerNodeResponse, SkillspectorState

from . import _analyzer_registry
from ._build_context_patches import EXTRACTED_PREFIX, HIDDEN_TEXT_ENV
from ._doc_text import HIDDEN_PREFIX
from ._patchlib import PatchDriftError, intercept_module_callable

ANALYZER_ID = "exaforce_hidden_text"

# Every EXA-HT finding context starts with this marker. Upstream static_runner drops a
# markdown/text finding whose context "looks like an example" (contains "such as",
# "e.g.", ...); hidden content is never a visible example, so that drop is bypassed
# for marked contexts (see _code_example_interceptor). The bypass covers every context that
# starts with FORK_CONTEXT_PREFIX so other fork analyzers can share it. For the lure rules the
# context is the matched line, so the real reason is evasion: an attacker can append "# e.g."
# or "such as" to the lure line in a non-executable file and the drop would hide the finding.
FORK_CONTEXT_PREFIX = "[exaforce: "
CONTEXT_MARKER = FORK_CONTEXT_PREFIX + "hidden text] "

HT1_MIN_HIDDEN_CHARS = 40
HT2_MIN_INVISIBLE_CHARS = 3
HT3_MIN_COMMENT_CHARS = 40

_INVISIBLE = frozenset(
    [chr(c) for c in range(0x200B, 0x2010)]
    + [chr(c) for c in range(0x202A, 0x202F)]
    + [chr(c) for c in range(0x2060, 0x2065)]
    + ["\ufeff"]
)
_ZWJ = "\u200d"
_ZWNJ = "\u200c"
_BOM = "\ufeff"

HT3_MAX_FINDINGS = 20  # per file

_DOC_SUFFIXES = (".pdf", ".docx", ".pptx", ".xlsx")
_FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_COMMENT_OPEN, _COMMENT_CLOSE = "<!--", "-->"
# First letter/digit of a comment: the verb must start there (leading punctuation,
# whitespace and underscores are skipped). Searched, not anchored, to stay linear.
_FIRST_WORD = re.compile(r"[^\W_]")
_IMPERATIVE = re.compile(
    r"(?:run|execute|ignore|delete|remove|send|upload|post|curl|wget|chmod|ssh|copy"
    r"|append|always|never|do\s+not\s+(?:tell|mention|ask))(?![\w-])",
    re.IGNORECASE,
)

_TAGS = [PatternCategory.PROMPT_INJECTION.value]

EXPLANATIONS: dict[str, str] = {
    "EXA-HT1": (
        "The document contains a substantial amount of text rendered so that a human reader "
        "cannot see it (white or invisible text, or a near-zero font size), while an agent "
        "reading the extracted text receives it. Hidden text is a common way to smuggle "
        "instructions past review."
    ),
    "EXA-HT2": (
        "The file contains several invisible formatting characters (zero-width characters, "
        "bidirectional overrides or word joiners) outside code blocks. They can split words "
        "to evade keyword checks, reorder displayed text, or carry content a reviewer does "
        "not see."
    ),
    "EXA-HT3": (
        "An HTML comment, which markdown renderers hide from readers, contains an imperative "
        "instruction directed at the agent. Comments are not displayed, so the instruction "
        "reaches the agent without being visible during review."
    ),
}

REMEDIATIONS: dict[str, str] = {
    "EXA-HT1": (
        "Inspect the document's hidden text. Remove it, or make it visible if it is legitimate "
        "content, and do not ship documents whose extracted text differs from what readers see."
    ),
    "EXA-HT2": (
        "Remove the invisible characters, or move legitimate uses into a fenced code block "
        "and explain them. Review the surrounding text with the characters made visible."
    ),
    "EXA-HT3": (
        "Remove instructions from HTML comments. Put any instruction the agent should follow "
        "in visible text where reviewers can see it."
    ),
}


def _enabled() -> bool:
    return os.environ.get(HIDDEN_TEXT_ENV) == "on"


def _finding(
    rule_id: str,
    message: str,
    severity: Severity,
    file_path: str,
    line: int,
    confidence: float,
    context: str,
    matched_text: str,
) -> AnalyzerFinding:
    return AnalyzerFinding(
        rule_id=rule_id,
        message=message,
        severity=severity,
        location=Location(file=file_path, start_line=line),
        confidence=confidence,
        tags=list(_TAGS),
        context=CONTEXT_MARKER + context,
        matched_text=matched_text[:200],
    )


def _ht1(content: str, file_path: str) -> list[AnalyzerFinding]:
    # Only documents _build_context_patches extracted: a text file cannot forge the header.
    if not file_path.lower().endswith(_DOC_SUFFIXES) or not content.startswith(EXTRACTED_PREFIX):
        return []
    total, first = 0, None
    for index, line in enumerate(content.split("\n")):
        if line.startswith(HIDDEN_PREFIX):
            total += len(line) - len(HIDDEN_PREFIX)
            if first is None:
                first = (index + 1, line)
    if first is None or total < HT1_MIN_HIDDEN_CHARS:
        return []
    line_no, line = first
    return [
        _finding(
            "EXA-HT1",
            f"Hidden text in document ({total} hidden characters)",
            Severity.HIGH,
            file_path,
            line_no,
            0.8,
            line[:500],
            line[len(HIDDEN_PREFIX) :],
        )
    ]


def _fence_closes(line: str, fence: str) -> bool:
    return re.fullmatch(rf" {{0,3}}{re.escape(fence[0])}{{{len(fence)},}}\s*", line) is not None


def _scan_markdown(
    content: str,
) -> tuple[list[tuple[int, int, str]], list[tuple[int, str, bool]]]:
    """One linear pass over ``content``.

    Returns the ``(line number, offset, text)`` of every line outside fenced code blocks,
    and the ``(start line, raw text, closed)`` of every HTML comment opened outside one.
    A line inside an open comment is never a fence marker (an HTML block opened by
    ``<!--`` runs to ``-->``); an unclosed comment runs to the end of the file.
    """
    lines: list[tuple[int, int, str]] = []
    comments: list[tuple[int, str, bool]] = []
    fence: str | None = None
    open_comment: tuple[int, int] | None = None  # (start line, absolute offset)
    offset = 0
    for index, line in enumerate(content.split("\n")):
        line_no = index + 1
        line_offset, offset = offset, offset + len(line) + 1
        if fence is not None:
            if _fence_closes(line, fence):
                fence = None
            continue
        if open_comment is None:
            opened = _FENCE_OPEN.match(line)
            if opened:
                fence = opened.group(1)
                continue
        lines.append((line_no, line_offset, line))
        pos = 0
        while True:
            if open_comment is None:
                start = line.find(_COMMENT_OPEN, pos)
                if start == -1:
                    break
                open_comment = (line_no, line_offset + start)
                pos = start + len(_COMMENT_OPEN)
            end = line.find(_COMMENT_CLOSE, pos)
            if end == -1:
                break
            pos = end + len(_COMMENT_CLOSE)
            comments.append((open_comment[0], content[open_comment[1] : line_offset + pos], True))
            open_comment = None
    if open_comment is not None:
        comments.append((open_comment[0], content[open_comment[1] :], False))
    return lines, comments


def _is_script_char(ch: str, categories: str) -> bool:
    return ord(ch) > 0x7F and unicodedata.category(ch)[0] in categories


def _counts(line: str, index: int, absolute: int) -> bool:
    ch = line[index]
    if ch not in _INVISIBLE:
        return False
    if ch == _BOM and absolute == 0:
        return False
    # Joiner/non-joiner between non-ASCII letters or marks is script shaping (Indic conjuncts,
    # Persian word forms); the joiner also joins emoji symbols.
    # Limitation: U+200E/U+200F (LRM/RLM) are still counted, though bidi prose uses them.
    if ch in (_ZWJ, _ZWNJ) and 0 < index < len(line) - 1:
        categories = "LMS" if ch == _ZWJ else "LM"
        if _is_script_char(line[index - 1], categories) and _is_script_char(
            line[index + 1], categories
        ):
            return False
    return True


def _visible(text: str) -> str:
    return "".join(f"<U+{ord(ch):04X}>" if ch in _INVISIBLE else ch for ch in text)


def _ht2(lines: list[tuple[int, int, str]], file_path: str) -> list[AnalyzerFinding]:
    total, first, codepoints = 0, None, set()
    for line_no, offset, line in lines:
        for index in range(len(line)):
            if _counts(line, index, offset + index):
                total += 1
                codepoints.add(f"U+{ord(line[index]):04X}")
                if first is None:
                    first = (line_no, line)
    if first is None or total < HT2_MIN_INVISIBLE_CHARS:
        return []
    line_no, line = first
    return [
        _finding(
            "EXA-HT2",
            f"Invisible formatting characters ({total} found)",
            Severity.MEDIUM,
            file_path,
            line_no,
            0.6,
            _visible(line)[:500],
            f"{total} invisible characters: {', '.join(sorted(codepoints))}",
        )
    ]


def _ht3(comments: list[tuple[int, str, bool]], file_path: str) -> list[AnalyzerFinding]:
    findings: list[AnalyzerFinding] = []
    for line_no, text, closed in comments:
        if len(findings) >= HT3_MAX_FINDINGS:
            break
        body = text[len(_COMMENT_OPEN) : -len(_COMMENT_CLOSE) if closed else None]
        inner = body.strip()
        if len(inner) < HT3_MIN_COMMENT_CHARS:
            continue
        first = _FIRST_WORD.search(inner)
        if first is None or not _IMPERATIVE.match(inner, first.start()):
            continue
        excerpt = " ".join(text[:1000].split())[:500]
        findings.append(
            _finding(
                "EXA-HT3",
                "Imperative instruction hidden in HTML comment",
                Severity.MEDIUM,
                file_path,
                line_no,
                0.7,
                excerpt,
                excerpt,
            )
        )
    return findings


def analyze(content: str, file_path: str, file_type: str) -> list[AnalyzerFinding]:
    """Find hidden-text indicators (EXA-HT1..3) in one file."""
    findings = _ht1(content, file_path)
    lower = file_path.lower()
    if lower.endswith((".md", ".txt")):
        lines, comments = _scan_markdown(content)
        findings += _ht2(lines, file_path)
        if lower.endswith(".md"):
            findings += _ht3(comments, file_path)
    return findings


def node(state: SkillspectorState) -> AnalyzerNodeResponse:
    """Run the hidden-text rules over every component through the static runner."""
    return static_runner.run_static_patterns_with_ledger(state, [sys.modules[__name__]])


def _register_texts() -> None:
    """Add EXA-HT explanations/remediations to upstream's default tables (idempotent)."""
    for table_name, texts in (
        ("DEFAULT_EXPLANATIONS", EXPLANATIONS),
        ("DEFAULT_REMEDIATIONS", REMEDIATIONS),
    ):
        table = getattr(pattern_defaults, table_name, None)
        if not isinstance(table, dict):
            raise PatchDriftError(
                f"pattern_defaults.{table_name} is missing or not a dict; "
                "upstream changed — update the exaforce patch."
            )
        for rule_id, text in texts.items():
            if table.setdefault(rule_id, text) != text:
                raise PatchDriftError(
                    f"pattern_defaults.{table_name} already defines {rule_id!r}; "
                    "rename the exaforce rule."
                )
    if pattern_defaults.get_explanation("EXA-HT1") != EXPLANATIONS["EXA-HT1"] or (
        pattern_defaults.get_remediation("EXA-HT1") != REMEDIATIONS["EXA-HT1"]
    ):
        raise PatchDriftError(
            "pattern_defaults getters no longer read the default tables; "
            "upstream changed — update the exaforce patch."
        )


def _code_example_interceptor(original, args: tuple, kwargs: dict) -> object:
    # apply() checked that ``context`` is the first parameter, so no per-call binding.
    context = args[0] if args else kwargs.get("context")
    if isinstance(context, str) and context.startswith(FORK_CONTEXT_PREFIX):
        return False
    return original(*args, **kwargs)


def apply() -> None:
    """Register the EXA-HT texts and the hidden-text analyzer node (idempotent)."""
    _register_texts()
    params = list(inspect.signature(static_runner.is_code_example).parameters)
    if params[:1] != ["context"]:
        raise PatchDriftError(
            "static_runner.is_code_example no longer takes `context` first; "
            "upstream changed — update the exaforce patch."
        )
    # static_runner._scan_path calls its module-global is_code_example by name.
    intercept_module_callable(
        static_runner, "is_code_example", _code_example_interceptor, expected_params=("context",)
    )
    _analyzer_registry.register_analyzer(ANALYZER_ID, node, enabled=_enabled)
