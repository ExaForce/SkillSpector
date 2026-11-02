# SPDX-License-Identifier: Apache-2.0
"""Hidden-text static analyzer (EXA-HT1..3), gated by ``SKILLSPECTOR_EXA_HIDDEN_TEXT=on``.

Content a human reviewer does not see but an agent reads:

- ``EXA-HT1`` (HIGH): extracted document text (``_build_context_patches``) holding at
  least 40 characters of runs marked ``[hidden] `` (white, invisible-render-mode or tiny
  text). Needs ``SKILLSPECTOR_EXA_DOC_TEXT=on`` as well, which produces the markers.
- ``EXA-HT2`` (MEDIUM): at least 3 invisible formatting characters (zero-width, bidi
  override/embedding, word-joiner family, BOM past offset 0) in a ``.md``/``.txt`` file,
  outside fenced code blocks. A zero-width joiner between two non-ASCII letters, marks or
  symbols (emoji sequences, Indic conjuncts), or a zero-width non-joiner between two
  non-ASCII letters or marks (Persian word forms), is legitimate shaping and is not counted.
- ``EXA-HT3`` (MEDIUM): an HTML comment in a ``.md`` file, outside fenced code blocks,
  whose text (at least 40 characters) opens with an imperative directed at an agent.

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
# for marked contexts (see _code_example_interceptor).
CONTEXT_MARKER = "[exaforce: hidden text] "

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

_FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_IMPERATIVE = re.compile(
    r"^[\W_]*(?:run|execute|ignore|delete|remove|send|upload|post|curl|wget|chmod|ssh|copy"
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
    if not content.startswith(EXTRACTED_PREFIX):
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


def _unfenced_lines(content: str) -> list[tuple[int, int, str]]:
    """(line number, offset, text) of each line outside fenced code blocks."""
    result: list[tuple[int, int, str]] = []
    fence: str | None = None
    offset = 0
    for index, line in enumerate(content.split("\n")):
        if fence is None:
            opened = _FENCE_OPEN.match(line)
            if opened:
                fence = opened.group(1)
            else:
                result.append((index + 1, offset, line))
        elif re.fullmatch(rf" {{0,3}}{re.escape(fence[0])}{{{len(fence)},}}\s*", line):
            fence = None
        offset += len(line) + 1
    return result


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


def _ht2(content: str, file_path: str) -> list[AnalyzerFinding]:
    if not file_path.lower().endswith((".md", ".txt")):
        return []
    total, first, codepoints = 0, None, set()
    for line_no, offset, line in _unfenced_lines(content):
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


def _mask_fences(content: str) -> str:
    """``content`` with fenced code-block lines blanked (line numbers preserved)."""
    lines = content.split("\n")
    unfenced = {line_no for line_no, _, _ in _unfenced_lines(content)}
    return "\n".join(line if index + 1 in unfenced else "" for index, line in enumerate(lines))


def _ht3(content: str, file_path: str) -> list[AnalyzerFinding]:
    if not file_path.lower().endswith(".md"):
        return []
    findings: list[AnalyzerFinding] = []
    content = _mask_fences(content)  # a comment inside a code block is displayed, not hidden
    for match in _HTML_COMMENT.finditer(content):
        inner = match.group(1).strip()
        if len(inner) < HT3_MIN_COMMENT_CHARS or not _IMPERATIVE.match(inner):
            continue
        comment = " ".join(match.group(0).split())
        findings.append(
            _finding(
                "EXA-HT3",
                "Imperative instruction hidden in HTML comment",
                Severity.MEDIUM,
                file_path,
                content.count("\n", 0, match.start()) + 1,
                0.7,
                comment[:500],
                comment,
            )
        )
    return findings


def analyze(content: str, file_path: str, file_type: str) -> list[AnalyzerFinding]:
    """Find hidden-text indicators (EXA-HT1..3) in one file."""
    return [*_ht1(content, file_path), *_ht2(content, file_path), *_ht3(content, file_path)]


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
    context = inspect.signature(original).bind(*args, **kwargs).arguments["context"]
    if isinstance(context, str) and context.startswith(CONTEXT_MARKER):
        return False
    return original(*args, **kwargs)


def apply() -> None:
    """Register the EXA-HT texts and the hidden-text analyzer node (idempotent)."""
    _register_texts()
    # static_runner._scan_path calls its module-global is_code_example by name.
    intercept_module_callable(
        static_runner, "is_code_example", _code_example_interceptor, expected_params=("context",)
    )
    _analyzer_registry.register_analyzer(ANALYZER_ID, node, enabled=_enabled)
