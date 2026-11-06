# SPDX-License-Identifier: Apache-2.0
"""Remote-installer lure static analyzer (EXA-LU1, EXA-LU4); on by default, ``SKILLSPECTOR_EXA_LURE_RULES=off`` disables it.

Install instructions that hand the agent (or its user) code from an anonymous source:

- ``EXA-LU1`` (HIGH): fetch-and-execute (``curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod``
  piped or chained to a shell, ``iex``/``Invoke-Expression``, ``python`` or ``node``, or wrapped in
  ``bash -c "$(curl ...)"``/``eval``/``iex (iwr ...)``) where the URL host is a literal IPv4 address
  (loopback excluded) or a public paste/snippet service from ``PASTE_HOSTS``. A vendor's own
  domain does not match.
- ``EXA-LU4`` (HIGH): base64-decoded content executed (``base64 -d`` piped to a shell or interpreter,
  PowerShell ``-EncodedCommand`` with a payload, ``FromBase64String`` with ``iex``).

Two further candidates (LU2 archive-plus-password, LU3 integrity-check bypass) were prototyped
offline and DROPped by the pre-registered precision bar, so they are not shipped here.

The regex sources are copied verbatim from the offline prototype
(``benchmark/benchmark/lure_candidates.py``); ``tests/exaforce/test_lure_rules.py`` compares the two so
they cannot drift. ``src/`` never imports from ``benchmark/``.

The node runs through upstream ``static_runner``. Finding contexts carry ``CONTEXT_MARKER``, which the
shared interceptor installed by ``_fork_context.apply`` exempts from the runner's "looks like a code
example" drop. The finding context is the matched line only, so fence lines are never in it; the
bypass exists because an attacker can append a code-example indicator (``# e.g.``, "such as") to the
lure line itself in a non-executable file such as ``SKILL.md``, which would otherwise make
``is_code_example`` drop the finding.

Regex gaps are bounded (``[^\\n]{0,256}?``) and lines longer than ``MAX_LINE_CHARS`` are matched in
overlapping windows rather than skipped (skipping would let an attacker pad the lure line), so scan
time stays near-linear on adversarial single-line input.
"""

from __future__ import annotations

import logging
import os
import re
import sys

from skillspector.models import AnalyzerFinding, Location, Severity
from skillspector.nodes.analyzers import pattern_defaults, static_runner
from skillspector.nodes.analyzers.pattern_defaults import PatternCategory
from skillspector.state import AnalyzerNodeResponse, SkillspectorState

from . import _analyzer_registry, _fork_context
from ._fork_context import FORK_CONTEXT_PREFIX
from ._patchlib import PatchDriftError

logger = logging.getLogger(__name__)

ANALYZER_ID = "exaforce_lure_rules"
LURE_RULES_ENV = "SKILLSPECTOR_EXA_LURE_RULES"

# Starts with FORK_CONTEXT_PREFIX so the shared static_runner.is_code_example bypass applies.
CONTEXT_MARKER = FORK_CONTEXT_PREFIX + "lure] "

CONFIDENCE = 0.9
MAX_FINDINGS_PER_RULE = 10  # per file
_FLAGS = re.IGNORECASE | re.MULTILINE
# Lines longer than this are scanned in windows of this many characters. Bounded gaps alone still
# leave ~quadratic cost on a very long line, so the regexes never see more than one window.
# ``benchmark/benchmark/rulelab.py`` mirrors these constants so offline and live agree.
MAX_LINE_CHARS = 4096
# Consecutive windows overlap by WINDOW_OVERLAP, which must exceed the longest possible match of
# any shipped pattern, so a match straddling a window start lies wholly inside the previous
# window. Every quantifier in PATTERN_SOURCES is bounded (gaps 256, option chains 16 tokens of
# at most 32 chars, whitespace runs 16), which makes the maximum finite: 1,939 chars for EXA-LU4
# and 1,411 for EXA-LU1 (``test_window_overlap_exceeds_longest_match`` recomputes it from the
# parsed patterns). Whitespace runs over 16 chars are collapsed to one space before matching
# (``_normalize``): every pattern accepts a single space wherever it accepts a run.
WINDOW_OVERLAP = 2048
# Head and tail kept when the middle of a long line is blanked for the whole-file pass, so a
# multi-line match (FromBase64String ... newline ... iex) that touches a line end still works.
LONG_LINE_KEEP = 512
_LONG_LINE = re.compile(rf"[^\n]{{{MAX_LINE_CHARS + 1},}}")
_WS_RUN = re.compile(r"[^\S\n]{17,}")

# Public, general-purpose paste/snippet services. Never add a host because it appears in the
# dataset. The EXA-LU1 source below spells this list out (escaped) in each of its host groups.
PASTE_HOSTS: tuple[str, ...] = (
    "pastebin.com",  # Pastebin
    "paste.ee",  # Paste.ee
    "pastie.org",  # Pastie
    "hastebin.com",  # Hastebin
    "dpaste.com",  # dpaste.com
    "dpaste.org",  # dpaste.org (the open-source dpaste)
    "paste.rs",  # paste.rs
    "termbin.com",  # termbin, the netcat pastebin
    "ix.io",  # ix.io command-line pastebin
    "sprunge.us",  # sprunge command-line pastebin
    "rentry.co",  # Rentry markdown pastebin
    "rentry.org",  # Rentry (alternate domain)
    "controlc.com",  # ControlC pastebin
    "justpaste.it",  # JustPaste.it
    "paste.debian.net",  # Debian's public pastebin
    "bpa.st",  # bpaste, the Python community pastebin
    "paste.mozilla.org",  # Mozilla's public pastebin
    "gist.github.com",  # GitHub Gist snippets
    "gist.githubusercontent.com",  # GitHub Gist raw content
    "glot.io",  # glot.io code snippets
    "0bin.net",  # 0bin encrypted pastebin
    "paste.gg",  # paste.gg
    "pastes.dev",  # pastes.dev
    "codepad.org",  # codepad
)

PATTERN_SOURCES: dict[str, str] = {
    "EXA-LU1": (
        # fetch ... host ... (| or && or ;) exec
        r"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]{0,256}?"
        r"(?:https?://|(?<=[\s\"'(=]))(?!127\.)"
        r"(?:(?:\d{1,3}\.){3}\d{1,3}|(?:www\.)?(?:pastebin\.com|paste\.ee|pastie\.org|"
        r"hastebin\.com|dpaste\.com|dpaste\.org|paste\.rs|termbin\.com|ix\.io|sprunge\.us|"
        r"rentry\.co|rentry\.org|controlc\.com|justpaste\.it|paste\.debian\.net|bpa\.st|"
        r"paste\.mozilla\.org|gist\.github\.com|gist\.githubusercontent\.com|glot\.io|0bin\.net|"
        r"paste\.gg|pastes\.dev|codepad\.org))(?![\w.-])"
        r"[^\n]{0,256}?(?:\||&&|;)\s{0,16}(?:sudo\s{1,16}(?:-\S{1,32}\s{1,16}){0,16})?"
        r"(?:(?:ba|z|da|k)?sh\b(?!\s+-c\b)|iex\b|invoke-expression\b"
        r"|python[\d.]{0,16}(?![\w.])(?!\s+-[cm]\b)|node(?![\w.-])(?!\s+-[ep]\b))"
        # sh -c "$(curl ... host ...)" / eval "$(wget ... host ...)"
        r"|(?:\b(?:ba|z|da|k)?sh\s{1,16}(?:-\w{1,32}\s{1,16}){0,16}|\beval\s{1,16})[\"']?(?:\$\(|<\(|`)\s{0,16}"
        r"(?:curl|wget)\b[^\n]{0,256}?"
        r"(?:https?://|(?<=[\s\"'(=]))(?!127\.)"
        r"(?:(?:\d{1,3}\.){3}\d{1,3}|(?:www\.)?(?:pastebin\.com|paste\.ee|pastie\.org|"
        r"hastebin\.com|dpaste\.com|dpaste\.org|paste\.rs|termbin\.com|ix\.io|sprunge\.us|"
        r"rentry\.co|rentry\.org|controlc\.com|justpaste\.it|paste\.debian\.net|bpa\.st|"
        r"paste\.mozilla\.org|gist\.github\.com|gist\.githubusercontent\.com|glot\.io|0bin\.net|"
        r"paste\.gg|pastes\.dev|codepad\.org))(?![\w.-])"
        # iex (iwr ... host ...) / iex ((New-Object Net.WebClient).DownloadString('host'))
        r"|\b(?:iex|invoke-expression)\b[^\n]{0,256}?"
        r"\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|curl|wget)\b[^\n]{0,256}?"
        r"(?:https?://|(?<=[\s\"'(=]))(?!127\.)"
        r"(?:(?:\d{1,3}\.){3}\d{1,3}|(?:www\.)?(?:pastebin\.com|paste\.ee|pastie\.org|"
        r"hastebin\.com|dpaste\.com|dpaste\.org|paste\.rs|termbin\.com|ix\.io|sprunge\.us|"
        r"rentry\.co|rentry\.org|controlc\.com|justpaste\.it|paste\.debian\.net|bpa\.st|"
        r"paste\.mozilla\.org|gist\.github\.com|gist\.githubusercontent\.com|glot\.io|0bin\.net|"
        r"paste\.gg|pastes\.dev|codepad\.org))(?![\w.-])"
    ),
    "EXA-LU4": (
        # base64 -d ... | shell or interpreter
        r"\bbase64\s{1,16}(?:-\w{1,32}\s{1,16}){0,16}?(?:-[a-z]{0,16}d[a-z]{0,16}|--decode)\b[^\n]{0,256}?"
        r"\|\s{0,16}(?:sudo\s{1,16}(?:-\S{1,32}\s{1,16}){0,16})?"
        r"(?:(?:ba|z|da|k)?sh\b(?!\s+-c\b)|python[\d.]{0,16}(?![\w.])(?!\s+-[cm]\b)"
        r"|perl\b(?!\s+-e\b)|node(?![\w.-])(?!\s+-[ep]\b))"
        # sh -c "$(... base64 -d)" / eval "$(... base64 -d)"
        r"|(?:\b(?:ba|z|da|k)?sh\s{1,16}(?:-\w{1,32}\s{1,16}){0,16}|\beval\s{1,16})[\"']?(?:\$\(|<\(|`)[^\n]{0,256}?"
        r"\bbase64\s{1,16}(?:-\w{1,32}\s{1,16}){0,16}?(?:-[a-z]{0,16}d[a-z]{0,16}|--decode)\b"
        # PowerShell -EncodedCommand (or an accepted abbreviation) with a payload
        r"|\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,256}?\s-(?:e|ec|enc\w{0,16})\s{1,16}"
        r"(?:[a-z0-9+/]{16,64}={0,2}|\$\w{1,64})"
        # FromBase64String then iex / Invoke-Expression
        r"|\bfrombase64string\b[\s\S]{0,400}?\b(?:iex|invoke-expression)\b"
        r"|\b(?:iex|invoke-expression)\b[^\n]{0,256}?\bfrombase64string\b"
    ),
}


SEVERITY: dict[str, Severity] = {"EXA-LU1": Severity.HIGH, "EXA-LU4": Severity.HIGH}

PATTERNS: dict[str, re.Pattern[str]] = {
    k: re.compile(v, _FLAGS) for k, v in PATTERN_SOURCES.items()
}

_TAGS = [PatternCategory.SUPPLY_CHAIN.value]

MESSAGES: dict[str, str] = {
    "EXA-LU1": "Fetch-and-execute from an IP address or paste service",
    "EXA-LU4": "Base64-decoded content is executed",
}

EXPLANATIONS: dict[str, str] = {
    "EXA-LU1": (
        "An install step downloads a script from a raw IP address or an anonymous paste service "
        "and runs it directly. The content is unreviewed, can change at any time, and is not "
        "tied to a vendor domain, which is how remote-installer lures deliver their payload."
    ),
    "EXA-LU4": (
        "An instruction decodes base64 content and executes it. Encoding hides the command from "
        "reviewers, so the real action is not visible in the skill."
    ),
}

REMEDIATIONS: dict[str, str] = {
    "EXA-LU1": (
        "Do not pipe downloaded content into a shell. Install from the vendor's documented "
        "package or release, pin and verify a checksum, and never fetch from a bare IP or a paste site."
    ),
    "EXA-LU4": (
        "Replace the encoded command with the plain command, and review what it does before "
        "running it. Do not execute decoded content."
    ),
}


def _enabled() -> bool:
    """On unless ``SKILLSPECTOR_EXA_LURE_RULES=off`` (default-on since P5 acceptance)."""
    raw = os.environ.get(LURE_RULES_ENV, "").strip().lower()
    if raw == "off":
        return False
    if raw not in ("", "on"):
        logger.warning("%s=%r is not 'on' or 'off' — using 'on'.", LURE_RULES_ENV, raw)
    return True


# Cheap per-window necessary conditions (a match needs an IP/paste host for LU1, base64 or
# powershell for LU4); a window without them cannot match, so skip the regex.
_HINTS: dict[str, re.Pattern[str]] = {
    "EXA-LU1": re.compile(
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|" + "|".join(re.escape(h) for h in PASTE_HOSTS),
        _FLAGS,
    ),
    "EXA-LU4": re.compile(r"base64|powershell|pwsh", _FLAGS),
}


def _normalize(content: str) -> str:
    """Collapse whitespace runs over 16 chars (newlines kept, so line numbers hold)."""
    return _WS_RUN.sub(" ", content)


def _blank_middle(m: re.Match[str]) -> str:
    """Blank the middle of a long line but keep its length and its first/last LONG_LINE_KEEP chars."""
    s = m.group(0)
    return s[:LONG_LINE_KEEP] + " " * (len(s) - 2 * LONG_LINE_KEEP) + s[-LONG_LINE_KEEP:]


def _windows(line: str):
    """Yield (offset, window): ``MAX_LINE_CHARS``-char windows overlapping by WINDOW_OVERLAP."""
    step = MAX_LINE_CHARS - WINDOW_OVERLAP
    for i in range(0, max(len(line) - WINDOW_OVERLAP, 1), step):
        yield i, line[i : i + MAX_LINE_CHARS]


def _long_line_match(
    rule_id: str, pattern: re.Pattern[str], line: str
) -> tuple[int, re.Match[str]] | None:
    """First match in any window of one long line, as (offset in the line, match)."""
    hint = _HINTS[rule_id]
    for offset, window in _windows(line):
        if hint.search(window) and (m := pattern.search(window)):
            return offset + m.start(), m
    return None


def analyze(content: str, file_path: str, file_type: str) -> list[AnalyzerFinding]:
    """Find remote-installer lures (EXA-LU1, EXA-LU4) in one file.

    Offsets are into the normalized text, which keeps every newline, so line numbers are exact.
    """
    findings: list[AnalyzerFinding] = []
    content = _normalize(content)
    # Same length as content: only the middle of a long line is blanked.
    short = _LONG_LINE.sub(_blank_middle, content)
    long_lines = [(m.start(), m.end(), m.group(0)) for m in _LONG_LINE.finditer(content)]
    for rule_id, pattern in PATTERNS.items():
        hits: list[tuple[int, re.Match[str]]] = [(m.start(), m) for m in pattern.finditer(short)]
        for line_start, line_end, line in long_lines:
            if any(line_start <= pos <= line_end for pos, _ in hits):
                continue  # at most one finding per rule per line
            if (found := _long_line_match(rule_id, pattern, line)) is not None:
                hits.append((line_start + found[0], found[1]))
        hits.sort(key=lambda h: h[0])
        for count, (start, match) in enumerate(hits):
            if count >= MAX_FINDINGS_PER_RULE:
                break
            line_no = content.count("\n", 0, start) + 1
            line_start = content.rfind("\n", 0, start) + 1
            line_end = content.find("\n", start)
            line = content[line_start : line_end if line_end >= 0 else len(content)]
            if len(line) > MAX_LINE_CHARS:  # centre the excerpt on the match
                at = start - line_start
                line = line[max(0, at - 100) : at + 200]
            findings.append(
                AnalyzerFinding(
                    rule_id=rule_id,
                    message=MESSAGES[rule_id],
                    severity=SEVERITY[rule_id],
                    location=Location(file=file_path, start_line=line_no),
                    confidence=CONFIDENCE,
                    tags=list(_TAGS),
                    context=CONTEXT_MARKER + line.strip()[:300],
                    matched_text=match.group(0)[:200],
                )
            )
    return findings


def node(state: SkillspectorState) -> AnalyzerNodeResponse:
    """Run the lure rules over every component through the static runner."""
    return static_runner.run_static_patterns_with_ledger(state, [sys.modules[__name__]])


def _register_texts() -> None:
    """Add EXA-LU explanations/remediations to upstream's default tables (idempotent)."""
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


def apply() -> None:
    """Register the EXA-LU texts, the code-example bypass and the lure analyzer node (idempotent)."""
    _register_texts()
    _fork_context.apply()
    _analyzer_registry.register_analyzer(ANALYZER_ID, node, enabled=_enabled)
