# SPDX-License-Identifier: Apache-2.0
"""Remote-installer lure static analyzer (EXA-LU1, EXA-LU4), gated by ``SKILLSPECTOR_EXA_LURE_RULES=on``.

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
shared interceptor installed by ``_hidden_text.apply`` exempts from the runner's "looks like a code
example" drop. The finding context is the matched line only, so fence lines are never in it; the
bypass exists because an attacker can append a code-example indicator (``# e.g.``, "such as") to the
lure line itself in a non-executable file such as ``SKILL.md``, which would otherwise make
``is_code_example`` drop the finding.

Regex gaps are bounded (``[^\\n]{0,256}?``) and lines longer than ``MAX_LINE_CHARS`` are blanked
before matching, so scan time stays near-linear on adversarial single-line input.
"""

from __future__ import annotations

import os
import re
import sys

from skillspector.models import AnalyzerFinding, Location, Severity
from skillspector.nodes.analyzers import pattern_defaults, static_runner
from skillspector.nodes.analyzers.pattern_defaults import PatternCategory
from skillspector.state import AnalyzerNodeResponse, SkillspectorState

from . import _analyzer_registry
from ._hidden_text import FORK_CONTEXT_PREFIX
from ._patchlib import PatchDriftError

ANALYZER_ID = "exaforce_lure_rules"
LURE_RULES_ENV = "SKILLSPECTOR_EXA_LURE_RULES"

# Starts with FORK_CONTEXT_PREFIX so the shared static_runner.is_code_example bypass applies.
CONTEXT_MARKER = FORK_CONTEXT_PREFIX + "lure] "

CONFIDENCE = 0.9
MAX_FINDINGS_PER_RULE = 10  # per file
# Lines longer than this are skipped (blanked, newlines kept so line numbers hold). Bounded gaps
# alone still leave ~quadratic cost on a very long line; real install commands are far shorter.
# ``benchmark/benchmark/rulelab.py`` applies the same cap so offline and live agree.
MAX_LINE_CHARS = 4096
_LONG_LINE = re.compile(r"[^\n]{%d,}" % (MAX_LINE_CHARS + 1))
_FLAGS = re.IGNORECASE | re.MULTILINE

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
        r"[^\n]{0,256}?(?:\||&&|;)\s*(?:sudo\s+(?:-\S+\s+)*)?"
        r"(?:(?:ba|z|da|k)?sh\b(?!\s+-c\b)|iex\b|invoke-expression\b"
        r"|python[\d.]*(?![\w.])(?!\s+-[cm]\b)|node(?![\w.-])(?!\s+-[ep]\b))"
        # sh -c "$(curl ... host ...)" / eval "$(wget ... host ...)"
        r"|(?:\b(?:ba|z|da|k)?sh\s+(?:-\w+\s+)*|\beval\s+)[\"']?(?:\$\(|<\(|`)\s*"
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
        r"\bbase64\s+(?:-\w+\s+)*?(?:-[a-z]*d[a-z]*|--decode)\b[^\n]{0,256}?"
        r"\|\s*(?:sudo\s+(?:-\S+\s+)*)?"
        r"(?:(?:ba|z|da|k)?sh\b(?!\s+-c\b)|python[\d.]*(?![\w.])(?!\s+-[cm]\b)"
        r"|perl\b(?!\s+-e\b)|node(?![\w.-])(?!\s+-[ep]\b))"
        # sh -c "$(... base64 -d)" / eval "$(... base64 -d)"
        r"|(?:\b(?:ba|z|da|k)?sh\s+(?:-\w+\s+)*|\beval\s+)[\"']?(?:\$\(|<\(|`)[^\n]{0,256}?"
        r"\bbase64\s+(?:-\w+\s+)*?(?:-[a-z]*d[a-z]*|--decode)\b"
        # PowerShell -EncodedCommand (or an accepted abbreviation) with a payload
        r"|\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,256}?\s-(?:e|ec|enc\w*)\s+"
        r"(?:[a-z0-9+/]{16,}={0,2}|\$\w+)"
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
    return os.environ.get(LURE_RULES_ENV) == "on"


def analyze(content: str, file_path: str, file_type: str) -> list[AnalyzerFinding]:
    """Find remote-installer lures (EXA-LU1, EXA-LU4) in one file."""
    findings: list[AnalyzerFinding] = []
    content = _LONG_LINE.sub("", content)
    for rule_id, pattern in PATTERNS.items():
        for count, match in enumerate(pattern.finditer(content)):
            if count >= MAX_FINDINGS_PER_RULE:
                break
            start = match.start()
            line_no = content.count("\n", 0, start) + 1
            line_start = content.rfind("\n", 0, start) + 1
            line_end = content.find("\n", start)
            line = content[line_start : line_end if line_end >= 0 else len(content)]
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
    """Register the EXA-LU texts and the lure analyzer node (idempotent).

    The code-example bypass for ``CONTEXT_MARKER`` is the shared interceptor that
    ``_hidden_text.apply`` installs unconditionally, so it works with only this flag on.
    """
    _register_texts()
    _analyzer_registry.register_analyzer(ANALYZER_ID, node, enabled=_enabled)
