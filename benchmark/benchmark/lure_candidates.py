# SPDX-License-Identifier: Apache-2.0
"""P5 candidate "remote-installer lure" rules, prototyped offline with ``rulelab``.

Each rule is a general class (plan ``2026-10-29-recall-p5-lure-rules``, Global Constraints):

- ``EXA-LU1`` HIGH: fetch-and-execute (``curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod``
  piped or chained with ``|``, ``&&`` or ``;`` to ``sh|bash|zsh|iex|Invoke-Expression|python|node``,
  or wrapped as ``bash -c "$(curl ...)"`` / ``eval "$(curl ...)"`` / ``iex (iwr ...)``) where the
  URL host is a literal IPv4 address (loopback ``127.x`` excluded) or one of ``PASTE_HOSTS``.
  Interpreters that do not run the fetched bytes (``python -m``/``-c``, ``node -e``/``-p``,
  ``sh -c``) do not count.
- ``EXA-LU2`` HIGH: an archive download (``download``/a fetch tool and a ``.zip|.rar|.7z`` or the
  word archive on one line), a stated password (``password: x``/``password is x``,
  ``unzip -P x``, ``7z|unrar -px``) and an instruction to run or open the content, all within
  one window of 6 consecutive lines (so the archive and the password are at most 5 lines apart).
- ``EXA-LU3`` MEDIUM: disabling integrity/authenticity checks during install: a
  skip/ignore/disable/bypass of a checksum/signature/verification on a line that also names an
  install or download; ``curl -k``/``--insecure`` (and ``wget --no-check-certificate``) piped to a
  shell; ``--trusted-host`` with an ``http://`` index URL; ``Set-ExecutionPolicy Bypass`` within
  3 lines of a download.
- ``EXA-LU4`` HIGH: base64-decoded content executed: ``base64 -d|--decode`` piped to a shell or
  interpreter (or wrapped in ``bash -c "$(...)"``/``eval``); PowerShell ``-EncodedCommand``
  (and its ``-e``/``-ec``/``-enc`` abbreviations) with a payload; ``FromBase64String`` with
  ``iex``/``Invoke-Expression`` (``iex`` within 400 characters after, or before on the same line).

Every rule is one regular expression, so a rule matches a file iff ``PATTERNS[rule].search(text)``.
``EXA-LU2``'s multi-line condition is expressed with line-window lookaheads anchored at a line
start: a first lookahead requires that line to hold one of the three parts (a cheap filter), then
one lookahead per part requires it within that line and the next 5 lines.

``PATTERN_SOURCES`` holds the regex sources as plain literals (no string building) so the
classifier node can copy the dict verbatim and a test can compare the two with
``ast.literal_eval``.
"""

from __future__ import annotations

import re

FLAGS = re.IGNORECASE | re.MULTILINE

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
        r"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]*?"
        r"(?:https?://|(?<=[\s\"'(=]))(?!127\.)"
        r"(?:(?:\d{1,3}\.){3}\d{1,3}|(?:www\.)?(?:pastebin\.com|paste\.ee|pastie\.org|"
        r"hastebin\.com|dpaste\.com|dpaste\.org|paste\.rs|termbin\.com|ix\.io|sprunge\.us|"
        r"rentry\.co|rentry\.org|controlc\.com|justpaste\.it|paste\.debian\.net|bpa\.st|"
        r"paste\.mozilla\.org|gist\.github\.com|gist\.githubusercontent\.com|glot\.io|0bin\.net|"
        r"paste\.gg|pastes\.dev|codepad\.org))(?![\w.-])"
        r"[^\n]*?(?:\||&&|;)\s*(?:sudo\s+(?:-\S+\s+)*)?"
        r"(?:(?:ba|z|da|k)?sh\b(?!\s+-c\b)|iex\b|invoke-expression\b"
        r"|python[\d.]*(?![\w.])(?!\s+-[cm]\b)|node(?![\w.-])(?!\s+-[ep]\b))"
        # sh -c "$(curl ... host ...)" / eval "$(wget ... host ...)"
        r"|(?:\b(?:ba|z|da|k)?sh\s+(?:-\w+\s+)*|\beval\s+)[\"']?(?:\$\(|<\(|`)\s*"
        r"(?:curl|wget)\b[^\n]*?"
        r"(?:https?://|(?<=[\s\"'(=]))(?!127\.)"
        r"(?:(?:\d{1,3}\.){3}\d{1,3}|(?:www\.)?(?:pastebin\.com|paste\.ee|pastie\.org|"
        r"hastebin\.com|dpaste\.com|dpaste\.org|paste\.rs|termbin\.com|ix\.io|sprunge\.us|"
        r"rentry\.co|rentry\.org|controlc\.com|justpaste\.it|paste\.debian\.net|bpa\.st|"
        r"paste\.mozilla\.org|gist\.github\.com|gist\.githubusercontent\.com|glot\.io|0bin\.net|"
        r"paste\.gg|pastes\.dev|codepad\.org))(?![\w.-])"
        # iex (iwr ... host ...) / iex ((New-Object Net.WebClient).DownloadString('host'))
        r"|\b(?:iex|invoke-expression)\b[^\n]*?"
        r"\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|curl|wget)\b[^\n]*?"
        r"(?:https?://|(?<=[\s\"'(=]))(?!127\.)"
        r"(?:(?:\d{1,3}\.){3}\d{1,3}|(?:www\.)?(?:pastebin\.com|paste\.ee|pastie\.org|"
        r"hastebin\.com|dpaste\.com|dpaste\.org|paste\.rs|termbin\.com|ix\.io|sprunge\.us|"
        r"rentry\.co|rentry\.org|controlc\.com|justpaste\.it|paste\.debian\.net|bpa\.st|"
        r"paste\.mozilla\.org|gist\.github\.com|gist\.githubusercontent\.com|glot\.io|0bin\.net|"
        r"paste\.gg|pastes\.dev|codepad\.org))(?![\w.-])"
    ),
    "EXA-LU2": (
        # a line holding one of the three parts starts the 6-line window ...
        r"^(?=[^\n]*?(?:"
        r"\b(?:download\w*|curl|wget|iwr|invoke-webrequest)\b"
        r"|\b(?:password|passphrase|passcode|passwd|pwd)\b|\b(?:unzip|7z|7za|unrar)\b"
        r"|\b(?:run|execute|launch|open|double[- ]?click|start)\b|\bchmod\b|\./))"
        # ... archive download within the window
        r"(?=(?:[^\n]*\n){0,5}?[^\n]*?"
        r"\b(?:download\w*|curl|wget|iwr|invoke-webrequest)\b[^\n]*?"
        r"(?:\.(?:zip|rar|7z)\b|\b(?:zip|rar|7z|archive)\b))"
        # ... a stated archive password within the window
        r"(?=(?:[^\n]*\n){0,5}?[^\n]*?(?:"
        r"\b(?:password|passphrase|passcode|passwd|pwd)\b[^\n]{0,30}?(?:\bis\b|[:=])"
        r"[ \t`\"'*_]*[^\s`\"'*_]"
        r"|\bunzip\b[^\n]*?\s(?-i:-P)\s*\S"
        r"|\b(?:7z|7za|unrar)\b[^\n]*?\s(?-i:-p)\S))"
        # ... and an instruction to run or open the content within the window
        r"(?=(?:[^\n]*\n){0,5}?[^\n]*?(?:"
        r"\b(?:run|execute|launch|open|double[- ]?click|start)\b[^\n]{0,60}?"
        r"(?:\.(?:exe|msi|bat|cmd|ps1|vbs|scr|jar|app|dmg|pkg|sh|py|command|lnk)\b"
        r"|\b(?:it|installer|setup|executable|binary|program|application|app|file)\b)"
        r"|\bchmod\s+\+x\b|(?:^|\s)\./[\w.-]+))"
    ),
    "EXA-LU3": (
        # skip/ignore/disable/bypass a checksum/signature/verification on an install line
        r"^(?=[^\n]*\b(?:install\w*|download\w*|setup|curl|wget|pip3?|npm|brew|apt(?:-get)?)\b)"
        r"[^\n]*?\b(?:skip\w*|ignor\w*|disabl\w*|bypass\w*)\b[^\n]{0,40}?"
        r"\b(?:checksums?|signatures?|verification|integrity checks?|hash checks?)\b"
        # curl -k / --insecure (wget --no-check-certificate) piped to a shell
        r"|\bcurl\b[^\n]*?\s(?:-(?-i:[a-zA-Z]*k[a-zA-Z]*)|--insecure)(?=\s)[^\n]*?"
        r"\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k)?sh\b"
        r"|\bwget\b[^\n]*?--no-check-certificate\b[^\n]*?"
        r"\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k)?sh\b"
        # --trusted-host with a plain-http index URL (either order)
        r"|--trusted-host\b[^\n]*?(?:--(?:extra-)?index-url|\s-i)[\s=]+http://"
        r"|(?:--(?:extra-)?index-url|\s-i)[\s=]+http://[^\n]*?--trusted-host\b"
        # Set-ExecutionPolicy Bypass within 3 lines of a download (either order)
        r"|\bset-executionpolicy\s+(?:-executionpolicy\s+)?bypass\b(?:[^\n]*\n){0,3}?[^\n]*?"
        r"\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile"
        r"|start-bitstransfer|curl|wget)\b"
        r"|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile"
        r"|start-bitstransfer|curl|wget)\b(?:[^\n]*\n){0,3}?[^\n]*?"
        r"\bset-executionpolicy\s+(?:-executionpolicy\s+)?bypass\b"
    ),
    "EXA-LU4": (
        # base64 -d ... | shell or interpreter
        r"\bbase64\s+(?:-\w+\s+)*?(?:-[a-z]*d[a-z]*|--decode)\b[^\n]*?"
        r"\|\s*(?:sudo\s+(?:-\S+\s+)*)?"
        r"(?:(?:ba|z|da|k)?sh\b(?!\s+-c\b)|python[\d.]*(?![\w.])(?!\s+-[cm]\b)"
        r"|perl\b(?!\s+-e\b)|node(?![\w.-])(?!\s+-[ep]\b))"
        # sh -c "$(... base64 -d)" / eval "$(... base64 -d)"
        r"|(?:\b(?:ba|z|da|k)?sh\s+(?:-\w+\s+)*|\beval\s+)[\"']?(?:\$\(|<\(|`)[^\n]*?"
        r"\bbase64\s+(?:-\w+\s+)*?(?:-[a-z]*d[a-z]*|--decode)\b"
        # PowerShell -EncodedCommand (or an accepted abbreviation) with a payload
        r"|\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*?\s-(?:e|ec|enc\w*)\s+"
        r"(?:[a-z0-9+/]{16,}={0,2}|\$\w+)"
        # FromBase64String then iex / Invoke-Expression
        r"|\bfrombase64string\b[\s\S]{0,400}?\b(?:iex|invoke-expression)\b"
        r"|\b(?:iex|invoke-expression)\b[^\n]*?\bfrombase64string\b"
    ),
}

# Rule severities (plan Global Constraints); rulelab's replay scores one finding at these.
SEVERITY: dict[str, str] = {
    "EXA-LU1": "HIGH",
    "EXA-LU2": "HIGH",
    "EXA-LU3": "MEDIUM",
    "EXA-LU4": "HIGH",
}

PATTERNS: dict[str, re.Pattern] = {k: re.compile(v, FLAGS) for k, v in PATTERN_SOURCES.items()}
