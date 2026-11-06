# P5 offline prototyping: notes

Hand-written companion to `recall-p5-offline.md`. That file is `rulelab` output and is regenerated
whole on every run, so notes live here. To regenerate it:

```
uv run rulelab results/recall.duckdb e16e394f65c3 --patterns-module benchmark.lure_candidates \
  -o results/recall-p5-offline.md --matched-out results/evalsets/p5-matched.txt
```

`results/evalsets/p5-matched.txt` lists the 305 units (benign and malicious) matched by an
IMPLEMENT rule (EXA-LU1 or EXA-LU4).

## Versions and revisions

The regexes have one version, v0: written and unit-tested before the first dataset run and never
changed. No revision was made under the two-revision allowance. A revision may only remove
benign matches, and no rule fails, or ever failed, the benign bar.

## History: the original bar (v0 run, commit 553b7d0d)

The original bar had three parts:
- benign matched <= 12;
- FN matched >= 15;
- fewer than half of the FN matches already carry a HIGH/CRITICAL issue at baseline-v2.

Every rule was DROP under it:

| Rule | Benign | TP | FN | FN with HIGH+ | Verdict (original bar) |
|---|---|---|---|---|---|
| EXA-LU1 | 0 | 134 | 25 | 25 (100%) | DROP (bar 3) |
| EXA-LU2 | 0 | 36 | 5 | 5 (100%) | DROP (bars 2, 3) |
| EXA-LU3 | 2 | 1 | 0 | 0 | DROP (bar 2) |
| EXA-LU4 | 5 | 69 | 72 | 65 (90%) | DROP (bar 3) |

## Amendment (commit 067cdd0c, user decision 2026-11-04)

The third bar assumed a new HIGH finding adds nothing to a FN that already carries one. That is
false: upstream risk scoring adds points across distinct rule ids, and the matched FNs sit at
risk 21-50. Bars 2 and 3 were replaced by the replay, which judges each rule alone. The replay
asks whether at least 15 of the baseline-v2 FN units it matches would reach risk > 50 with one
finding of the rule added at its severity points × 0.8 (HIGH +20, MEDIUM +8). This is a post-hoc
change made with the offline results in view. The spec's dev and acceptance rules still decide
P5.

## Verdicts under the amended bar

| Rule | Severity | Benign | Replay FN->TP | Replay TN->FP | Verdict |
|---|---|---|---|---|---|
| EXA-LU1 | HIGH | 0 | 16 of 25 FN | 0 | IMPLEMENT |
| EXA-LU2 | HIGH | 0 | 4 of 5 FN | 0 | DROP (replay 4 < 15) |
| EXA-LU3 | MEDIUM | 2 | 0 of 0 FN | 0 | DROP (replay 0 < 15) |
| EXA-LU4 | HIGH | 5 | 42 of 72 FN | 1 | IMPLEMENT |

EXA-LU1 passes with one flip to spare (16 against a bar of 15).

## The benign matches

Baseline-v2 outcome and risk score are given for each unit.

- EXA-LU4 (5): security-education / skill-auditor skills that quote attack patterns
  (`base64 -d | bash`, `eval $(... | base64 -d)`) as examples of what to detect:
  - `ecap-security-auditor`: FP, risk 100 (already FP);
  - `openclaw-defender`: TN, risk 0;
  - `openclaw-skill-vetter`: TN, risk 0;
  - `skill-security-audit`: TN, risk 40. This is the 1 replay TN->FP (40 + 20 > 50);
  - `skillguard-scanner`: TN, risk 0.

  These matches are expected (plan Review Focus 5: the rule does not know intent).
- EXA-LU3 (2):
  - `ecap-security-auditor`: an auditor skill's design note telling the agent to "skip integrity
    verification" for non-skill npm/pip packages. Already FP.
  - `waizao-stockapi__stb-case_05433`: TN, risk 27. A documented
    `pip install -i http://<public PyPI mirror>/simple/ --trusted-host=<mirror>` line.

## Context: existing HIGH+ issues (information only)

At baseline-v2, 834 of the 1,846 FN units (45%) carry at least one HIGH/CRITICAL issue. These
are the HIGH+ rules already present on the FN matches, with the number of units each:
- LU1: SQP-2 10, SDI-1 9, SC2 6, SSD-1 4, SDI-2 4, SSD-2 2, SSD-3 2, RA1 1.
- LU4: SSD-2 27, SSD-3 21, SQP-2 13, SDI-1 11, SQP-3 9, SSD-1 8, SDI-2 5, SQP-1 4.

## Design notes

- Each rule is one regex: a `PATTERN_SOURCES` literal compiled with
  `FLAGS = IGNORECASE | MULTILINE`. The severities come from the `SEVERITY` literal in
  `benchmark/benchmark/lure_candidates.py`.
- A rule matches a unit iff it matches any of the unit's files.
- EXA-LU2's multi-line condition (archive download, stated password, run/open instruction) is
  expressed with lookaheads anchored at a line start. All three parts must fall within that line
  and the next 5 lines, so the archive and the password are at most 5 lines apart.
- Files are matched as the scanner sees them:
  - units with materialized content are matched over that content;
  - other units are matched over every regular file under the unit directory, with symlinks
    not followed;
  - binary files (with a NUL byte) and files over `MAX_FILE_CHARS` (1,000,000 characters) are
    skipped.
- The replay uses the scanner's `_SEVERITY_POINTS` (from `skillspector.nodes.report`) × 0.8. It
  adds one finding to the unit's baseline-v2 `risk_score`. A unit already above 50, or with no
  score, never flips.

## Regex sources (v0, unchanged)

EXA-LU1:

```
\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]*?(?:https?://|(?<=[\s\"'(=]))(?!127\.)(?:(?:\d{1,3}\.){3}\d{1,3}|(?:www\.)?(?:pastebin\.com|paste\.ee|pastie\.org|hastebin\.com|dpaste\.com|dpaste\.org|paste\.rs|termbin\.com|ix\.io|sprunge\.us|rentry\.co|rentry\.org|controlc\.com|justpaste\.it|paste\.debian\.net|bpa\.st|paste\.mozilla\.org|gist\.github\.com|gist\.githubusercontent\.com|glot\.io|0bin\.net|paste\.gg|pastes\.dev|codepad\.org))(?![\w.-])[^\n]*?(?:\||&&|;)\s*(?:sudo\s+(?:-\S+\s+)*)?(?:(?:ba|z|da|k)?sh\b(?!\s+-c\b)|iex\b|invoke-expression\b|python[\d.]*(?![\w.])(?!\s+-[cm]\b)|node(?![\w.-])(?!\s+-[ep]\b))|(?:\b(?:ba|z|da|k)?sh\s+(?:-\w+\s+)*|\beval\s+)[\"']?(?:\$\(|<\(|`)\s*(?:curl|wget)\b[^\n]*?(?:https?://|(?<=[\s\"'(=]))(?!127\.)(?:(?:\d{1,3}\.){3}\d{1,3}|(?:www\.)?(?:pastebin\.com|paste\.ee|pastie\.org|hastebin\.com|dpaste\.com|dpaste\.org|paste\.rs|termbin\.com|ix\.io|sprunge\.us|rentry\.co|rentry\.org|controlc\.com|justpaste\.it|paste\.debian\.net|bpa\.st|paste\.mozilla\.org|gist\.github\.com|gist\.githubusercontent\.com|glot\.io|0bin\.net|paste\.gg|pastes\.dev|codepad\.org))(?![\w.-])|\b(?:iex|invoke-expression)\b[^\n]*?\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|curl|wget)\b[^\n]*?(?:https?://|(?<=[\s\"'(=]))(?!127\.)(?:(?:\d{1,3}\.){3}\d{1,3}|(?:www\.)?(?:pastebin\.com|paste\.ee|pastie\.org|hastebin\.com|dpaste\.com|dpaste\.org|paste\.rs|termbin\.com|ix\.io|sprunge\.us|rentry\.co|rentry\.org|controlc\.com|justpaste\.it|paste\.debian\.net|bpa\.st|paste\.mozilla\.org|gist\.github\.com|gist\.githubusercontent\.com|glot\.io|0bin\.net|paste\.gg|pastes\.dev|codepad\.org))(?![\w.-])
```

EXA-LU2:

```
^(?=[^\n]*?(?:\b(?:download\w*|curl|wget|iwr|invoke-webrequest)\b|\b(?:password|passphrase|passcode|passwd|pwd)\b|\b(?:unzip|7z|7za|unrar)\b|\b(?:run|execute|launch|open|double[- ]?click|start)\b|\bchmod\b|\./))(?=(?:[^\n]*\n){0,5}?[^\n]*?\b(?:download\w*|curl|wget|iwr|invoke-webrequest)\b[^\n]*?(?:\.(?:zip|rar|7z)\b|\b(?:zip|rar|7z|archive)\b))(?=(?:[^\n]*\n){0,5}?[^\n]*?(?:\b(?:password|passphrase|passcode|passwd|pwd)\b[^\n]{0,30}?(?:\bis\b|[:=])[ \t`\"'*_]*[^\s`\"'*_]|\bunzip\b[^\n]*?\s(?-i:-P)\s*\S|\b(?:7z|7za|unrar)\b[^\n]*?\s(?-i:-p)\S))(?=(?:[^\n]*\n){0,5}?[^\n]*?(?:\b(?:run|execute|launch|open|double[- ]?click|start)\b[^\n]{0,60}?(?:\.(?:exe|msi|bat|cmd|ps1|vbs|scr|jar|app|dmg|pkg|sh|py|command|lnk)\b|\b(?:it|installer|setup|executable|binary|program|application|app|file)\b)|\bchmod\s+\+x\b|(?:^|\s)\./[\w.-]+))
```

EXA-LU3:

```
^(?=[^\n]*\b(?:install\w*|download\w*|setup|curl|wget|pip3?|npm|brew|apt(?:-get)?)\b)[^\n]*?\b(?:skip\w*|ignor\w*|disabl\w*|bypass\w*)\b[^\n]{0,40}?\b(?:checksums?|signatures?|verification|integrity checks?|hash checks?)\b|\bcurl\b[^\n]*?\s(?:-(?-i:[a-zA-Z]*k[a-zA-Z]*)|--insecure)(?=\s)[^\n]*?\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k)?sh\b|\bwget\b[^\n]*?--no-check-certificate\b[^\n]*?\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k)?sh\b|--trusted-host\b[^\n]*?(?:--(?:extra-)?index-url|\s-i)[\s=]+http://|(?:--(?:extra-)?index-url|\s-i)[\s=]+http://[^\n]*?--trusted-host\b|\bset-executionpolicy\s+(?:-executionpolicy\s+)?bypass\b(?:[^\n]*\n){0,3}?[^\n]*?\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|start-bitstransfer|curl|wget)\b|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|start-bitstransfer|curl|wget)\b(?:[^\n]*\n){0,3}?[^\n]*?\bset-executionpolicy\s+(?:-executionpolicy\s+)?bypass\b
```

EXA-LU4:

```
\bbase64\s+(?:-\w+\s+)*?(?:-[a-z]*d[a-z]*|--decode)\b[^\n]*?\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:(?:ba|z|da|k)?sh\b(?!\s+-c\b)|python[\d.]*(?![\w.])(?!\s+-[cm]\b)|perl\b(?!\s+-e\b)|node(?![\w.-])(?!\s+-[ep]\b))|(?:\b(?:ba|z|da|k)?sh\s+(?:-\w+\s+)*|\beval\s+)[\"']?(?:\$\(|<\(|`)[^\n]*?\bbase64\s+(?:-\w+\s+)*?(?:-[a-z]*d[a-z]*|--decode)\b|\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*?\s-(?:e|ec|enc\w*)\s+(?:[a-z0-9+/]{16,}={0,2}|\$\w+)|\bfrombase64string\b[\s\S]{0,400}?\b(?:iex|invoke-expression)\b|\b(?:iex|invoke-expression)\b[^\n]*?\bfrombase64string\b
```

