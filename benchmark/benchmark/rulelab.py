# SPDX-License-Identifier: Apache-2.0
"""Offline rule prototyping: count a candidate static rule set's matches over a run's units.

Static rules are cheap, so before any classifier code ships each candidate regex gets an exact
benign/malicious match count over the whole dataset, joined to an existing run's outcomes.

- Units are the run's ``evaluation`` rows, enumerated on disk with ``MalSkillBenchHandler``.
  A unit with ``materialize`` content is matched over those file contents; any other unit over
  every regular file under its ``source_path`` (recursively, symlinks not followed).
- Like the scanner, a file whose decoded text is longer than ``MAX_FILE_CHARS`` is skipped;
  binary files (holding a NUL byte) are skipped too. Text is decoded as UTF-8, errors ignored.
- A rule matches a unit iff ``pattern.search(text)`` succeeds on any of its files.

Precision bar (plan ``2026-10-29-recall-p5-lure-rules``, "Precision bar amended", user decision
2026-11-04; keep in sync, do not tune here). Each rule is judged alone; it is ``IMPLEMENT`` iff
both hold, else ``DROP``:

1. benign units matched <= floor(0.2% of the run's benign units) (12 of 6,315 at baseline-v2);
2. replay: at least 15 of the run's FN units it matches would reach risk > 50 if one finding of
   the rule were added to the unit's ``risk_score`` in the run, at its severity's points (the
   scanner's ``_SEVERITY_POINTS``: HIGH 25, MEDIUM 10) x 0.8 (HIGH +20, MEDIUM +8).

The same replay is reported for benign TN units (TN -> FP). FN matches that already carry a
HIGH/CRITICAL issue are reported as information only (the original third bar, replaced).
The rule severities come from the patterns module's ``SEVERITY`` dict.

The CLI opens the DB read-only.
"""

from __future__ import annotations

import importlib
import pathlib
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field

import click
from skillspector.nodes.analyzers.static_runner import MAX_FILE_CHARS

# Mirrors ``skillspector.exaforce._lure_rules`` (a test keeps the constants and the regex
# sources equal): whitespace runs over 16 chars collapse to one space, the middle of each line
# over MAX_LINE_CHARS is blanked (length kept) for the whole-text search, and such lines are then
# searched in overlapping windows (one match per line at most). This guards against regex
# blow-up on untrusted dataset files without letting padding hide a match.
MAX_LINE_CHARS = 4096
WINDOW_OVERLAP = 2048
LONG_LINE_KEEP = 512
_LONG_LINE = re.compile(r"[^\n]{%d,}" % (MAX_LINE_CHARS + 1))
_WS_RUN = re.compile(r"[^\S\n]{17,}")


def _blank_middle(m: re.Match) -> str:
    s = m.group(0)
    return s[:LONG_LINE_KEEP] + " " * (len(s) - 2 * LONG_LINE_KEEP) + s[-LONG_LINE_KEEP:]


def _windows(line: str) -> Iterator[str]:
    step = MAX_LINE_CHARS - WINDOW_OVERLAP
    for i in range(0, max(len(line) - WINDOW_OVERLAP, 1), step):
        yield line[i : i + MAX_LINE_CHARS]


def _search(pattern: re.Pattern, text: str) -> tuple[re.Match | None, str]:
    """``pattern.search`` on normalized text with long lines windowed; returns (match, text)."""
    text = _WS_RUN.sub(" ", text)
    if not _LONG_LINE.search(text):
        return pattern.search(text), text
    short = _LONG_LINE.sub(_blank_middle, text)
    if (m := pattern.search(short)) is not None:
        return m, short
    for line in _LONG_LINE.findall(text):
        for window in _windows(line):
            if (m := pattern.search(window)) is not None:
                return m, window
    return None, text
from skillspector.nodes.report import _SEVERITY_POINTS

from .dataset_handler.malskillbench import MalSkillBenchHandler
from .models import Unit
from .report.query import one, rows

BENIGN_PER_MILLE = 2  # bar 1: at most 0.2% of benign units
MIN_FLIPS = 15  # bar 2: replay FN -> TP flips
RISK_THRESHOLD = 50  # the scanner predicts malicious iff risk_score > 50
REPLAY_CONFIDENCE = 0.8  # one added finding scores its severity points x 0.8
HIGH_SEVERITIES = ("HIGH", "CRITICAL")  # information: FN with an "existing HIGH+ rule"
EXCERPT_CHARS = 160


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #
def _unit_files(unit: Unit) -> Iterator[tuple[str, str]]:
    """Yield ``(file name, text)`` for each scannable file of a unit, in sorted order."""
    if unit.materialize:
        for name, text in sorted(unit.materialize.items()):
            if "\x00" not in text and len(text) <= MAX_FILE_CHARS:
                yield name, text
        return
    root = pathlib.Path(unit.source_path)
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        data = path.read_bytes()
        if b"\x00" in data:
            continue
        text = data.decode("utf-8", errors="ignore")
        if len(text) > MAX_FILE_CHARS:
            continue
        yield path.relative_to(root).as_posix(), text


def _excerpt(text: str, start: int, end: int) -> str:
    """A one-line excerpt of a match (at least ``EXCERPT_CHARS`` from its start)."""
    snippet = text[start : max(end, start + EXCERPT_CHARS)]
    return " ⏎ ".join(s.strip() for s in snippet.splitlines() if s.strip())[:EXCERPT_CHARS]


def _match(
    dataset: pathlib.Path, patterns: dict[str, re.Pattern], units: list[str]
) -> tuple[dict[str, set[str]], dict[tuple[str, str], str]]:
    """``match_units`` plus, per (rule, unit), the first matching file and an excerpt."""
    wanted = set(units)
    found = {
        u.unit_path: u
        for u in MalSkillBenchHandler().discover(pathlib.Path(dataset))
        if u.unit_path in wanted
    }
    missing = sorted(wanted - found.keys())
    if missing:
        raise ValueError(f"{len(missing)} units not found under {dataset}, e.g. {missing[:3]}")
    matches: dict[str, set[str]] = {rule: set() for rule in patterns}
    excerpts: dict[tuple[str, str], str] = {}
    for unit_path in sorted(found):
        pending = list(patterns)
        for name, text in _unit_files(found[unit_path]):
            for rule in list(pending):
                m, mtext = _search(patterns[rule], text)
                if m:
                    matches[rule].add(unit_path)
                    excerpts[(rule, unit_path)] = f"{name}: {_excerpt(mtext, m.start(), m.end())}"
                    pending.remove(rule)
            if not pending:
                break
    return matches, excerpts


def match_units(
    dataset: pathlib.Path, patterns: dict[str, re.Pattern], units: list[str]
) -> dict[str, set[str]]:
    """Map each rule in ``patterns`` to the unit_paths (among ``units``) it matches.

    Raises ``ValueError`` if a requested unit is not found under ``dataset``.
    """
    return _match(dataset, patterns, units)[0]


# --------------------------------------------------------------------------- #
# Scoring against the precision bar
# --------------------------------------------------------------------------- #
@dataclass
class RuleStats:
    rule: str
    benign: list[tuple[str, str, str]]  # (unit_path, corpus, outcome), sorted
    tp: int
    fn: int
    fn_high: int  # FN matches that already carry a HIGH+ issue (information)
    other: int  # malicious matches with another outcome (e.g. ERROR)
    fn_flips: int = 0  # replay: FN matches that would cross risk > 50 (FN -> TP)
    tn_flips: int = 0  # replay: benign TN matches that would cross risk > 50 (TN -> FP)
    benign_by_corpus: dict[str, int] = field(default_factory=dict)
    malicious_by_corpus: dict[str, int] = field(default_factory=dict)
    verdict: str = ""
    reasons: list[str] = field(default_factory=list)


def benign_max(n_benign: int) -> int:
    return n_benign * BENIGN_PER_MILLE // 1000


def replay_points(severity: str) -> float:
    """Risk points one added finding of ``severity`` contributes in the replay."""
    return _SEVERITY_POINTS[severity.upper()] * REPLAY_CONFIDENCE


def flips(risk_score: int | None, severity: str) -> bool:
    """Would one added finding take a unit at or below the threshold above it?"""
    if risk_score is None or risk_score > RISK_THRESHOLD:
        return False
    return risk_score + replay_points(severity) > RISK_THRESHOLD


def verdict(s: RuleStats, n_benign: int) -> tuple[str, list[str]]:
    """Apply the (amended) two-part bar; return the verdict and each failed bar."""
    reasons = []
    cap = benign_max(n_benign)
    if len(s.benign) > cap:
        reasons.append(f"benign matched {len(s.benign)} > {cap} (0.2% of {n_benign})")
    if s.fn_flips < MIN_FLIPS:
        reasons.append(f"replay FN->TP {s.fn_flips} < {MIN_FLIPS}")
    return ("DROP" if reasons else "IMPLEMENT"), reasons


def rule_stats(
    rule: str,
    matched: set[str],
    meta: dict[str, dict],
    high: set[str],
    n_benign: int,
    severity: str,
) -> RuleStats:
    """Score one rule's matched units against the run (``meta``: unit_path -> evaluation row
    with ``corpus``, ``truth_malicious``, ``outcome`` and ``risk_score``)."""
    benign, mal = [], []
    for u in sorted(matched):
        (mal if meta[u]["truth_malicious"] else benign).append(u)
    fn = [u for u in mal if meta[u]["outcome"] == "FN"]
    s = RuleStats(
        rule=rule,
        benign=[(u, meta[u]["corpus"] or "", meta[u]["outcome"]) for u in benign],
        tp=sum(meta[u]["outcome"] == "TP" for u in mal),
        fn=len(fn),
        fn_high=sum(u in high for u in fn),
        other=sum(meta[u]["outcome"] not in ("TP", "FN") for u in mal),
        fn_flips=sum(flips(meta[u]["risk_score"], severity) for u in fn),
        tn_flips=sum(
            meta[u]["outcome"] == "TN" and flips(meta[u]["risk_score"], severity) for u in benign
        ),
        benign_by_corpus=dict(sorted(Counter(meta[u]["corpus"] or "" for u in benign).items())),
        malicious_by_corpus=dict(sorted(Counter(meta[u]["corpus"] or "" for u in mal).items())),
    )
    s.verdict, s.reasons = verdict(s, n_benign)
    return s


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def _pct(n: int, d: int) -> str:
    return f"{100 * n / d:.0f}%" if d else "n/a"


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("`", "'")


def _by_corpus(counts: dict[str, int]) -> str:
    return ", ".join(f"{c or '(none)'} {n}" for c, n in counts.items()) or "-"


def render_markdown(
    run: str,
    module: str,
    dataset: str,
    n_benign: int,
    n_malicious: int,
    stats: list[RuleStats],
    excerpts: dict[tuple[str, str], str],
    severities: dict[str, str],
) -> str:
    out = [
        f"# rulelab: {module} over run {run}",
        "",
        f"Dataset: `{dataset}`. Units: {n_benign} benign, {n_malicious} malicious.",
        "",
        f"Bar (each rule alone; IMPLEMENT iff both hold): benign matched <= "
        f"{benign_max(n_benign)} (0.2%); replay FN->TP >= {MIN_FLIPS}. Replay: one finding of the"
        f" rule added to the unit's risk_score at its severity points x {REPLAY_CONFIDENCE:g}"
        f" crosses > {RISK_THRESHOLD}. FN with HIGH+ (FN matches already carrying a"
        " HIGH/CRITICAL issue) is information only.",
        "",
        "| Rule | Severity | Benign | TP | FN | FN with HIGH+ | Other | Replay FN->TP |"
        " Replay TN->FP | Benign by corpus | Malicious by corpus | Verdict |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for s in stats:
        sev = severities[s.rule]
        out.append(
            f"| {s.rule} | {sev} (+{replay_points(sev):g}) | {len(s.benign)} | {s.tp} | {s.fn}"
            f" | {s.fn_high} ({_pct(s.fn_high, s.fn)}) | {s.other} | {s.fn_flips} | {s.tn_flips}"
            f" | {_by_corpus(s.benign_by_corpus)} | {_by_corpus(s.malicious_by_corpus)}"
            f" | {s.verdict} |"
        )
    out += ["", "## Verdicts", ""]
    for s in stats:
        why = f": {'; '.join(s.reasons)}" if s.reasons else ""
        out.append(f"- {s.rule}: {s.verdict}{why}")
    for s in stats:
        out += ["", f"## {s.rule}: benign units matched ({len(s.benign)})", ""]
        if not s.benign:
            out.append("None.")
            continue
        out += ["| Unit | Corpus | Outcome | First match |", "|---|---|---|---|"]
        for unit, corpus, outcome in s.benign:
            ex = _md(excerpts.get((s.rule, unit), ""))
            out.append(f"| {unit} | {corpus} | {outcome} | `{ex}` |")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@click.command()
@click.argument("db_path", metavar="DB", type=click.Path(exists=True, dir_okay=False))
@click.argument("run")
@click.option(
    "--patterns-module",
    required=True,
    help="Importable module with PATTERNS (rule id -> compiled regex) and SEVERITY"
    " (rule id -> HIGH|MEDIUM|...).",
)
@click.option(
    "--dataset",
    type=click.Path(exists=True, file_okay=False),
    default=None,
    help="Dataset root (default: the run's dataset_path).",
)
@click.option("-o", "--output", type=click.Path(), default=None, help="Write the report here.")
@click.option(
    "--matched-out",
    type=click.Path(),
    default=None,
    help="Write the sorted unit_paths matched by any IMPLEMENT rule, one per line.",
)
def main(db_path, run, patterns_module, dataset, output, matched_out):
    """Count each candidate rule's matches over RUN's units and print the precision-bar verdict."""
    import duckdb

    module = importlib.import_module(patterns_module)
    patterns = getattr(module, "PATTERNS", None)
    if not isinstance(patterns, dict) or not patterns:
        raise click.ClickException(f"{patterns_module} has no non-empty PATTERNS dict")
    severities = getattr(module, "SEVERITY", None) or {}
    bad = sorted(r for r in patterns if str(severities.get(r, "")).upper() not in _SEVERITY_POINTS)
    if bad:
        raise click.ClickException(f"{patterns_module}.SEVERITY lacks a known severity for {bad}")
    con = duckdb.connect(db_path, read_only=True)
    try:
        dataset = dataset or one(con, "SELECT dataset_path FROM runs WHERE run_id = ?", [run]).get(
            "dataset_path"
        )
        if not dataset:
            raise click.ClickException(f"run {run} not found in {db_path} or has no dataset_path")
        meta = {
            r["unit_path"]: r
            for r in rows(
                con,
                "SELECT unit_path, corpus, truth_malicious, outcome, risk_score FROM evaluation"
                " WHERE run_id = ?",
                [run],
            )
        }
        high = {
            r["unit_path"]
            for r in rows(
                con,
                "SELECT DISTINCT unit_path FROM issues WHERE run_id = ?"
                " AND upper(severity) IN (?, ?)",
                [run, *HIGH_SEVERITIES],
            )
        }
    finally:
        con.close()
    if not meta:
        raise click.ClickException(f"run {run} has no evaluation rows")
    try:
        matches, excerpts = _match(pathlib.Path(dataset), patterns, sorted(meta))
    except ValueError as e:
        raise click.ClickException(str(e)) from e
    n_benign = sum(not r["truth_malicious"] for r in meta.values())
    stats = [
        rule_stats(rule, matches[rule], meta, high, n_benign, severities[rule]) for rule in patterns
    ]
    text = render_markdown(
        run,
        patterns_module,
        str(dataset),
        n_benign,
        len(meta) - n_benign,
        stats,
        excerpts,
        severities,
    )
    click.echo(text)
    if output:
        pathlib.Path(output).write_text(text, encoding="utf-8")
    if matched_out:
        keep = sorted(set().union(*(matches[s.rule] for s in stats if s.verdict == "IMPLEMENT")))
        pathlib.Path(matched_out).write_text("".join(f"{u}\n" for u in keep), encoding="utf-8")
