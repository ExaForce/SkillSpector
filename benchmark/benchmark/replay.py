"""Offline policy replay: re-decide a run's verdicts under a different scoring policy.

Reads a run's stored ``issues`` and ``components``, rescores every unit under a
:class:`Policy` (threshold, rule gates, a cap on documentation MEDIUM findings),
and writes the result as a **synthetic run** in the same DB so ``report``,
``health`` and ``arms`` work on it unchanged. No scans, no LLM calls.

Usage:
    replay DB RUN --policy '{"gate_rules": ["SSD-", "P2"]}' --description "SSD/P2 gate"
"""

from __future__ import annotations

import json
import pathlib
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, fields
from datetime import UTC, datetime
from typing import Literal

import click

from .config import MALICIOUS_RECOMMENDATION
from .db import open_db, resolve_run_id

# Mirrors src/skillspector/nodes/report.py `_SEVERITY_POINTS`, `_DIMINISHING_WEIGHTS`,
# `_MAX_OCCURRENCES_PER_RULE`, `_RISK_SEVERITY_BANDS`, `_RISK_RECOMMENDATION` and the
# severity rank inside `_compute_risk_score`. Reimplemented, not imported: the benchmark
# must replay old runs even if the scanner's scorer changes.
_SEVERITY_POINTS = {"CRITICAL": 50, "HIGH": 25, "MEDIUM": 10, "LOW": 5}
_UNKNOWN_SEVERITY_POINTS = 5
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_UNKNOWN_SEVERITY_RANK = 4
_DIMINISHING_WEIGHTS = (1.0, 0.5, 0.25)  # at most len() occurrences per rule_id score
_EXECUTABLE_MULTIPLIER = 1.3
_RISK_SEVERITY_BANDS = ((81, "CRITICAL"), (51, "HIGH"), (21, "MEDIUM"), (0, "LOW"))
_RISK_RECOMMENDATION = {
    "LOW": "SAFE",
    "MEDIUM": "CAUTION",
    "HIGH": MALICIOUS_RECOMMENDATION,
    "CRITICAL": MALICIOUS_RECOMMENDATION,
}
# upstream Finding.confidence default (src/skillspector/models.py); never NULL in practice.
_DEFAULT_CONFIDENCE = 0.5
UNCONFIRMED_TAG = "llm-unconfirmed"
# classifications columns -> duckdb types, for the bulk JSON insert in replay_run.
_CLASSIFICATION_COLUMNS = {
    "run_id": "VARCHAR",
    "unit_path": "VARCHAR",
    "classification": "VARCHAR",
    "is_malicious": "BOOLEAN",
    "risk_score": "INTEGER",
    "risk_severity": "VARCHAR",
    "run_time": "DOUBLE",
    "status": "VARCHAR",
    "error": "VARCHAR",
    "num_issues": "INTEGER",
    "llm_calls_attempted": "INTEGER",
    "llm_calls_succeeded": "INTEGER",
}
REPLAY_STATUS = "Replay"


@dataclass(frozen=True)
class Policy:
    """A scoring policy. ``Policy()`` is the upstream scorer and the 51 (HIGH band) cut.

    ``gate_rules``: a finding whose rule_id equals an entry, or starts with an entry that
    ends in ``-`` (``"SSD-"``), blocks the unit outright when its severity is at least
    ``gate_min_severity``. In ``confirmed`` mode, findings tagged ``llm-unconfirmed`` do not
    gate. ``doc_medium_cap``: only the first N scoring MEDIUM findings from non-executable
    files count; later ones contribute 0.
    """

    threshold: int = 51
    gate_rules: tuple[str, ...] = ()
    gate_min_severity: str = "HIGH"
    gate_mode: Literal["any", "confirmed"] = "any"
    doc_medium_cap: int | None = None

    def __post_init__(self):
        if isinstance(self.threshold, bool) or not isinstance(self.threshold, int):
            raise ValueError(f"threshold must be an int, got {self.threshold!r}")
        if not isinstance(self.gate_rules, tuple) or not all(
            isinstance(r, str) and r for r in self.gate_rules
        ):
            raise ValueError(f"gate_rules must be a tuple of rule ids, got {self.gate_rules!r}")
        if self.gate_min_severity not in _SEVERITY_RANK:
            raise ValueError(
                f"gate_min_severity must be one of {list(_SEVERITY_RANK)}, "
                f"got {self.gate_min_severity!r}"
            )
        if self.gate_mode not in ("any", "confirmed"):
            raise ValueError(f"gate_mode must be 'any' or 'confirmed', got {self.gate_mode!r}")
        if self.doc_medium_cap is not None and (
            isinstance(self.doc_medium_cap, bool)
            or not isinstance(self.doc_medium_cap, int)
            or self.doc_medium_cap < 0
        ):
            raise ValueError(
                f"doc_medium_cap must be null or an int >= 0, got {self.doc_medium_cap!r}"
            )


def _severity(f: dict) -> str:
    return (f.get("severity") or "LOW").upper()


def rescore(findings: list[dict], executable_files: set[str], policy: Policy) -> float:
    """Upstream additive risk score of ``findings`` (unclamped, untruncated), plus the cap.

    Mirrors ``_compute_risk_score`` in src/skillspector/nodes/report.py: findings sorted
    (stably) by ``(rule_id or "UNKNOWN", severity rank)``; per rule_id the 1st/2nd/3rd
    occurrence scores x1/x0.5/x0.25 and later ones 0; points scaled by confidence clamped
    to [0, 1], and confidence <= 0 is skipped before it counts as an occurrence; x1.3 when
    the finding's file is executable. ``policy.doc_medium_cap`` then zeroes MEDIUM findings
    from non-executable files after the first N that would otherwise score, in this order.

    Each finding is a dict with ``rule_id``, ``severity``, ``confidence`` and ``file``.
    Pass them in stored ``issue_index`` order: ties in the sort keep that order, as upstream.
    """
    ordered = sorted(
        findings,
        key=lambda f: (
            f.get("rule_id") or "UNKNOWN",
            _SEVERITY_RANK.get(_severity(f), _UNKNOWN_SEVERITY_RANK),
        ),
    )
    occurrences: dict[str, int] = defaultdict(int)
    doc_mediums = 0
    score = 0.0
    for f in ordered:
        conf = f.get("confidence")
        confidence = max(0.0, min(1.0, _DEFAULT_CONFIDENCE if conf is None else conf))
        if confidence <= 0.0:
            continue
        rule_id = f.get("rule_id") or "UNKNOWN"
        count = occurrences[rule_id]
        occurrences[rule_id] = count + 1
        if count >= len(_DIMINISHING_WEIGHTS):
            continue
        sev = _severity(f)
        executable = f.get("file") in executable_files
        if sev == "MEDIUM" and not executable and policy.doc_medium_cap is not None:
            doc_mediums += 1
            if doc_mediums > policy.doc_medium_cap:
                continue
        contribution = _SEVERITY_POINTS.get(sev, _UNKNOWN_SEVERITY_POINTS)
        contribution *= _DIMINISHING_WEIGHTS[count] * confidence
        if executable:
            contribution *= _EXECUTABLE_MULTIPLIER
        score += contribution
    return score


def _gate_hit(findings: list[dict], policy: Policy) -> bool:
    if not policy.gate_rules:
        return False
    min_rank = _SEVERITY_RANK[policy.gate_min_severity]
    for f in findings:
        rule_id = f.get("rule_id") or ""
        if not any(
            rule_id.startswith(g) if g.endswith("-") else rule_id == g for g in policy.gate_rules
        ):
            continue
        if _SEVERITY_RANK.get(_severity(f), _UNKNOWN_SEVERITY_RANK) > min_rank:
            continue
        if policy.gate_mode == "confirmed" and UNCONFIRMED_TAG in (f.get("tags") or []):
            continue
        return True
    return False


def _band(score: int) -> str:
    return next(band for floor, band in _RISK_SEVERITY_BANDS if score >= floor)


def _replayed_score(stored: int | None, findings, executable, policy: Policy) -> int:
    """New 0-100 score: the stored score moved by the policy's change to the recomputation.

    The stored score is what the scanner decided; a plain recomputation from stored issues
    differs from it for a few percent of units (upstream dedupe etc.), so the policy's
    *delta* is applied to the stored score and units the policy does not touch keep their
    score exactly. When the recomputation agrees with the stored score, the new score is
    the recomputation itself, which also keeps the fraction the stored int truncated.
    """
    new = rescore(findings, executable, policy)
    if stored is None:
        raw = new
    else:
        base = rescore(findings, executable, Policy())
        if new == base:
            return stored
        raw = new if min(100, int(base)) == stored else stored + (new - base)
    return min(100, max(0, int(raw)))


def _require_tags(con, src_run: str) -> None:
    n_issues, n_tagged = con.execute(
        "SELECT count(*), count(tags) FROM issues WHERE run_id = ?", [src_run]
    ).fetchone()
    if n_issues and not n_tagged:
        raise SystemExit(
            f"run {src_run} has no issues.tags (all {n_issues} are NULL); "
            "gate_mode='confirmed' needs a run recorded after tags were added"
        )


def replay_run(con, src_run: str, policy: Policy, description: str) -> str:
    """Write ``src_run`` re-decided under ``policy`` as a new run; return its run id.

    Copies the run's ``units``, ``issues`` and ``components``. Each scanned unit's
    classification gets the replayed score and verdict (status ``Replay``); units the
    source run recorded as errors stay errors with no verdict.
    """
    src = con.execute(
        "SELECT dataset_path, provider, model, region, use_llm, workers, sample_limit "
        "FROM runs WHERE run_id = ?",
        [src_run],
    ).fetchone()
    if src is None:
        raise SystemExit(f"run id {src_run!r} not found")
    if policy.gate_mode == "confirmed" and policy.gate_rules:
        _require_tags(con, src_run)

    findings: dict[str, list[dict]] = defaultdict(list)
    for unit, rule_id, severity, confidence, file, tags in con.execute(
        "SELECT unit_path, rule_id, severity, confidence, file, tags FROM issues "
        "WHERE run_id = ? ORDER BY unit_path, issue_index",
        [src_run],
    ).fetchall():
        findings[unit].append(
            {
                "rule_id": rule_id,
                "severity": severity,
                "confidence": confidence,
                "file": file,
                "tags": tags or [],
            }
        )
    executable: dict[str, set[str]] = defaultdict(set)
    for unit, path in con.execute(
        "SELECT unit_path, path FROM components WHERE run_id = ? AND executable", [src_run]
    ).fetchall():
        executable[unit].add(path)

    new_run = uuid.uuid4().hex[:12]
    rows = []
    for (
        unit, classification, is_malicious, risk_score, risk_severity,
        run_time, status, error, num_issues, attempted, succeeded,
    ) in con.execute(
        "SELECT unit_path, classification, is_malicious, risk_score, risk_severity, run_time, "
        "status, error, num_issues, llm_calls_attempted, llm_calls_succeeded "
        "FROM classifications WHERE run_id = ?",
        [src_run],
    ).fetchall():  # fmt: skip
        if status != "Error" and is_malicious is not None:
            unit_findings = findings.get(unit, [])
            score = _replayed_score(risk_score, unit_findings, executable[unit], policy)
            band = _band(score)
            predicted = score >= policy.threshold or _gate_hit(unit_findings, policy)
            if predicted:
                rec = MALICIOUS_RECOMMENDATION
            else:
                rec = _RISK_RECOMMENDATION[band]
                # Above the band cut but under a higher policy threshold: not a block.
                if rec == MALICIOUS_RECOMMENDATION:
                    rec = "CAUTION"
                # Upstream raises SAFE to CAUTION on a degraded/incomplete scan; visible
                # here only when the source score was in the LOW band.
                if rec == "SAFE" and classification == "CAUTION" and risk_severity == "LOW":
                    rec = "CAUTION"
            classification, is_malicious, risk_score, risk_severity, status = (
                rec, predicted, score, band, REPLAY_STATUS,
            )  # fmt: skip
        rows.append(dict(zip(_CLASSIFICATION_COLUMNS, (
            new_run, unit, classification, is_malicious, risk_score, risk_severity,
            run_time, status, error, num_issues, attempted, succeeded,
        ), strict=True)))  # fmt: skip

    now = datetime.now(UTC)
    config = json.dumps({"replay_of": src_run, "policy": asdict(policy)})
    con.execute("BEGIN TRANSACTION")
    try:
        con.execute(
            "INSERT INTO runs (run_id, started_at, finished_at, dataset_path, provider, model, "
            "region, use_llm, workers, sample_limit, description, config_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [new_run, now, now, *src, description, config],
        )
        for table in ("units", "issues", "components"):
            con.execute(
                f"INSERT INTO {table} BY NAME "  # noqa: S608 - fixed table names
                f"SELECT * REPLACE (CAST(? AS TEXT) AS run_id) FROM {table} WHERE run_id = ?",
                [new_run, src_run],
            )
        if rows:
            # One JSON parameter, not executemany: duckdb's per-value parameter binding
            # retries a failed import for every value (~15 s for a 12.7k-unit run).
            con.execute(
                "INSERT INTO classifications BY NAME "
                "SELECT unnest(from_json(?::JSON, ?), recursive := true)",
                [json.dumps(rows), json.dumps([_CLASSIFICATION_COLUMNS])],
            )
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    return new_run


def parse_policy(text: str) -> Policy:
    """Policy from a JSON object; unknown keys and bad values raise ``click.BadParameter``."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise click.BadParameter(f"not valid JSON: {e}", param_hint="--policy") from None
    if not isinstance(data, dict):
        raise click.BadParameter("must be a JSON object", param_hint="--policy")
    known = [f.name for f in fields(Policy)]
    unknown = sorted(set(data) - set(known))
    if unknown:
        raise click.BadParameter(
            f"unknown key(s) {unknown}; allowed: {known}", param_hint="--policy"
        )
    if isinstance(data.get("gate_rules"), list):
        data["gate_rules"] = tuple(data["gate_rules"])
    try:
        return Policy(**data)
    except ValueError as e:
        raise click.BadParameter(str(e), param_hint="--policy") from None


def _confusion(con, run_id: str) -> dict[str, int]:
    counts = dict(
        con.execute(
            "SELECT outcome, count(*) FROM evaluation WHERE run_id = ? GROUP BY outcome", [run_id]
        ).fetchall()
    )
    return {k: counts.get(k, 0) for k in ("TP", "FP", "TN", "FN", "ERROR")}


@click.command()
@click.argument(
    "db_path", metavar="DB", type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path)
)
@click.argument("run", metavar="RUN")
@click.option(
    "--policy",
    "policy_json",
    default="{}",
    show_default=True,
    help="JSON object of Policy fields: threshold, gate_rules, gate_min_severity, "
    "gate_mode ('any' | 'confirmed'), doc_medium_cap.",
)
@click.option("--description", default=None, help="runs.description of the synthetic run.")
def main(db_path, run, policy_json, description):
    """Replay RUN in DB under --policy and record the result as a new synthetic run."""
    policy = parse_policy(policy_json)
    con, _, _ = open_db(db_path, None)
    try:
        src = resolve_run_id(con, run)
        if description is None:
            description = f"replay of {src}: {policy_json}"
        new_run = replay_run(con, src, policy, description)
        old, new = _confusion(con, src), _confusion(con, new_run)
    finally:
        con.close()
    click.echo(new_run)
    click.echo(
        "  ".join(f"{k}={new[k]}" for k in new)
        + f"  ({new['TP'] - old['TP']:+d}/{new['FP'] - old['FP']:+d}) TP/FP vs {src}"
    )
