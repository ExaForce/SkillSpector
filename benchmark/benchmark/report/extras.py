"""Extra per-run report sections: health, STB split, validity tiers, attribution, FP by size.

Data only -- rendering lives in ``render`` and the templates. The label-dependent
sections read the dataset's label files from ``<runs.dataset_path>/Skills/``:

- ``_external_labels.jsonl``: SkillTrustBench vs rest (``stb_split``);
- ``_boundary_labels.jsonl``: label-validity tiers (``validity_tiers``);
- ``_skillharm_injected.jsonl``: SkillHarm attributed recall (``skillharm_attributed``).

Each section is ``None`` when its own label file is missing, so one absent file
degrades only that section. ``labels_found`` is True only when all three files
exist. ``health`` and ``fp_by_size`` need no labels and are always computed.
"""

from __future__ import annotations

import pathlib
from collections.abc import Iterable
from dataclasses import dataclass

from ..health import check_health
from .data import Breakdown
from .query import one, rows

EXTERNAL_LABELS = "_external_labels.jsonl"
BOUNDARY_LABELS = "_boundary_labels.jsonl"
SKILLHARM_INJECTED = "_skillharm_injected.jsonl"
LABEL_FILES = (EXTERNAL_LABELS, BOUNDARY_LABELS, SKILLHARM_INJECTED)

STB_SOURCE = "SkillTrustBench"
STB_KEYS = (STB_SOURCE, "non-STB")

# label_validity -> tier. working: the sample works as malware; intent: malicious
# intent but broken or unverifiable; not_malicious: weak or mislabeled.
VALIDITY_TIERS = {
    "CORRECT": "working",
    "BROKEN": "intent",
    "UNVERIFIABLE": "intent",
    "WEAK": "not_malicious",
    "MISLABELED": "not_malicious",
}
TIER_KEYS = ("working", "intent", "not_malicious")

# Benign units bucketed by component count; units with no components rows
# (typically scans that errored before inventory) fall under NO_COMPONENTS.
SIZE_BUCKETS = (("1", 1), ("2-5", 5), ("6-20", 20), ("21+", None))
NO_COMPONENTS = "(none)"
SIZE_KEYS = (*(k for k, _ in SIZE_BUCKETS), NO_COMPONENTS)

ATTRIBUTION_SEVERITIES = ("MEDIUM", "HIGH", "CRITICAL")
UNASSIGNED = "unassigned"

_OUTCOME_FIELD = {"TP": "tp", "FP": "fp", "TN": "tn", "FN": "fn", "ERROR": "errors"}


@dataclass
class AttributedRecall:
    """SkillHarm recall, plain and attributed to the injected payload.

    ``units`` is the SkillHarm malicious units that got a verdict (TP + FN; errors
    excluded), the denominator of both rates. A verdict TP is attributed when it
    has >=1 issue of severity MEDIUM or above whose ``file`` is an injected file.
    """

    units: int
    verdict_tp: int
    attributed_tp: int
    recall: float | None
    attributed_recall: float | None


@dataclass
class Extras:
    health: list[str]
    stb_split: list[Breakdown] | None
    validity_tiers: list[Breakdown] | None
    skillharm_attributed: AttributedRecall | None
    fp_by_size: list[Breakdown]
    splits: list[Breakdown] | None
    labels_found: bool


def _tally(keyed: Iterable[tuple[str, str]], order: Iterable[str] = ()) -> list[Breakdown]:
    """Count (key, outcome) pairs into Breakdowns: ``order`` first, then the rest sorted."""
    counts: dict[str, dict[str, int]] = {}
    for key, outcome in keyed:
        c = counts.setdefault(key, {"n": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0, "errors": 0})
        c["n"] += 1
        c[_OUTCOME_FIELD[outcome]] += 1
    order = [k for k in order if k in counts]
    keys = order + sorted(k for k in counts if k not in order)
    return [Breakdown(key=k, **counts[k]) for k in keys]


def _size_bucket(n_components: int | None) -> str:
    if not n_components:
        return NO_COMPONENTS
    for key, upper in SIZE_BUCKETS:
        if upper is None or n_components <= upper:
            return key
    raise AssertionError("unreachable: the last bucket is open-ended")


def _read_splits(path: pathlib.Path) -> dict[str, str]:
    """``unit_path<TAB>split`` per line; blank lines and a ``unit_path`` header are skipped."""
    splits: dict[str, str] = {}
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError(f"{path}: line {lineno}: expected 'unit_path<TAB>split'")
        if lineno == 1 and parts[0] == "unit_path":
            continue
        splits[parts[0]] = parts[1].strip()
    return splits


def _stb_split(con, labels: pathlib.Path, outcomes: list[dict]) -> list[Breakdown]:
    stb = {
        r["unit_path"]
        for r in rows(
            con,
            "SELECT DISTINCT 'Skills/' || unit AS unit_path FROM read_json_auto(?)"
            " WHERE source_dataset = ?",
            [str(labels), STB_SOURCE],
        )
    }
    keyed = (
        (STB_SOURCE if o["unit_path"] in stb else "non-STB", o["outcome"])
        for o in outcomes
        if o["truth_malicious"]
    )
    return _tally(keyed, STB_KEYS)


def _validity_tiers(con, labels: pathlib.Path, outcomes: list[dict]) -> list[Breakdown]:
    validity = {
        r["unit_path"]: r["label_validity"]
        for r in rows(con, "SELECT unit_path, label_validity FROM read_json_auto(?)", [str(labels)])
    }
    keyed = (
        (VALIDITY_TIERS.get(validity[o["unit_path"]], validity[o["unit_path"]]), o["outcome"])
        for o in outcomes
        if o["truth_malicious"] and o["unit_path"] in validity
    )
    return _tally(keyed, TIER_KEYS)


def _skillharm_attributed(con, run_id: str, injected: pathlib.Path) -> AttributedRecall:
    sql = """
    WITH inj AS (
        SELECT unit_path, unnest(files) AS file FROM read_json_auto(?)
    ),
    attributed AS (
        SELECT DISTINCT i.unit_path
        FROM issues i JOIN inj ON i.unit_path = inj.unit_path AND i.file = inj.file
        WHERE i.run_id = ? AND upper(i.severity) IN (?, ?, ?)
    )
    SELECT
        count(*) FILTER (WHERE e.outcome IN ('TP', 'FN')) AS units,
        count(*) FILTER (WHERE e.outcome = 'TP')          AS verdict_tp,
        count(*) FILTER (WHERE e.outcome = 'TP' AND a.unit_path IS NOT NULL) AS attributed_tp
    FROM evaluation e
    LEFT JOIN attributed a ON a.unit_path = e.unit_path
    WHERE e.run_id = ? AND e.truth_malicious
      AND e.unit_path IN (SELECT unit_path FROM inj)
    """
    r = one(con, sql, [str(injected), run_id, *ATTRIBUTION_SEVERITIES, run_id])
    units, tp, att = r.get("units") or 0, r.get("verdict_tp") or 0, r.get("attributed_tp") or 0
    return AttributedRecall(
        units=units,
        verdict_tp=tp,
        attributed_tp=att,
        recall=tp / units if units else None,
        attributed_recall=att / units if units else None,
    )


def load_extras(con, run_id: str, split_file: pathlib.Path | None) -> Extras:
    """Gather the extra report sections for one run (see the module docstring)."""
    outcomes = rows(
        con,
        "SELECT unit_path, truth_malicious, outcome FROM evaluation WHERE run_id = ?",
        [run_id],
    )
    n_components = {
        r["unit_path"]: r["n"]
        for r in rows(
            con,
            "SELECT unit_path, count(*) AS n FROM components WHERE run_id = ? GROUP BY unit_path",
            [run_id],
        )
    }
    fp_by_size = _tally(
        (
            (_size_bucket(n_components.get(o["unit_path"])), o["outcome"])
            for o in outcomes
            if o["truth_malicious"] is False
        ),
        SIZE_KEYS,
    )

    dataset = one(con, "SELECT dataset_path FROM runs WHERE run_id = ?", [run_id]).get(
        "dataset_path"
    )
    skills = pathlib.Path(dataset) / "Skills" if dataset else None
    present = {f: skills / f for f in LABEL_FILES if skills and (skills / f).is_file()}

    splits = None
    if split_file is not None:
        assigned = _read_splits(pathlib.Path(split_file))
        splits = _tally((assigned.get(o["unit_path"], UNASSIGNED), o["outcome"]) for o in outcomes)
        # Keep "unassigned" last whatever its name sorts as.
        splits.sort(key=lambda b: b.key == UNASSIGNED)

    return Extras(
        health=check_health(con, run_id),
        stb_split=(
            _stb_split(con, present[EXTERNAL_LABELS], outcomes)
            if EXTERNAL_LABELS in present
            else None
        ),
        validity_tiers=(
            _validity_tiers(con, present[BOUNDARY_LABELS], outcomes)
            if BOUNDARY_LABELS in present
            else None
        ),
        skillharm_attributed=(
            _skillharm_attributed(con, run_id, present[SKILLHARM_INJECTED])
            if SKILLHARM_INJECTED in present
            else None
        ),
        fp_by_size=fp_by_size,
        splits=splits,
        labels_found=len(present) == len(LABEL_FILES),
    )
