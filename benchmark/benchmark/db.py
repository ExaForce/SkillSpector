"""DuckDB output: schema definition and result persistence.

Output tables: ``runs``, ``units`` (ground truth), ``classifications``
(SkillSpector verdict), ``issues``, ``components``, plus an ``evaluation`` view
that labels every scan TP/FP/TN/FN/ERROR.
"""

from __future__ import annotations

import pathlib

from .config import MALICIOUS_RECOMMENDATION
from .models import ScanResult

_SCHEMA = """
CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    dataset_path TEXT,
    provider TEXT,
    model TEXT,
    region TEXT,
    use_llm BOOLEAN,
    workers INTEGER,
    sample_limit INTEGER,
    description TEXT
);
CREATE TABLE units (
    run_id TEXT,
    unit_path TEXT,
    category TEXT,
    source_path TEXT,
    display_name TEXT,
    is_malicious BOOLEAN,
    label TEXT,
    best_guess_label TEXT,
    label_source TEXT,
    attack_vector TEXT,
    behavior TEXT,
    insertion_strategy TEXT,
    corpus TEXT,
    sample_type TEXT
);
CREATE TABLE classifications (
    run_id TEXT,
    unit_path TEXT,
    classification TEXT,
    is_malicious BOOLEAN,
    risk_score INTEGER,     -- 0-100 score behind the verdict (severity, not a probability)
    risk_severity TEXT,
    run_time DOUBLE,
    status TEXT,
    error TEXT,
    num_issues INTEGER
);
CREATE TABLE issues (
    run_id TEXT,
    unit_path TEXT,
    issue_index INTEGER,
    rule_id TEXT,
    category TEXT,
    pattern TEXT,
    severity TEXT,
    confidence DOUBLE,
    file TEXT,
    start_line INTEGER,
    end_line INTEGER,
    intent TEXT,
    explanation TEXT
);
CREATE TABLE components (
    run_id TEXT,
    unit_path TEXT,
    path TEXT,
    type TEXT,
    lines INTEGER,
    executable BOOLEAN,
    size_bytes BIGINT
);
"""

# Ground truth (units.is_malicious) vs SkillSpector's verdict
# (classifications.is_malicious), labeled per scan.
_EVAL_VIEW = """
CREATE VIEW evaluation AS
SELECT
    u.run_id,
    u.unit_path,
    u.category,
    u.corpus,
    u.attack_vector,
    u.behavior,
    u.is_malicious AS truth_malicious,
    c.is_malicious AS predicted_malicious,
    c.classification,
    c.risk_score,
    c.risk_severity,
    c.status,
    CASE
        WHEN c.status = 'Error' OR c.is_malicious IS NULL THEN 'ERROR'
        WHEN u.is_malicious AND c.is_malicious THEN 'TP'
        WHEN u.is_malicious AND NOT c.is_malicious THEN 'FN'
        WHEN NOT u.is_malicious AND c.is_malicious THEN 'FP'
        ELSE 'TN'
    END AS outcome
FROM units u
JOIN classifications c USING (run_id, unit_path);
"""


# Every table keyed by run_id -- deleting a run means clearing its rows in all of
# them (there is no FK cascade in the schema).
_RUN_TABLES = ("runs", "units", "classifications", "issues", "components")


def classification_status(res: ScanResult, no_llm: bool) -> str:
    """How SkillSpector produced this verdict (the user's status enum)."""
    if res.scan_status != "ok":
        return "Error"
    if no_llm:
        return "StaticAnalysis"
    if res.llm_requested and not res.llm_available:
        return "StaticAnalysisFallback"
    return "LLM"


def known_run_ids(con) -> list[str]:
    """Every run_id in the DB, newest first -- for resolution and error messages."""
    return [
        r[0] for r in con.execute("SELECT run_id FROM runs ORDER BY started_at DESC").fetchall()
    ]


def resolve_run_id(con, ref: str) -> str:
    """Resolve a run-id reference against the runs table: exact, else unique prefix.

    Raises SystemExit (with the known ids) if the reference is unknown or matches
    more than one run.
    """
    if con.execute("SELECT 1 FROM runs WHERE run_id = ? LIMIT 1", [ref]).fetchone():
        return ref
    known = known_run_ids(con)
    matches = [r for r in known if r.startswith(ref)]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise SystemExit(f"run id {ref!r} not found. known run ids: {known or '(none)'}")
    raise SystemExit(f"run id {ref!r} is ambiguous; matches: {matches}")


def open_db(path: pathlib.Path, run_id: str | None):
    """Open the DuckDB file, creating the schema on first use.

    Returns ``(con, done_unit_paths, extending)``.

    ``run_id`` is None -> a new run: the schema is created if the file is new
    (a new run is otherwise appended into an existing benchmark DB), and an
    empty done-set is returned -- the caller assigns a fresh run_id and inserts
    the ``runs`` row. ``run_id`` is set -> extend that run: it must already
    exist in the file, and the set of unit_paths already classified cleanly is
    returned so they are skipped.
    """
    import duckdb

    con = duckdb.connect(str(path))
    tables = {r[0] for r in con.execute("SHOW TABLES").fetchall()}
    if "runs" not in tables:
        if run_id is not None:
            raise SystemExit(
                f"cannot extend run {run_id}: {path} has no benchmark results. "
                "Omit --run-id to start a new run."
            )
        con.execute(_SCHEMA)
        con.execute(_EVAL_VIEW)
        return con, set(), False
    if run_id is None:
        return con, set(), False  # append a new run into the existing DB
    if not con.execute("SELECT 1 FROM runs WHERE run_id = ? LIMIT 1", [run_id]).fetchone():
        known = known_run_ids(con)
        raise SystemExit(f"run id {run_id} not found in {path}. known run ids: {known or '(none)'}")
    done = {
        r[0]
        for r in con.execute(
            "SELECT unit_path FROM classifications WHERE run_id = ? AND status <> 'Error'",
            [run_id],
        ).fetchall()
    }
    return con, done, True


def purge_incomplete(con, run_id: str) -> None:
    """Drop rows for units that did NOT classify cleanly, so a resume re-scans
    them without leaving duplicate/partial rows behind."""
    bad = [
        r[0]
        for r in con.execute(
            "SELECT unit_path FROM classifications WHERE run_id = ? AND status = 'Error'",
            [run_id],
        ).fetchall()
    ]
    if not bad:
        return
    con.execute("CREATE TEMP TABLE _purge(unit_path VARCHAR)")
    con.executemany("INSERT INTO _purge VALUES (?)", [[p] for p in bad])
    for table in ("classifications", "units", "issues", "components"):
        con.execute(
            f"DELETE FROM {table} WHERE run_id = ? "  # noqa: S608 - fixed table names
            "AND unit_path IN (SELECT unit_path FROM _purge)",
            [run_id],
        )
    con.execute("DROP TABLE _purge")


def run_row_counts(con, run_id: str) -> dict[str, int]:
    """Rows attributable to ``run_id`` in each run-scoped table -- for the delete preview."""
    return {
        table: con.execute(
            f"SELECT count(*) FROM {table} WHERE run_id = ?",  # noqa: S608 - fixed table names
            [run_id],
        ).fetchone()[0]
        for table in _RUN_TABLES
    }


def delete_runs(con, run_ids: list[str]) -> None:
    """Delete every row for the given ``run_ids`` across all run-scoped tables.

    Runs in a single transaction so a batch delete is all-or-nothing. ``run_ids``
    must be exact ids already resolved against the ``runs`` table; duplicates are
    ignored and an empty list is a no-op.
    """
    ids = list(dict.fromkeys(run_ids))
    if not ids:
        return
    placeholders = ",".join("?" * len(ids))
    con.execute("BEGIN TRANSACTION")
    try:
        for table in _RUN_TABLES:
            con.execute(
                f"DELETE FROM {table} WHERE run_id IN ({placeholders})",  # noqa: S608 - fixed table names
                ids,
            )
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise


def record_result(con, run_id: str, res: ScanResult, no_llm: bool) -> None:
    u = res.unit
    con.execute(
        "INSERT INTO units VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            run_id,
            u.unit_path,
            u.category,
            u.source_path,
            u.display_name,
            u.is_malicious,
            u.label,
            u.best_guess_label,
            u.label_source,
            u.attack_vector,
            u.behavior,
            u.insertion_strategy,
            u.corpus,
            u.sample_type,
        ],
    )
    ok = res.scan_status == "ok"
    predicted = (res.risk_recommendation == MALICIOUS_RECOMMENDATION) if ok else None
    con.execute(
        "INSERT INTO classifications VALUES (?,?,?,?,?,?,?,?,?,?)",
        [
            run_id,
            u.unit_path,
            res.risk_recommendation if ok else None,
            predicted,
            res.risk_score,
            res.risk_severity,
            res.scan_seconds,
            classification_status(res, no_llm),
            res.error_message,
            res.num_issues,
        ],
    )
    for idx, issue in enumerate(res.issues):
        loc = issue.get("location", {}) or {}
        con.execute(
            "INSERT INTO issues VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                run_id,
                u.unit_path,
                idx,
                issue.get("id"),
                issue.get("category"),
                issue.get("pattern"),
                issue.get("severity"),
                issue.get("confidence"),
                loc.get("file"),
                loc.get("start_line"),
                loc.get("end_line"),
                issue.get("intent"),
                (issue.get("explanation") or "")[:4000],
            ],
        )
    for comp in res.components:
        con.execute(
            "INSERT INTO components VALUES (?,?,?,?,?,?,?)",
            [
                run_id,
                u.unit_path,
                comp.get("path"),
                comp.get("type"),
                comp.get("lines"),
                bool(comp.get("executable")),
                comp.get("size_bytes"),
            ],
        )


def print_summary(con, run_id: str) -> None:
    rows = con.execute(
        "SELECT outcome, count(*) FROM evaluation WHERE run_id = ? GROUP BY outcome",
        [run_id],
    ).fetchall()
    counts = dict(rows)
    tp, fp, tn, fn = (counts.get(k, 0) for k in ("TP", "FP", "TN", "FN"))
    err = counts.get("ERROR", 0)
    print("\n=== classification summary (verdict = DO_NOT_INSTALL) ===")
    print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}  errors={err}")
    if tp + fp:
        print(f"  precision = {tp / (tp + fp):.3f}")
    if tp + fn:
        print(f"  recall    = {tp / (tp + fn):.3f}")
    total = tp + fp + tn + fn
    if total:
        print(f"  accuracy  = {(tp + tn) / total:.3f}  (over {total} scored units)")
