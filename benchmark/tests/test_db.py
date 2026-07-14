# SPDX-License-Identifier: Apache-2.0
"""Tests for run deletion across the benchmark DuckDB schema."""

from __future__ import annotations

import duckdb
from benchmark.db import _EVAL_VIEW, _RUN_TABLES, _SCHEMA, delete_runs, run_row_counts


def _fresh_db():
    con = duckdb.connect()  # in-memory
    con.execute(_SCHEMA)
    con.execute(_EVAL_VIEW)
    return con


def _seed_run(con, run_id: str) -> None:
    """One row per run-scoped table for ``run_id`` (partial inserts; other cols null)."""
    con.execute("INSERT INTO runs (run_id) VALUES (?)", [run_id])
    con.execute("INSERT INTO units (run_id, unit_path) VALUES (?, 'u')", [run_id])
    con.execute("INSERT INTO classifications (run_id, unit_path) VALUES (?, 'u')", [run_id])
    con.execute("INSERT INTO issues (run_id, unit_path, issue_index) VALUES (?, 'u', 0)", [run_id])
    con.execute("INSERT INTO components (run_id, unit_path) VALUES (?, 'u')", [run_id])


def test_delete_runs_removes_target_across_all_tables_and_spares_others():
    con = _fresh_db()
    _seed_run(con, "keep")
    _seed_run(con, "drop")

    assert sum(run_row_counts(con, "drop").values()) == len(_RUN_TABLES)

    delete_runs(con, ["drop"])

    assert sum(run_row_counts(con, "drop").values()) == 0
    for table in _RUN_TABLES:
        assert con.execute(f"SELECT count(*) FROM {table} WHERE run_id='drop'").fetchone()[0] == 0
        assert con.execute(f"SELECT count(*) FROM {table} WHERE run_id='keep'").fetchone()[0] == 1


def test_delete_runs_handles_multiple_ids_in_one_call():
    con = _fresh_db()
    for rid in ("a", "b", "c"):
        _seed_run(con, rid)

    delete_runs(con, ["a", "c"])

    survivors = [r[0] for r in con.execute("SELECT run_id FROM runs ORDER BY run_id").fetchall()]
    assert survivors == ["b"]


def test_run_row_counts_reports_per_table():
    con = _fresh_db()
    _seed_run(con, "x")
    counts = run_row_counts(con, "x")
    assert counts == dict.fromkeys(_RUN_TABLES, 1)


def test_delete_runs_noop_on_empty_id_list():
    con = _fresh_db()
    _seed_run(con, "x")
    delete_runs(con, [])
    assert con.execute("SELECT count(*) FROM runs").fetchone()[0] == 1
