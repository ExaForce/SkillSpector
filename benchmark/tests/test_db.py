# SPDX-License-Identifier: Apache-2.0
"""Tests for run deletion across the benchmark DuckDB schema."""

from __future__ import annotations

import json

import duckdb

from benchmark.db import (
    _EVAL_VIEW,
    _RUN_TABLES,
    _SCHEMA,
    config_snapshot,
    delete_runs,
    run_row_counts,
)


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


def test_open_db_adds_llm_call_columns_to_an_older_db(tmp_path):
    from benchmark.db import open_db

    path = tmp_path / "old.duckdb"
    con = duckdb.connect(str(path))
    con.execute(
        _SCHEMA.replace(",\n    llm_calls_attempted INTEGER", "").replace(
            ",\n    llm_calls_succeeded INTEGER  -- < attempted: some LLM batches were dropped (e.g. 429s)",
            "",
        )
    )
    con.execute(_EVAL_VIEW)
    assert "llm_calls_attempted" not in {
        r[0] for r in con.execute("DESCRIBE classifications").fetchall()
    }
    con.close()

    con, _, _ = open_db(path, None)
    cols = {r[0] for r in con.execute("DESCRIBE classifications").fetchall()}
    assert {"llm_calls_attempted", "llm_calls_succeeded"} <= cols


def _scan_with_issue(tags):
    from benchmark.models import ScanResult, Unit

    unit = Unit(
        unit_path="Skills/malware/x", category="skill", source_path="/x",
        display_name="x", is_malicious=True,
    )  # fmt: skip
    issue = {"id": "SSD-1", "severity": "HIGH", "confidence": 0.9, "location": {"file": "SKILL.md"}}
    if tags is not None:
        issue["tags"] = tags
    return ScanResult(unit=unit, scan_status="ok", issues=[issue])


def test_record_result_persists_finding_tags():
    from benchmark.db import record_result

    con = _fresh_db()
    record_result(con, "r", _scan_with_issue(["llm-unconfirmed"]), no_llm=False)
    record_result(con, "s", _scan_with_issue(None), no_llm=False)

    tags = dict(con.execute("SELECT run_id, tags FROM issues ORDER BY run_id").fetchall())
    assert tags == {"r": ["llm-unconfirmed"], "s": []}
    unconfirmed = con.execute(
        "SELECT count(*) FROM issues WHERE list_contains(tags, 'llm-unconfirmed')"
    ).fetchone()[0]
    assert unconfirmed == 1


def test_open_db_adds_issue_tags_column_to_an_older_db(tmp_path):
    from benchmark.db import open_db

    path = tmp_path / "old.duckdb"
    con = duckdb.connect(str(path))
    con.execute(_SCHEMA.replace(",\n    tags VARCHAR[]", ""))
    con.execute(_EVAL_VIEW)
    assert "tags" not in {r[0] for r in con.execute("DESCRIBE issues").fetchall()}
    con.close()

    con, _, _ = open_db(path, None)
    assert "tags" in {r[0] for r in con.execute("DESCRIBE issues").fetchall()}


def test_config_snapshot_keeps_flags_drops_secrets():
    env = {
        "SKILLSPECTOR_EXA_X": "on",
        "SKILLSPECTOR_API_KEY": "s",
        "SKILLSPECTOR_TOKEN_LIMIT": "5",
        "MODEL_OVERRIDE": "m",
        "MODEL_OVERRIDE_SECRET": "s",
        "OPENAI_API_KEY": "s",
        "PATH": "/bin",
    }
    snap = json.loads(config_snapshot(env, "abc123"))
    assert snap == {"git_sha": "abc123", "env": {"SKILLSPECTOR_EXA_X": "on", "MODEL_OVERRIDE": "m"}}


def test_open_db_adds_config_json_to_an_older_db(tmp_path):
    from benchmark.db import open_db

    path = tmp_path / "old.duckdb"
    con = duckdb.connect(str(path))
    con.execute(_SCHEMA.replace(",\n    config_json TEXT", ""))
    con.execute(_EVAL_VIEW)
    assert "config_json" not in {r[0] for r in con.execute("DESCRIBE runs").fetchall()}
    con.close()

    con, _, _ = open_db(path, None)
    assert "config_json" in {r[0] for r in con.execute("DESCRIBE runs").fetchall()}


def test_current_git_sha_is_nonempty_string():
    from benchmark.db import current_git_sha

    assert current_git_sha()
