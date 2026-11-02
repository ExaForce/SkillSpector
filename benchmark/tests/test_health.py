from test_db import _fresh_db

from benchmark.health import check_health


def _make_run(
    *,
    use_llm=True,
    n=20,
    semantic=True,
    dropped=0,
    errors=0,
    run_time=10.0,
    run_id="r",
):
    con = _fresh_db()
    con.execute("INSERT INTO runs (run_id, use_llm) VALUES (?, ?)", [run_id, use_llm])
    for i in range(n):
        u = f"u{i}"
        con.execute(
            "INSERT INTO units (run_id, unit_path, is_malicious) VALUES (?, ?, TRUE)", [run_id, u]
        )
        is_err = i < errors
        is_drop = errors <= i < errors + dropped
        con.execute(
            "INSERT INTO classifications (run_id, unit_path, is_malicious, status, run_time,"
            " llm_calls_attempted, llm_calls_succeeded) VALUES (?, ?, ?, ?, ?, 3, ?)",
            [
                run_id,
                u,
                None if is_err else True,
                "Error" if is_err else "Done",
                run_time,
                2 if is_drop else 3,
            ],
        )
        rule = "SSD-1" if (semantic and i == n - 1) else "SC1"
        con.execute(
            "INSERT INTO issues (run_id, unit_path, issue_index, rule_id) VALUES (?, ?, 0, ?)",
            [run_id, u, rule],
        )
    return con


def test_health_flags_llm_run_without_semantic_rules():
    problems = check_health(_make_run(semantic=False), "r")
    assert any("no SSD-/SDI-/SQP- issues" in p for p in problems)


def test_health_flags_dropped_llm_calls():
    problems = check_health(_make_run(dropped=2), "r")
    assert any("10.0%" in p for p in problems)


def test_health_ok():
    assert check_health(_make_run(), "r") == []


def test_health_static_run_skips_llm_checks():
    con = _make_run(use_llm=False, semantic=False, run_time=0.1)
    assert check_health(con, "r") == []


def test_health_flags_errors_and_slow_median_and_no_scans():
    assert any("ERROR" in p for p in check_health(_make_run(errors=2), "r"))
    assert any("run_time" in p for p in check_health(_make_run(run_time=1.0), "r"))
    con = _fresh_db()
    con.execute("INSERT INTO runs (run_id, use_llm) VALUES ('e', TRUE)")
    assert any("no scans" in p for p in check_health(con, "e"))


def test_health_null_run_time_and_null_calls_are_tolerated():
    con = _make_run()
    con.execute("UPDATE classifications SET run_time = NULL, llm_calls_attempted = NULL")
    assert check_health(con, "r") == []
