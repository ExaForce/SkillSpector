import pytest
from test_db import _fresh_db

from benchmark.health import check_health, check_health_pooled


def _make_run(**kw):
    con = _fresh_db()
    _add_run(con, **kw)
    return con


def _add_run(
    con,
    *,
    use_llm=True,
    n=20,
    semantic=True,
    dropped=0,
    errors=0,
    run_time=10.0,
    run_id="r",
    first=0,
):
    """``n`` units ``u{first}``.. into ``con``; the first ``errors`` are ERROR scans."""
    con.execute("INSERT INTO runs (run_id, use_llm) VALUES (?, ?)", [run_id, use_llm])
    for i in range(n):
        u = f"u{first + i}"
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
    problems = check_health(_make_run(dropped=3), "r")
    assert any("15.0%" in p and "> 10%" in p for p in problems)


def test_health_dropped_threshold_is_ten_percent():
    assert check_health(_make_run(n=100, dropped=10), "r") == []  # exactly 10% passes
    problems = check_health(_make_run(n=100, dropped=11), "r")  # just over 10% fails
    assert any("dropped LLM calls in 11.0% of scans (11/100) > 10%" in p for p in problems)


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


def test_check_health_is_pooled_check_of_one_run():
    for kw in ({}, {"semantic": False}, {"dropped": 3}, {"errors": 2}, {"run_time": 1.0}):
        con = _make_run(**kw)
        assert check_health(con, "r") == check_health_pooled(con, ["r"])
    con = _make_run()
    with pytest.raises(KeyError, match="nope"):
        check_health_pooled(con, ["r", "nope"])


def test_pooled_health_two_percent_each_fails_both_ways():
    con = _fresh_db()
    _add_run(con, run_id="a", n=100, errors=2)
    _add_run(con, run_id="b", n=100, errors=2, first=100)
    assert any("ERROR" in p for p in check_health(con, "a"))
    assert any("ERROR" in p for p in check_health(con, "b"))
    problems = check_health_pooled(con, ["a", "b"])
    assert any("ERROR outcomes in 2.0% of scans (4/200)" in p for p in problems), problems


def test_pooled_health_judges_union_as_one_run():
    con = _fresh_db()
    _add_run(con, run_id="a", n=50, errors=1)  # 2.0% alone
    _add_run(con, run_id="b", n=150, first=50)
    assert any("ERROR" in p for p in check_health(con, "a"))  # the old per-member rule fails it
    assert check_health_pooled(con, ["a", "b"]) == []  # 1/200 = 0.5%


def test_pooled_health_pools_dropped_semantic_median_and_use_llm():
    con = _fresh_db()
    # a: static, no semantic issues, fast, 2 of 10 dropped (20% alone)
    _add_run(con, run_id="a", n=10, use_llm=False, semantic=False, run_time=0.1, dropped=2)
    # b: LLM, one semantic issue, slow
    _add_run(con, run_id="b", n=30, first=10, run_time=10.0)
    assert any("dropped" in p for p in check_health(con, "a"))
    # pooled: use_llm from b, semantic count 1, median run_time 10.0, dropped 2/40 = 5%
    assert check_health_pooled(con, ["a", "b"]) == []
    # an LLM member with no semantic issue anywhere fails the pooled semantic check
    con = _fresh_db()
    _add_run(con, run_id="a", n=10, use_llm=False, semantic=False)
    _add_run(con, run_id="b", n=10, first=10, semantic=False)
    assert any("no SSD-/SDI-/SQP- issues" in p for p in check_health_pooled(con, ["a", "b"]))
    # pooled median: 15 fast + 10 slow scans -> median 1.0 < 3
    con = _fresh_db()
    _add_run(con, run_id="a", n=15, run_time=1.0)
    _add_run(con, run_id="b", n=10, first=15, run_time=10.0)
    assert any("median run_time 1.00s" in p for p in check_health_pooled(con, ["a", "b"]))
