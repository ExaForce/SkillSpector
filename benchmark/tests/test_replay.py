# SPDX-License-Identifier: Apache-2.0
"""Tests for offline policy replay (benchmark.replay)."""

from __future__ import annotations

import json
import pathlib
import shutil

import pytest
from test_db import _fresh_db

from benchmark.replay import Policy, replay_run, rescore

SEED_DB = pathlib.Path(__file__).resolve().parents[1] / "malskillbench_agentguard_seed.duckdb"
SEED_RUN = "113b02ab497b"


def _f(rule_id, severity, confidence=1.0, file="SKILL.md", tags=None):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "confidence": confidence,
        "file": file,
        "tags": tags,
    }


def _add_unit(con, run_id, unit, *, truth, score, findings, executable=(), status="LLM"):
    """One scanned unit: units + classifications (verdict at the 51 band) + issues + components."""
    con.execute(
        "INSERT INTO units (run_id, unit_path, is_malicious) VALUES (?, ?, ?)",
        [run_id, unit, truth],
    )
    if status == "Error":
        cls, pred, sev = None, None, None
    else:
        pred = score >= 51
        cls = "DO_NOT_INSTALL" if pred else ("CAUTION" if score >= 21 else "SAFE")
        sev = "CRITICAL" if score >= 81 else "HIGH" if pred else "MEDIUM" if score >= 21 else "LOW"
    con.execute(
        "INSERT INTO classifications (run_id, unit_path, classification, is_malicious, "
        "risk_score, risk_severity, run_time, status, error, num_issues, "
        "llm_calls_attempted, llm_calls_succeeded) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        [run_id, unit, cls, pred, None if status == "Error" else score, sev, 7.5, status,
         "boom" if status == "Error" else None, len(findings), 4, 3],
    )  # fmt: skip
    for i, f in enumerate(findings):
        con.execute(
            "INSERT INTO issues (run_id, unit_path, issue_index, rule_id, severity, confidence, "
            "file, tags) VALUES (?,?,?,?,?,?,?,?)",
            [run_id, unit, i, f["rule_id"], f["severity"], f["confidence"], f["file"], f["tags"]],
        )
    files = {f["file"] for f in findings} | set(executable)
    for path in sorted(files):
        con.execute(
            "INSERT INTO components (run_id, unit_path, path, type, executable) "
            "VALUES (?, ?, ?, 'x', ?)",
            [run_id, unit, path, path in executable],
        )


def _src_run(con, run_id="src", use_llm=True):
    con.execute(
        "INSERT INTO runs (run_id, dataset_path, provider, model, region, use_llm, workers, "
        "sample_limit, description) VALUES (?, '/ds', 'openai', 'm', 'r', ?, 8, 100, 'orig')",
        [run_id, use_llm],
    )


def _outcomes(con, run_id):
    return dict(
        con.execute(
            "SELECT unit_path, outcome FROM evaluation WHERE run_id = ? ORDER BY unit_path",
            [run_id],
        ).fetchall()
    )


def test_rescore_matches_upstream_formula():
    two_high = [_f("SSD-1", "HIGH"), _f("SSD-1", "HIGH")]
    assert rescore(two_high, set(), Policy()) == pytest.approx(37.5)
    crit_exec = [_f("SC1", "CRITICAL", confidence=0.8, file="run.sh")]
    assert rescore(crit_exec, {"run.sh"}, Policy()) == pytest.approx(52.0)
    # Same finding in a non-executable file: no 1.3x.
    assert rescore(crit_exec, set(), Policy()) == pytest.approx(40.0)


def test_rescore_details_follow_upstream():
    # Max 3 per rule, highest severity first within a rule; confidence clamped; <=0 skipped;
    # unknown severity scores 5; None rule_id buckets as UNKNOWN.
    findings = [
        _f("R", "LOW"),
        _f("R", "CRITICAL"),
        _f("R", "HIGH"),
        _f("R", "MEDIUM"),
        _f("S", "HIGH", confidence=1.7),
        _f("T", "HIGH", confidence=0.0),
        _f("U", "WEIRD"),
        _f(None, "HIGH"),
    ]
    expected = (50 + 12.5 + 2.5) + 25 + 0 + 5 + 25
    assert rescore(findings, set(), Policy()) == pytest.approx(expected)


def test_gate_blocks_on_rule_prefix():
    con = _fresh_db()
    _src_run(con)
    _add_unit(con, "src", "gated", truth=True, score=25, findings=[_f("SSD-3", "HIGH")])
    _add_unit(con, "src", "low_sev", truth=True, score=10, findings=[_f("SSD-3", "MEDIUM")])
    _add_unit(con, "src", "other", truth=True, score=25, findings=[_f("SSDX", "HIGH")])
    _add_unit(con, "src", "exact", truth=False, score=25, findings=[_f("P2", "HIGH")])
    _add_unit(con, "src", "not_exact", truth=False, score=25, findings=[_f("P21", "HIGH")])

    new = replay_run(con, "src", Policy(gate_rules=("SSD-", "P2")), "gate")

    assert _outcomes(con, new) == {
        "gated": "TP",
        "low_sev": "FN",
        "other": "FN",
        "exact": "FP",
        "not_exact": "TN",
    }
    row = con.execute(
        "SELECT classification, is_malicious, risk_score, risk_severity, status "
        "FROM classifications WHERE run_id = ? AND unit_path = 'gated'",
        [new],
    ).fetchone()
    # The score is untouched by a gate; the verdict uses the upstream vocabulary.
    assert row == ("DO_NOT_INSTALL", True, 25, "MEDIUM", "Replay")


def test_gate_min_severity_is_at_least_as_severe():
    con = _fresh_db()
    _src_run(con)
    _add_unit(con, "src", "crit", truth=True, score=50, findings=[_f("SSD-1", "CRITICAL")])
    _add_unit(con, "src", "high", truth=True, score=25, findings=[_f("SSD-1", "HIGH")])
    new = replay_run(con, "src", Policy(gate_rules=("SSD-1",), gate_min_severity="CRITICAL"), "")
    assert _outcomes(con, new) == {"crit": "TP", "high": "FN"}


def test_replay_confirmed_gate_requires_tags():
    con = _fresh_db()
    _src_run(con)
    _add_unit(con, "src", "unconf", truth=True, score=25,
              findings=[_f("SSD-1", "HIGH", tags=["llm-unconfirmed"])])  # fmt: skip
    _add_unit(con, "src", "conf", truth=True, score=25, findings=[_f("SSD-1", "HIGH", tags=[])])
    policy = Policy(gate_rules=("SSD-",), gate_mode="confirmed")

    new = replay_run(con, "src", policy, "confirmed")
    assert _outcomes(con, new) == {"unconf": "FN", "conf": "TP"}
    # "any" mode gates on the unconfirmed finding too.
    any_run = replay_run(con, "src", Policy(gate_rules=("SSD-",)), "any")
    assert _outcomes(con, any_run) == {"unconf": "TP", "conf": "TP"}

    old = _fresh_db()
    _src_run(old, "notags")
    _add_unit(old, "notags", "u", truth=True, score=25, findings=[_f("SSD-1", "HIGH")])
    with pytest.raises(SystemExit, match=r"notags.*issues\.tags"):
        replay_run(old, "notags", policy, "x")
    # NULL tags are fine (treated as []) outside confirmed mode.
    assert _outcomes(old, replay_run(old, "notags", Policy(gate_rules=("SSD-",)), "y")) == {
        "u": "TP"
    }


def test_doc_medium_cap():
    meds = [_f(f"M{i}", "MEDIUM", file="ref.md") for i in range(5)]
    assert rescore(meds, set(), Policy()) == pytest.approx(50.0)
    assert rescore(meds, set(), Policy(doc_medium_cap=2)) == pytest.approx(20.0)
    # Executable files and other severities are not capped.
    exec_meds = [_f(f"M{i}", "MEDIUM", file="x.py") for i in range(3)]
    assert rescore(exec_meds + [_f("H", "HIGH", file="ref.md")], {"x.py"},
                   Policy(doc_medium_cap=0)) == pytest.approx(39.0 + 25)  # fmt: skip


def test_doc_medium_cap_lowers_replayed_score():
    con = _fresh_db()
    _src_run(con)
    meds = [_f(f"M{i}", "MEDIUM", file="ref.md") for i in range(6)]
    _add_unit(con, "src", "docs", truth=False, score=60, findings=meds)
    new = replay_run(con, "src", Policy(doc_medium_cap=2), "cap")
    row = con.execute(
        "SELECT risk_score, is_malicious, classification, risk_severity FROM classifications "
        "WHERE run_id = ?",
        [new],
    ).fetchone()
    assert row == (20, False, "SAFE", "LOW")
    assert _outcomes(con, new) == {"docs": "TN"}


def test_replay_delta_method_keeps_stored_score_offset():
    # Stored 70 while the stored findings recompute to 50 (e.g. dedupe differences upstream):
    # the delta (-20) applies to the stored score, not to the recomputation.
    con = _fresh_db()
    _src_run(con)
    meds = [_f(f"M{i}", "MEDIUM", file="ref.md") for i in range(5)]
    _add_unit(con, "src", "u", truth=True, score=70, findings=meds)
    new = replay_run(con, "src", Policy(doc_medium_cap=3), "cap")
    assert con.execute(
        "SELECT risk_score, is_malicious FROM classifications WHERE run_id = ?", [new]
    ).fetchone() == (50, False)


def test_replay_uses_exact_recomputation_when_it_agrees_with_stored_score():
    # Findings recompute to 61.8, stored 61 (upstream int()). The cap removes M2 (0.5):
    # the exact new score is 61.3 -> 61, while stored + delta would give 60.5 -> 60.
    con = _fresh_db()
    _src_run(con)
    findings = [
        _f("C", "CRITICAL"),
        _f("L", "LOW", confidence=0.26),
        _f("M1", "MEDIUM"),
        _f("M2", "MEDIUM", confidence=0.05),
    ]
    _add_unit(con, "src", "u", truth=True, score=61, findings=findings)
    new = replay_run(con, "src", Policy(threshold=61, doc_medium_cap=1), "frac")
    assert con.execute(
        "SELECT risk_score, is_malicious FROM classifications WHERE run_id = ?", [new]
    ).fetchone() == (61, True)


def test_replay_threshold_changes_verdict_vocabulary():
    con = _fresh_db()
    _src_run(con)
    _add_unit(con, "src", "u", truth=True, score=60, findings=[_f("C", "CRITICAL")])
    new = replay_run(con, "src", Policy(threshold=70), "t70")
    assert con.execute(
        "SELECT classification, is_malicious, risk_severity FROM classifications WHERE run_id = ?",
        [new],
    ).fetchone() == ("CAUTION", False, "HIGH")


def test_replay_identity_policy_reproduces_verdicts():
    con = _fresh_db()
    _src_run(con)
    # Stored scores deliberately disagree with a plain recomputation of the findings.
    _add_unit(con, "src", "tp", truth=True, score=55, findings=[_f("SSD-1", "HIGH")])
    _add_unit(con, "src", "fn", truth=True, score=50, findings=[_f("C", "CRITICAL", file="a.sh")],
              executable=("a.sh",))  # fmt: skip
    _add_unit(con, "src", "fp", truth=False, score=100, findings=[])
    _add_unit(con, "src", "tn", truth=False, score=0, findings=[_f("L", "LOW")])
    _add_unit(con, "src", "err", truth=True, score=0, findings=[], status="Error")

    new = replay_run(con, "src", Policy(), "identity")

    assert new != "src" and len(new) == 12
    assert _outcomes(con, new) == _outcomes(con, "src")
    assert _outcomes(con, new)["err"] == "ERROR"
    for table in ("units", "issues", "components"):
        n_src, n_new = (
            con.execute(f"SELECT count(*) FROM {table} WHERE run_id = ?", [r]).fetchone()[0]
            for r in ("src", new)
        )
        assert n_src == n_new > 0
    cls = {
        r[0]: r[1:]
        for r in con.execute(
            "SELECT unit_path, status, risk_score, run_time, llm_calls_attempted, "
            "llm_calls_succeeded, error, num_issues FROM classifications WHERE run_id = ?",
            [new],
        ).fetchall()
    }
    assert cls["tp"] == ("Replay", 55, 7.5, 4, 3, None, 1)
    assert cls["err"] == ("Error", None, 7.5, 4, 3, "boom", 0)
    run = con.execute(
        "SELECT dataset_path, provider, model, region, use_llm, workers, sample_limit, "
        "description, config_json, started_at IS NOT NULL, finished_at IS NOT NULL "
        "FROM runs WHERE run_id = ?",
        [new],
    ).fetchone()
    assert run[:8] == ("/ds", "openai", "m", "r", True, 8, 100, "identity")
    assert json.loads(run[8]) == {
        "replay_of": "src",
        "policy": {
            "threshold": 51,
            "gate_rules": [],
            "gate_min_severity": "HIGH",
            "gate_mode": "any",
            "doc_medium_cap": None,
        },
    }
    assert run[9] and run[10]


def test_policy_rejects_bad_values():
    with pytest.raises(ValueError):
        Policy(gate_mode="sometimes")
    with pytest.raises(ValueError):
        Policy(gate_min_severity="SEVERE")


def test_cli_rejects_unknown_policy_key_and_unknown_run(tmp_path):
    from click.testing import CliRunner

    from benchmark.db import open_db
    from benchmark.replay import main

    path = tmp_path / "db.duckdb"
    con, _, _ = open_db(path, None)
    _src_run(con)
    _add_unit(con, "src", "u", truth=True, score=25, findings=[_f("SSD-1", "HIGH")])
    con.close()

    runner = CliRunner()
    bad_key = runner.invoke(main, [str(path), "src", "--policy", '{"gate_rule": ["SSD-"]}'])
    assert bad_key.exit_code != 0
    assert "gate_rule" in bad_key.output
    unknown = runner.invoke(main, [str(path), "nope", "--policy", "{}"])
    assert unknown.exit_code != 0
    assert "nope" in str(unknown.exception) + unknown.output

    ok = runner.invoke(
        main, [str(path), "src", "--policy", '{"gate_rules": ["SSD-"]}', "--description", "d"]
    )
    assert ok.exit_code == 0, ok.output
    assert "TP=1" in ok.output and "(+1/+0)" in ok.output


@pytest.mark.slow
@pytest.mark.skipif(not SEED_DB.exists(), reason="seed DB not present")
def test_replay_fidelity_on_seed_db(tmp_path):
    """SLOW: copies the ~170 MB seed DB and replays the full 12.7k-unit baseline run."""
    from benchmark.db import open_db

    path = tmp_path / "seed.duckdb"
    shutil.copyfile(SEED_DB, path)
    con, _, _ = open_db(path, None)

    new = replay_run(con, SEED_RUN, Policy(), "fidelity")

    def confusion(run_id):
        return dict(
            con.execute(
                "SELECT outcome, count(*) FROM evaluation WHERE run_id = ? GROUP BY 1", [run_id]
            ).fetchall()
        )

    assert confusion(new) == confusion(SEED_RUN)
    changed = con.execute(
        "SELECT count(*) FROM evaluation a JOIN evaluation b USING (unit_path) "
        "WHERE a.run_id = ? AND b.run_id = ? AND a.outcome <> b.outcome",
        [SEED_RUN, new],
    ).fetchone()[0]
    assert changed == 0
    # Identity replay also reproduces every copied/derived column (status aside).
    cols = (
        "unit_path, classification, is_malicious, risk_score, risk_severity, run_time, "
        "error, num_issues, llm_calls_attempted, llm_calls_succeeded"
    )
    diff = con.execute(
        f"(SELECT {cols} FROM classifications WHERE run_id = $1 EXCEPT ALL "
        f" SELECT {cols} FROM classifications WHERE run_id = $2) UNION ALL "
        f"(SELECT {cols} FROM classifications WHERE run_id = $2 EXCEPT ALL "
        f" SELECT {cols} FROM classifications WHERE run_id = $1)",
        [SEED_RUN, new],
    ).fetchall()
    assert diff == []
    for table in ("units", "issues", "components"):
        n_src, n_new = (
            con.execute(f"SELECT count(*) FROM {table} WHERE run_id = ?", [r]).fetchone()[0]
            for r in (SEED_RUN, new)
        )
        assert n_src == n_new
