# SPDX-License-Identifier: Apache-2.0
"""Tests for same-day arm comparison and its pre-registered verdicts."""

from __future__ import annotations

import json

import pytest
from test_db import _fresh_db

from benchmark.arms import compare_arms, render_markdown

N_MAL, N_BEN = 130, 20


def _run(con, run_id, tp, fp, *, units=None, dataset=None, llm_calls=None):
    """Run with ``tp`` of N_MAL malicious detected and ``fp`` of N_BEN benign flagged."""
    con.execute(
        "INSERT INTO runs (run_id, use_llm, dataset_path) VALUES (?, FALSE, ?)",
        [run_id, str(dataset) if dataset else None],
    )
    for i in range(N_MAL):
        _unit(con, run_id, f"m{i}", True, i < tp)
    for i in range(N_BEN):
        _unit(con, run_id, f"b{i}", False, i < fp)
    for extra in units or []:
        _unit(con, run_id, extra, False, False)


def _unit(con, run_id, path, truth, pred):
    con.execute(
        "INSERT INTO units (run_id, unit_path, is_malicious) VALUES (?, ?, ?)",
        [run_id, path, truth],
    )
    con.execute(
        "INSERT INTO classifications (run_id, unit_path, is_malicious, status)"
        " VALUES (?, ?, ?, 'Completed')",
        [run_id, path, pred],
    )


def test_arms_promising():
    con = _fresh_db()
    for rid, tp in (("c1", 100), ("c2", 102), ("t1", 112), ("t2", 114)):
        _run(con, rid, tp, 5)
    r = compare_arms(con, ["c1", "c2"], ["t1", "t2"])
    assert r.verdict == "PROMISING", r.reasons
    assert r.n_tp == 3 and r.d_tp == 12 and r.n_fp == 2 and r.d_fp == 0
    assert r.replicates == (2, 2)


def test_arms_reject_on_fp_cost():
    con = _fresh_db()
    for rid, tp, fp in (("c1", 100, 2), ("c2", 102, 2), ("t1", 112, 7), ("t2", 114, 7)):
        _run(con, rid, tp, fp)
    r = compare_arms(con, ["c1", "c2"], ["t1", "t2"])
    assert r.verdict == "REJECT" and r.d_fp == 5
    assert any("8:1" in x for x in r.reasons)


def test_arms_single_replicate():
    con = _fresh_db()
    _run(con, "c1", 100, 5)
    _run(con, "t1", 110, 5)
    r = compare_arms(con, ["c1"], ["t1"])
    assert (r.n_tp, r.n_fp) == (3, 2) and r.replicates == (1, 1)
    assert r.verdict == "PROMISING"
    assert "1 replicate" in render_markdown(r)
    assert any("1 replicate" in x for x in r.reasons)


def test_arms_noise_floor_uses_range_of_control():
    con = _fresh_db()
    for rid, tp in (("c1", 100), ("c2", 110), ("c3", 105), ("t1", 120)):
        _run(con, rid, tp, 5)
    r = compare_arms(con, ["c1", "c2", "c3"], ["t1"])
    assert r.n_tp == 10 and r.d_tp == 15  # 15 < 2*10 -> REJECT
    assert r.verdict == "REJECT"


def test_arms_fp_boundary_allows_tp_over_eight():
    con = _fresh_db()
    # d_tp=24 -> allowed d_fp = max(2, 3) = 3
    for rid, tp, fp in (("c1", 100, 2), ("c2", 100, 2), ("t1", 124, 5)):
        _run(con, rid, tp, fp)
    r = compare_arms(con, ["c1", "c2"], ["t1"])
    assert r.d_fp == 3 and r.verdict == "PROMISING", r.reasons


def test_arms_rejects_unhealthy_treatment():
    con = _fresh_db()
    for rid, tp in (("c1", 100), ("c2", 102), ("t1", 112)):
        _run(con, rid, tp, 5)
    con.execute("UPDATE classifications SET status = 'Error' WHERE run_id = 't1'")
    r = compare_arms(con, ["c1", "c2"], ["t1"])
    assert r.verdict == "REJECT"
    assert any("health" in x for x in r.reasons)


def test_arms_rejects_mismatched_units():
    con = _fresh_db()
    _run(con, "c1", 100, 5)
    _run(con, "t1", 112, 5, units=["extra1", "extra2"])
    with pytest.raises(SystemExit) as e:
        compare_arms(con, ["c1"], ["t1"])
    msg = str(e.value)
    assert "c1" in msg and "t1" in msg and "2" in msg


def test_arms_unknown_run():
    con = _fresh_db()
    _run(con, "c1", 100, 5)
    with pytest.raises(SystemExit, match="nope"):
        compare_arms(con, ["c1"], ["nope"])


def _labels(tmp_path):
    skills = tmp_path / "Skills"
    skills.mkdir()
    # Injected payload file per malicious unit m0..m99.
    (skills / "_skillharm_injected.jsonl").write_text(
        "".join(json.dumps({"unit_path": f"m{i}", "files": ["evil.py"]}) + "\n" for i in range(100))
    )
    (skills / "_external_labels.jsonl").write_text(
        json.dumps({"unit": "m0", "source_dataset": "SkillTrustBench"}) + "\n"
    )
    (skills / "_boundary_labels.jsonl").write_text(
        json.dumps({"unit_path": "m0", "label_validity": "CORRECT"}) + "\n"
    )
    return tmp_path


def _attribute(con, run_id, n):
    for i in range(n):
        con.execute(
            "INSERT INTO issues (run_id, unit_path, issue_index, severity, file)"
            " VALUES (?, ?, 0, 'HIGH', 'evil.py')",
            [run_id, f"m{i}"],
        )


def test_arms_fp_kind_with_attributed_recall(tmp_path):
    ds = _labels(tmp_path)
    con = _fresh_db()
    _run(con, "c1", 100, 10, dataset=ds)
    _run(con, "c2", 100, 10, dataset=ds)
    _run(con, "t1", 99, 5, dataset=ds)
    _attribute(con, "c1", 90)
    _attribute(con, "c2", 90)
    _attribute(con, "t1", 90)
    r = compare_arms(con, ["c1", "c2"], ["t1"], kind="fp")
    assert r.d_fp == -5 and r.d_tp == -1
    assert r.attributed_recall == (0.9, 0.9)
    assert r.verdict == "PROMISING", r.reasons
    # Attributed recall drops -> REJECT
    con.execute("DELETE FROM issues WHERE run_id = 't1' AND unit_path = 'm0'")
    r = compare_arms(con, ["c1", "c2"], ["t1"], kind="fp")
    assert r.verdict == "REJECT" and any("attributed" in x for x in r.reasons)


def test_arms_fp_kind_rejects_when_attributed_unavailable():
    con = _fresh_db()
    _run(con, "c1", 100, 10)
    _run(con, "c2", 100, 10)
    _run(con, "t1", 100, 5)
    r = compare_arms(con, ["c1", "c2"], ["t1"], kind="fp")
    assert r.verdict == "REJECT"
    assert any("attributed recall is unavailable" in x for x in r.reasons)
    assert r.attributed_recall == (None, None)


def test_arms_recall_kind_attributed_na_does_not_block():
    con = _fresh_db()
    for rid, tp in (("c1", 100), ("c2", 102), ("t1", 112), ("t2", 114)):
        _run(con, rid, tp, 5)
    r = compare_arms(con, ["c1", "c2"], ["t1", "t2"])
    assert r.verdict == "PROMISING"
    assert "n/a" in render_markdown(r)


def test_arms_fp_kind_tp_cost_rejects():
    con = _fresh_db()
    _run(con, "c1", 100, 10)
    _run(con, "c2", 100, 10)
    _run(con, "t1", 90, 5)
    r = compare_arms(con, ["c1", "c2"], ["t1"], kind="fp")
    assert r.verdict == "REJECT" and any("TP" in x for x in r.reasons)


def _provenance(con, run_id, *, sha="abc1234", env=None, started="2026-11-02 09:00:00"):
    cfg = None if env is None else json.dumps({"git_sha": sha, "env": env})
    con.execute(
        "UPDATE runs SET config_json = ?, started_at = CAST(? AS TIMESTAMP) WHERE run_id = ?",
        [cfg, started, run_id],
    )


def test_arms_shows_run_provenance():
    con = _fresh_db()
    for rid, tp in (("c1", 100), ("c2", 102), ("t1", 112), ("t2", 114)):
        _run(con, rid, tp, 5)
    base = {"SKILLSPECTOR_MODEL": "m", "SKILLSPECTOR_EXA_KEEP": "1"}
    _provenance(con, "c1", env=base)
    _provenance(con, "c2", sha="def5678", env=base, started="2026-11-02 18:00:00")
    _provenance(con, "t1", env={**base, "SKILLSPECTOR_EXA_GATE": "any"})
    _provenance(con, "t2", env=None)  # recorded before config_json existed
    r = compare_arms(con, ["c1", "c2"], ["t1", "t2"])
    md = render_markdown(r)
    rows = {line.split("|")[2].strip(): line for line in md.splitlines() if line.startswith("| ")}
    assert "abc1234" in rows["c1"] and "SKILLSPECTOR_EXA_KEEP='1'" in rows["c1"]
    assert "def5678" in rows["c2"] and "same as c1" in rows["c2"]
    assert "SKILLSPECTOR_EXA_GATE: (unset) -> 'any'" in rows["t1"]
    assert "SKILLSPECTOR_MODEL" not in rows["t1"]  # only EXA flags are shown
    assert rows["t2"].count("unrecorded") == 2
    assert "different dates" not in md
    assert r.verdict == "PROMISING"  # display only


def test_arms_warns_on_different_start_dates():
    con = _fresh_db()
    for rid, tp in (("c1", 100), ("c2", 102), ("t1", 112)):
        _run(con, rid, tp, 5)
    _provenance(con, "c1", env={})
    _provenance(con, "c2", env={}, started="2026-11-01 23:00:00")
    _provenance(con, "t1", env={})
    r = compare_arms(con, ["c1", "c2"], ["t1"])
    md = render_markdown(r)
    assert "WARNING" in md and "different dates" in md
    assert "2026-11-01" in md and "2026-11-02" in md
    assert r.verdict == "PROMISING"
