# SPDX-License-Identifier: Apache-2.0
"""Tests for the sequential futility screen (``uv run screen``).

Scans never run the real ``benchmark`` command: ``screen.BENCHMARK_CMD`` is replaced by a
small fake that writes rows into the temp DuckDB and prints the lines the real one prints.
"""

from __future__ import annotations

import json
import math
import os
import sys
import textwrap
import time
from collections import Counter
from datetime import datetime

import duckdb
import pytest
from click.testing import CliRunner
from test_db import _fresh_db

from benchmark import screen
from benchmark.db import _EVAL_VIEW, _SCHEMA
from benchmark.screen import (
    build_batches,
    judge,
    main,
    render_table,
    simulate,
    strata_for,
    unit_outcomes,
)

MAL = [f"Skills/malware/m{i:02d}" for i in range(15)]
BEN = [f"Skills/benign/b{i:02d}" for i in range(15)]
UNITS = MAL + BEN

# control: detects m00-m09, misses m10-m14, flags b00
CONTROL = {u: (True, i < 10) for i, u in enumerate(MAL)} | {
    u: (False, i == 0) for i, u in enumerate(BEN)
}
# positive treatment: detects every malicious unit, same single FP
POSITIVE = dict.fromkeys(MAL, (True, True)) | {u: (False, i == 0) for i, u in enumerate(BEN)}
# futile treatment: same TPs as control, flags every benign unit
FUTILE = {u: (True, i < 10) for i, u in enumerate(MAL)} | dict.fromkeys(BEN, (False, True))


def _insert_run(con, run_id, outcomes, *, started=None, sha="fake", behavior="exfil"):
    """One run; ``outcomes`` maps unit -> (truth, pred), pred None meaning an ERROR scan."""
    con.execute(
        "INSERT INTO runs (run_id, started_at, use_llm, config_json) VALUES (?, ?, TRUE, ?)",
        [run_id, started or datetime.now(), json.dumps({"git_sha": sha, "env": {}})],
    )
    for u, (truth, pred) in outcomes.items():
        con.execute(
            "INSERT INTO units (run_id, unit_path, is_malicious, behavior) VALUES (?, ?, ?, ?)",
            [run_id, u, truth, behavior if truth else None],
        )
        con.execute(
            "INSERT INTO classifications (run_id, unit_path, is_malicious, status)"
            " VALUES (?, ?, ?, ?)",
            [run_id, u, pred, "Error" if pred is None else "Completed"],
        )


FAKE_BENCHMARK = textwrap.dedent(
    """
    import argparse, json, os, pathlib, subprocess, sys, time
    from datetime import datetime

    p = argparse.ArgumentParser()
    p.add_argument("dataset")
    p.add_argument("-o")
    p.add_argument("--units-file")
    p.add_argument("--auth-wait-seconds")
    p.add_argument("--description")
    p.add_argument("--run-id")
    a = p.parse_args()
    plan = json.loads(pathlib.Path(os.environ["FAKE_BENCH_PLAN"]).read_text())
    record = pathlib.Path(plan["record"])
    n_calls = len(record.read_text().splitlines()) if record.exists() else 0
    arm, bk = a.description.split()[-2:]
    rid = a.run_id or f"{arm}-{bk}"
    manifest = pathlib.Path(a.units_file).parent / "manifest.json"
    entry = {
        "argv": sys.argv[1:],
        "exa": {k: v for k, v in os.environ.items() if k.startswith("SKILLSPECTOR_EXA_")},
        "looks": len(json.loads(manifest.read_text())["looks"]) if manifest.exists() else None,
    }
    if a.run_id is None:
        print(f"starting run {rid}")
    if n_calls < plan.get("stall", 0):
        entry["child"] = subprocess.Popen(["sleep", "60"]).pid
        with record.open("a") as f:
            f.write(json.dumps(entry) + "\\n")
        time.sleep(60)
    with record.open("a") as f:
        f.write(json.dumps(entry) + "\\n")
    import duckdb  # after the stall point: under load its import can outlast --stall-seconds

    units = [x.strip() for x in open(a.units_file) if x.strip()]
    con = duckdb.connect(a.o)
    if not con.execute("SELECT 1 FROM runs WHERE run_id = ?", [rid]).fetchone():
        con.execute(
            "INSERT INTO runs (run_id, started_at, config_json) VALUES (?, ?, ?)",
            [rid, datetime.now(), json.dumps({"git_sha": "fake", "env": entry["exa"]})],
        )
    for u in units:
        truth, pred = plan["outcomes"][arm][u]
        con.execute(
            "INSERT INTO units (run_id, unit_path, is_malicious) VALUES (?, ?, ?)",
            [rid, u, truth],
        )
        con.execute(
            "INSERT INTO classifications (run_id, unit_path, is_malicious, status)"
            " VALUES (?, ?, ?, ?)",
            [rid, u, pred, "Error" if pred is None else "Completed"],
        )
    con.close()
    print(f"wrote {a.o} (run id {rid})")
    """
)


class Bench:
    """A temp DB holding a reference run, a units file, and the fake ``benchmark`` command."""

    def __init__(self, tmp_path, monkeypatch):
        self.tmp = tmp_path
        self.dataset = tmp_path / "Dataset"
        self.dataset.mkdir()
        self.db = tmp_path / "bench.duckdb"
        con = duckdb.connect(str(self.db))
        con.execute(_SCHEMA)
        con.execute(_EVAL_VIEW)
        _insert_run(con, "ref", CONTROL)
        con.close()
        self.units_file = tmp_path / "units.txt"
        self.units_file.write_text("\n".join(UNITS) + "\n")
        self.out = tmp_path / "screens"
        self.record = tmp_path / "calls.jsonl"
        self.plan_path = tmp_path / "plan.json"
        fake = tmp_path / "fake_benchmark.py"
        fake.write_text(FAKE_BENCHMARK)
        monkeypatch.setattr(screen, "BENCHMARK_CMD", [sys.executable, str(fake)])
        monkeypatch.setenv("FAKE_BENCH_PLAN", str(self.plan_path))
        for k in [k for k in os.environ if k.startswith("SKILLSPECTOR_EXA_")]:
            monkeypatch.delenv(k)
        self.plan(CONTROL, POSITIVE)

    def plan(self, control, treatment, stall=0):
        self.plan_path.write_text(
            json.dumps(
                {
                    "record": str(self.record),
                    "stall": stall,
                    "outcomes": {"control": control, "treatment": treatment},
                }
            )
        )

    def add_runs(self, *runs):
        con = duckdb.connect(str(self.db))
        for run_id, outcomes, kw in runs:
            _insert_run(con, run_id, outcomes, **kw)
        con.close()

    def invoke(self, *args, label="t"):
        base = [str(self.dataset), "--db", str(self.db), "--units-file", str(self.units_file)]
        base += ["--ref-run", "ref", "--label", label, "--batch-size", "10"]
        base += ["--out-dir", str(self.out)]
        return CliRunner().invoke(main, [*base, *args])

    def calls(self):
        if not self.record.exists():
            return []
        return [json.loads(x) for x in self.record.read_text().splitlines()]

    def manifest(self, label="t"):
        return json.loads((self.out / label / "manifest.json").read_text())


@pytest.fixture
def bench(tmp_path, monkeypatch):
    return Bench(tmp_path, monkeypatch)


# --- pure parts -------------------------------------------------------------------------------


def test_build_batches_deterministic_and_proportional():
    sizes = {"benign": 400, "exfil": 333, "persist": 200, "unknown": 67}
    units, strata = [], {}
    for key, n in sizes.items():
        for i in range(n):
            u = f"{key}/{i:04d}"
            units.append(u)
            strata[u] = key
    batches = build_batches(units, strata)
    assert len(batches) == math.ceil(1000 / 150) == 7
    assert batches == build_batches(list(reversed(units)), strata, seed=29)
    assert batches != build_batches(units, strata, seed=30)
    flat = [u for b in batches for u in b]
    assert len(flat) == len(set(flat)) == 1000
    assert all(len(b) <= 150 for b in batches)
    for key in sizes:
        counts = [sum(strata[u] == key for u in b) for b in batches]
        assert max(counts) - min(counts) <= 1, (key, counts)
    # a unit missing from the strata map lands in 'unknown'
    assert sorted(u for b in build_batches(["x", "y"], {}) for u in b) == ["x", "y"]


def test_strata_benign_behavior_corpus_unknown():
    con = _fresh_db()
    rows = [
        ("ref", "b", False, "exfil", "c0"),
        ("ref", "m1", True, "exfil", "c1"),
        ("ref", "m2", True, None, "c2"),
        ("ref", "m3", True, None, None),
        ("other", "zz", True, "persist", "c9"),
    ]
    for run_id, u, mal, behavior, corpus in rows:
        con.execute(
            "INSERT INTO units (run_id, unit_path, is_malicious, behavior, corpus)"
            " VALUES (?, ?, ?, ?, ?)",
            [run_id, u, mal, behavior, corpus],
        )
        con.execute(
            "INSERT INTO classifications (run_id, unit_path, is_malicious, status)"
            " VALUES (?, ?, FALSE, 'Completed')",
            [run_id, u],
        )
    got = strata_for(con, "ref", ["b", "m1", "m2", "m3", "zz"])
    assert got == {"b": "benign", "m1": "exfil", "m2": "c2", "m3": "unknown", "zz": "unknown"}


def test_unit_outcomes_means_and_errors():
    con = _fresh_db()
    _insert_run(con, "r1", {"m": (True, True), "b": (False, True), "e": (False, False)})
    _insert_run(con, "r2", {"m": (True, False), "b": (False, True), "e": (False, None)})
    got = unit_outcomes(con, ["r1", "r2"], ["m", "b", "e", "absent"])
    assert got == {"m": (0.5, 0.0, False), "b": (0.0, 1.0, False), "e": (0.0, 0.0, True)}


# Hand-computed 6-unit example. Units u1-u5 are benign and gain an FP; u6 is a steady TP.
#   recall: d = [-8]*5 + [0] -> D = -40, mean = -20/3,
#           sum sq dev = 5*(4/3)^2 + (20/3)^2 = 80/9 + 400/9 = 480/9,
#           var = (480/9)/5 = 32/3, SE = sqrt(32/3 * 6) = sqrt(64) = 8,
#           D + 2.8*SE = -17.6, allowance = 16*6/6 = 16 -> -17.6 < -16 -> stop (batch >= 3).
#   fp:     d = 2*dTP - dFP = [-1]*5 + [0] -> D = -5, mean = -5/6,
#           sum sq dev = 5*(1/6)^2 + (5/6)^2 = 5/6, var = 1/6, SE = sqrt(1/6 * 6) = 1,
#           D + 2.8*SE = -2.2 < 0 (allowance 0) -> stop.
_C6 = {f"u{i}": (0.0, 0.0, False) for i in range(1, 6)} | {"u6": (1.0, 0.0, False)}
_T6 = {f"u{i}": (0.0, 1.0, False) for i in range(1, 6)} | {"u6": (1.0, 0.0, False)}
_U6 = [f"u{i}" for i in range(1, 7)]


def test_judge_formula():
    look = judge(_C6, _T6, _U6, 6, batch=3)
    assert (look.n, look.n_errors, look.d_tp, look.d_fp) == (6, 0, 0, 5)
    assert look.D == -40
    assert look.se == pytest.approx(8.0)
    assert look.ucb == pytest.approx(-17.6)
    assert look.allowance == pytest.approx(16.0)
    assert look.stop is True
    assert judge(_C6, _T6, _U6, 6, batch=2).stop is False  # fewer than min_batches
    # allowance scales with n/N: 16*6/600
    assert judge(_C6, _T6, _U6, 600, batch=3).allowance == pytest.approx(0.16)
    # a wider z clears the allowance: -40 + 3.1*8 = -15.2, not < -16
    assert judge(_C6, _T6, _U6, 6, z=3.1, batch=3).stop is False

    fp = judge(_C6, _T6, _U6, 6, batch=3, kind="fp")
    assert fp.D == -5
    assert fp.se == pytest.approx(1.0)
    assert fp.ucb == pytest.approx(-2.2)
    assert fp.allowance == 0
    assert fp.stop is True

    # mixed example: recall d = [1, 1, 0, -8, 0, -1]; fp-kind d = [2, 2, 0, -1, 0, -2]
    c = {"a": (0, 0, False), "b": (0, 0, False), "c": (1, 0, False)}
    c |= {"d": (0, 0, False), "e": (0, 0, False), "f": (1, 0, False)}
    t = {"a": (1, 0, False), "b": (1, 0, False), "c": (1, 0, False)}
    t |= {"d": (0, 1, False), "e": (0, 0, False), "f": (0, 0, False)}
    mixed = judge(c, t, list("abcdef"), 600, batch=5)
    assert mixed.D == -7
    assert mixed.se == pytest.approx(math.sqrt(70.6))  # var = (67 - 49/6)/5 = 11.7667; *6
    assert mixed.stop is False
    mixed_fp = judge(c, t, list("abcdef"), 600, batch=5, kind="fp")
    assert mixed_fp.D == 1
    assert mixed_fp.se == pytest.approx(math.sqrt(15.4))  # var = (13 - 1/6)/5; *6
    assert mixed_fp.stop is False


def test_judge_single_unit_has_zero_se():
    look = judge({"a": (0, 0, False)}, {"a": (0, 1, False)}, ["a"], 10, batch=3)
    assert (look.n, look.D, look.se) == (1, -8, 0.0)


def test_judge_excludes_errors():
    c = dict(_C6) | {"e1": (0.0, 0.0, True), "e2": (1.0, 0.0, False)}
    t = dict(_T6) | {"e1": (0.0, 1.0, False), "e2": (0.0, 0.0, True)}
    units = [*_U6, "e1", "e2"]
    look = judge(c, t, units, 8, batch=3)
    assert (look.n, look.n_errors) == (6, 2)
    assert look.D == -40 and look.d_fp == 5 and look.d_tp == 0
    assert look.se == pytest.approx(8.0)
    assert look.allowance == pytest.approx(16 * 6 / 8)
    table = render_table([look], [8])
    assert "| 3 | 8 | 6 | 2 |" in table


def test_never_stops_on_positive():
    for kind in ("recall", "fp"):
        for n in (1, 2, 5, 30, 300):
            units = [f"u{i}" for i in range(n)]
            c = dict.fromkeys(units, (0.0, 0.0, False))
            t = dict.fromkeys(units, (1.0, 0.0, False))
            for batch in range(1, 20):
                look = judge(c, t, units, n, z=0.0, batch=batch, min_batches=1, kind=kind)
                assert look.D > 0 and look.stop is False
        # one huge gain, many zeros: big SE, still positive
        units = [f"u{i}" for i in range(50)]
        c = dict.fromkeys(units, (0.0, 0.0, False))
        t = dict(c) | {"u0": (1.0, 0.0, False)}
        assert judge(c, t, units, 50, batch=10, min_batches=1, kind=kind).stop is False
        # no change at all is not futile either
        assert judge(c, c, units, 50, batch=10, kind=kind).stop is False


def test_stops_on_clear_futility_after_min_batches(bench):
    bench.add_runs(("C", CONTROL, {}), ("T", FUTILE, {}))
    con = duckdb.connect(str(bench.db), read_only=True)
    batches = build_batches(UNITS, strata_for(con, "ref", UNITS), batch_size=10)
    looks = simulate(con, batches, ["C"], ["T"], len(UNITS))
    con.close()
    assert [x.batch for x in looks] == [1, 2, 3]
    assert [x.stop for x in looks] == [False, False, True]
    # batch 2 is already past the boundary; only the minimum-batch rule holds it
    assert looks[1].ucb < -looks[1].allowance

    r = bench.invoke("--simulate", "--control-runs", "C", "--treatment-runs", "T")
    assert r.exit_code == 0, r.output
    assert "SCREEN: FUTILE at batch 3 (30 units)" in r.output
    assert not bench.calls()


# --- orchestration ----------------------------------------------------------------------------


def test_control_runs_must_cover_batch(bench):
    partial = {u: o for u, o in CONTROL.items() if u not in MAL[:5]}
    bench.add_runs(("C", partial, {}), ("T", POSITIVE, {}))
    r = bench.invoke("--control-runs", "C")
    assert r.exit_code != 0
    assert "5 of 30" in r.output and "C" in r.output
    assert not bench.calls()  # refused before any scan

    r = bench.invoke("--simulate", "--control-runs", "C", "--treatment-runs", "T")
    assert r.exit_code != 0 and "5 of 30" in r.output

    r = bench.invoke("--simulate", "--control-runs", "T", "--treatment-runs", "C")
    assert r.exit_code != 0 and "5 of 30" in r.output

    # full coverage from another day and sha: warned, not refused
    bench.add_runs(("OLD", CONTROL, {"started": datetime(2026, 1, 1), "sha": "old"}))
    r = bench.invoke("--control-runs", "OLD", label="old")
    assert r.exit_code == 0, r.output
    warnings = [x for x in r.output.splitlines() if x.startswith("WARNING")]
    assert any("2026-01-01" in w for w in warnings), r.output
    assert any("old" in w and "fake" in w for w in warnings), r.output
    arms = [c for c in bench.calls() if "--description" in c["argv"]]
    descs = [c["argv"][c["argv"].index("--description") + 1] for c in arms]
    assert descs == ["old treatment b1", "old treatment b2", "old treatment b3"]
    assert r.output.rstrip().splitlines()[-1] == (
        "arms: --control OLD --treatment treatment-b1+treatment-b2+treatment-b3"
    )


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_stall_kills_and_resumes(bench):
    bench.units_file.write_text("\n".join(UNITS[:5]) + "\n")
    bench.plan(CONTROL, POSITIVE, stall=1)
    r = bench.invoke("--stall-seconds", "1")
    assert r.exit_code == 0, r.output
    calls = bench.calls()
    assert len(calls) == 3  # control (stalled), control (resumed), treatment
    assert "--run-id" not in calls[0]["argv"]
    argv = calls[1]["argv"]
    assert argv[argv.index("--run-id") + 1] == "control-b1"
    assert (
        argv[argv.index("--units-file") + 1]
        == calls[0]["argv"][calls[0]["argv"].index("--units-file") + 1]
    )
    # the whole process group died, not just the direct child
    deadline = time.monotonic() + 3
    while _alive(calls[0]["child"]) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _alive(calls[0]["child"])
    assert bench.manifest()["batches"][0]["control"] == ["control-b1"]


def test_stall_gives_up_after_two_retries(bench):
    bench.units_file.write_text("\n".join(UNITS[:5]) + "\n")
    bench.plan(CONTROL, POSITIVE, stall=99)
    r = bench.invoke("--stall-seconds", "1")
    assert r.exit_code != 0
    assert len(bench.calls()) == 3  # first try + 2 resumes
    assert "control-b1" in r.output and "stalled" in r.output
    for c in bench.calls():
        deadline = time.monotonic() + 3
        while _alive(c["child"]) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _alive(c["child"])


def test_manifest_written_each_batch(bench):
    r = bench.invoke("--treatment-env", "SKILLSPECTOR_EXA_FOO=1")
    assert r.exit_code == 0, r.output
    calls = bench.calls()
    descs = [c["argv"][c["argv"].index("--description") + 1] for c in calls]
    assert descs == [f"t {arm} b{k}" for k in (1, 2, 3) for arm in ("control", "treatment")]
    # each scan saw the manifest with one look per finished batch
    assert [c["looks"] for c in calls] == [0, 0, 1, 1, 2, 2]
    assert [c["exa"] for c in calls] == [{}, {"SKILLSPECTOR_EXA_FOO": "1"}] * 3
    m = bench.manifest()
    assert [b["control"] for b in m["batches"]] == [[f"control-b{k}"] for k in (1, 2, 3)]
    assert [b["treatment"] for b in m["batches"]] == [f"treatment-b{k}" for k in (1, 2, 3)]
    assert sorted(u for b in m["batches"] for u in b["units"]) == sorted(UNITS)
    assert len(m["looks"]) == 3 and m["result"] == "PASSED"
    assert all((bench.out / "t" / b["file"]).exists() for b in m["batches"])
    assert (bench.out / "t" / "b01-control.log").exists()
    lines = r.output.rstrip().splitlines()
    assert lines[-2] == "SCREEN: PASSED (30 units)"
    assert lines[-1] == (
        "arms: --control control-b1+control-b2+control-b3"
        " --treatment treatment-b1+treatment-b2+treatment-b3"
    )
    # a second screen under the same label would clobber this record
    assert bench.invoke().exit_code != 0


def test_futile_screen_stops_scanning(bench):
    bench.plan(CONTROL, FUTILE)
    r = bench.invoke()
    assert r.exit_code == 0, r.output
    assert r.output.rstrip().splitlines()[-1] == "SCREEN: FUTILE at batch 3 (30 units)"
    assert "arms:" not in r.output
    assert bench.manifest()["result"] == "FUTILE"

    # with more batches than the stop point, later batches are never scanned
    bench.units_file.write_text("\n".join(UNITS) + "\n")
    r = bench.invoke("--batch-size", "6", label="small")
    assert r.exit_code == 0, r.output
    m = bench.manifest("small")
    stop = len(m["looks"])
    assert stop < len(m["batches"])
    assert m["looks"][-1]["stop"] is True
    descs = [c["argv"][c["argv"].index("--description") + 1] for c in bench.calls()]
    assert sum(d.startswith("small ") for d in descs) == 2 * stop


def test_simulate_matches_full_runs(bench):
    mixed = dict(POSITIVE) | {BEN[3]: (False, True), MAL[2]: (True, None), BEN[7]: (False, None)}
    bench.plan(CONTROL, mixed)
    r = bench.invoke()
    assert r.exit_code == 0, r.output
    m = bench.manifest()
    assert any(x["n_errors"] for x in m["looks"])

    bench.add_runs(("C", CONTROL, {}), ("T", mixed, {}))
    con = duckdb.connect(str(bench.db), read_only=True)
    batches = [b["units"] for b in m["batches"]]
    looks = simulate(con, batches, ["C"], ["T"], len(UNITS))
    con.close()
    assert [vars(x) for x in looks] == m["looks"]

    s = bench.invoke("--simulate", "--control-runs", "C", "--treatment-runs", "T")
    assert s.exit_code == 0, s.output
    table = render_table(looks, [10, 20, 30])
    assert table in s.output and table in r.output
    assert "SCREEN: PASSED (30 units)" in s.output


def test_batches_follow_ref_run_strata(bench):
    con = duckdb.connect(str(bench.db), read_only=True)
    strata = strata_for(con, "ref", UNITS)
    con.close()
    assert Counter(strata.values()) == {"benign": 15, "exfil": 15}
    for b in build_batches(UNITS, strata, batch_size=10):
        assert Counter(strata[u] for u in b) == {"benign": 5, "exfil": 5}
