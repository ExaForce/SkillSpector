# SPDX-License-Identifier: Apache-2.0
"""Tests for deterministic evaluation-set construction."""

from __future__ import annotations

import json

from click.testing import CliRunner
from test_db import _fresh_db

from benchmark.evalset import build_core, build_focus, main, write_splits

RUN = "r1"


def _add(con, unit, corpus, malicious, predicted, n_components=1, run=RUN):
    con.execute(
        "INSERT INTO units (run_id, unit_path, corpus, is_malicious) VALUES (?, ?, ?, ?)",
        [run, unit, corpus, malicious],
    )
    con.execute(
        "INSERT INTO classifications (run_id, unit_path, is_malicious, status)"
        " VALUES (?, ?, ?, 'Done')",
        [run, unit, predicted],
    )
    for i in range(n_components):
        con.execute(
            "INSERT INTO components (run_id, unit_path, path) VALUES (?, ?, ?)",
            [run, unit, f"f{i}"],
        )


def _world(tmp_path, n_tn=40):
    con = _fresh_db()
    con.execute("INSERT INTO runs (run_id, dataset_path) VALUES (?, ?)", [RUN, str(tmp_path)])
    (tmp_path / "Skills").mkdir()
    for i in range(5):
        _add(con, f"Skills/mal/m{i}", "malware", True, i % 2 == 0)
    for i in range(3):
        _add(con, f"Skills/b/fp{i}", "benign", False, True, n_components=8)
    for i in range(n_tn):
        _add(
            con,
            f"Skills/b/tn{i:03d}",
            "benign" if i % 2 else "other",
            False,
            False,
            n_components=[1, 3, 10, 30][i % 4],
        )
    labels = tmp_path / "labels.jsonl"
    labels.write_text(
        "\n".join(json.dumps({"unit_path": f"Skills/mal/m{i}"}) for i in (0, 1, 99)) + "\n"
    )
    return con, labels


def test_build_core_is_deterministic(tmp_path):
    con, labels = _world(tmp_path)
    a = build_core(con, RUN, labels, seed=29, n_tn=10)
    b = build_core(con, RUN, labels, seed=29, n_tn=10)
    c = build_core(con, RUN, labels, seed=30, n_tn=10)
    assert a == b == sorted(set(a))
    assert a != c


def test_build_core_includes_all_fps_and_annotated(tmp_path):
    con, labels = _world(tmp_path)
    core = build_core(con, RUN, labels, n_tn=10)
    assert {"Skills/mal/m0", "Skills/mal/m1"} <= set(core)  # annotated; m99 not in run
    assert "Skills/mal/m99" not in core
    assert {f"Skills/b/fp{i}" for i in range(3)} <= set(core)
    tns = [u for u in core if u.startswith("Skills/b/tn")]
    assert len(tns) == 10
    assert len(core) == 2 + 3 + 10


def test_build_core_tn_stratified_and_capped(tmp_path):
    con, labels = _world(tmp_path)
    # asking for more TNs than exist returns every TN once
    core = build_core(con, RUN, labels, n_tn=1000)
    assert len([u for u in core if u.startswith("Skills/b/tn")]) == 40
    # every (corpus, size) stratum is represented in a proportional sample
    core = build_core(con, RUN, labels, n_tn=20)
    got = [u for u in core if u.startswith("Skills/b/tn")]
    assert len(got) == 20
    sizes = {int(u[-3:]) % 4 for u in got}
    assert sizes == {0, 1, 2, 3}


def test_build_focus_sql_and_cap(tmp_path):
    con, _ = _world(tmp_path)
    bf = tmp_path / "Skills" / "_boundary_features.jsonl"
    bf.write_text(
        "\n".join(
            json.dumps({"unit_path": f"Skills/mal/m{i}", "attack_vector": "CI" if i < 3 else "X"})
            for i in range(5)
        )
        + "\n"
    )
    ci = build_focus(con, RUN, "bf.attack_vector = 'CI'", None)
    assert ci == ["Skills/mal/m0", "Skills/mal/m1", "Skills/mal/m2"]
    # benign units have NULL bf columns
    mixed = build_focus(con, RUN, "bf.attack_vector = 'CI' OR e.outcome = 'FP'", None)
    assert len(mixed) == 6
    capped = build_focus(con, RUN, "bf.attack_vector IS NOT NULL OR e.corpus = 'other'", 7)
    assert len(capped) == 7
    assert {f"Skills/mal/m{i}" for i in range(5)} <= set(capped)  # malicious kept first
    assert capped == build_focus(con, RUN, "bf.attack_vector IS NOT NULL OR e.corpus = 'other'", 7)
    tiny = build_focus(con, RUN, "bf.attack_vector IS NOT NULL", 2)
    assert len(tiny) == 2 and set(tiny) <= {f"Skills/mal/m{i}" for i in range(5)}


def test_write_splits_marks_holdout(tmp_path):
    out = tmp_path / "s.tsv"
    write_splits(["b", "a", "c", "d"], [["a"], ["c", "zz"]], out)
    assert out.read_text() == "a\tdev\nb\tholdout\nc\tdev\nd\tholdout\n"


def test_cli_core_and_splits(tmp_path):
    import duckdb

    con, labels = _world(tmp_path)
    (tmp_path / "Skills" / "_boundary_labels.jsonl").write_text(labels.read_text())
    db = tmp_path / "x.duckdb"
    # build an on-disk db the simple way: copy schema + rows
    from benchmark.db import _EVAL_VIEW, _SCHEMA

    disk = duckdb.connect(str(db))
    disk.execute(_SCHEMA)
    disk.execute(_EVAL_VIEW)
    for t in ("runs", "units", "classifications", "components"):
        cols = [r[0] for r in con.execute(f"DESCRIBE {t}").fetchall()]
        for row in con.execute(f"SELECT * FROM {t}").fetchall():
            disk.execute(
                f"INSERT INTO {t} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                list(row),
            )
    disk.close()
    core = tmp_path / "core.txt"
    res = CliRunner().invoke(main, ["core", str(core), "--db", str(db), "--run", RUN])
    assert res.exit_code == 0, res.output
    units = core.read_text().split()
    assert "Skills/b/fp0" in units
    splits = tmp_path / "splits.tsv"
    res = CliRunner().invoke(
        main, ["splits", str(splits), "--db", str(db), "--run", RUN, str(core)]
    )
    assert res.exit_code == 0, res.output
    lines = splits.read_text().splitlines()
    assert "Skills/b/fp0\tdev" in lines
    assert any(line.endswith("\tholdout") for line in lines)
