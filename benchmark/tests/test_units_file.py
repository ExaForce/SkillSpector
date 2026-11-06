import hashlib
import json
import os
from types import SimpleNamespace

import click
import pytest

from benchmark import main as bm


def _units(*paths):
    return [SimpleNamespace(unit_path=p) for p in paths]


def test_read_units_file_ignores_comments_and_blanks(tmp_path):
    f = tmp_path / "u.txt"
    f.write_text("# header\na\n\n  b  \n# c\na\n")
    assert bm.read_units_file(f) == ["a", "b"]


def test_units_file_reports_missing(capsys):
    units = _units("a", "b", "c")
    selected, missing = bm.select_units(units, ["c", "zzz", "a"])
    assert [u.unit_path for u in selected] == ["c", "a"]
    assert missing == 1
    bm.print_units_file_selection(len(selected), missing)
    assert "1 not found" in capsys.readouterr().out


def test_failures_only_with_units_file_is_usage_error(tmp_path):
    f = tmp_path / "u.txt"
    f.write_text("a\n")
    with pytest.raises(click.UsageError):
        bm._run_benchmark(
            SimpleNamespace(
                dataset_path=None,
                from_run="x",
                failures_only=True,
                units_file=str(f),
                output="o.duckdb",
                run_id=None,
                overwrite=False,
                dataset=None,
            )
        )


# --- resume verification (final-review Important #1, ruling R18) ---------------------------

_LIVE_ENV = {
    "SKILLSPECTOR_BENCH_AUTH_WAIT": "0",
    "SKILLSPECTOR_LOG_LEVEL": "ERROR",
    "SKILLSPECTOR_MODEL": "m1",
    "SKILLSPECTOR_PROVIDER": "openai",
}


def _cfg(env, units_file="absent", git_sha="abc"):
    cfg = {"git_sha": git_sha, "env": env}
    if units_file != "absent":
        cfg["units_file"] = units_file
    return json.dumps(cfg)


def test_resume_mismatches_identical_is_empty():
    uf = {"path": "/x/u.txt", "sha256": "aa"}
    assert bm.resume_config_mismatches(_cfg(_LIVE_ENV, uf), _cfg(_LIVE_ENV, uf)) == []


def test_resume_mismatches_lists_exa_flag_added_removed_changed():
    old = {**_LIVE_ENV, "SKILLSPECTOR_EXA_GONE": "on", "SKILLSPECTOR_EXA_CHG": "any"}
    new = {**_LIVE_ENV, "SKILLSPECTOR_EXA_CHG": "confirmed", "SKILLSPECTOR_EXA_NEW": "1"}
    got = bm.resume_config_mismatches(_cfg(old, None), _cfg(new, None))
    assert len(got) == 3
    assert any("SKILLSPECTOR_EXA_GONE" in m and "on" in m and "unset" in m for m in got)
    assert any("SKILLSPECTOR_EXA_CHG" in m and "any" in m and "confirmed" in m for m in got)
    assert any("SKILLSPECTOR_EXA_NEW" in m and "unset" in m for m in got)


def test_resume_mismatches_pins_model_provider_and_override():
    new = {**_LIVE_ENV, "SKILLSPECTOR_MODEL": "m2", "MODEL_OVERRIDE": "m2"}
    del new["SKILLSPECTOR_PROVIDER"]
    got = bm.resume_config_mismatches(_cfg(_LIVE_ENV, None), _cfg(new, None))
    assert sorted(m.split(":")[0] for m in got) == [
        "MODEL_OVERRIDE",
        "SKILLSPECTOR_MODEL",
        "SKILLSPECTOR_PROVIDER",
    ]


def test_resume_mismatches_ignores_volatile_env_and_git_sha():
    new = {**_LIVE_ENV, "SKILLSPECTOR_BENCH_AUTH_WAIT": "1800", "SKILLSPECTOR_LOG_LEVEL": "DEBUG"}
    new["SKILLSPECTOR_SOMETHING_ELSE"] = "x"
    assert bm.resume_config_mismatches(_cfg(_LIVE_ENV, None), _cfg(new, None, "def")) == []


def test_resume_mismatches_lists_units_file_change():
    a = {"path": "/x/u.txt", "sha256": "aa"}
    for new in ({"path": "/x/u.txt", "sha256": "bb"}, {"path": "/y/u.txt", "sha256": "aa"}, None):
        got = bm.resume_config_mismatches(_cfg(_LIVE_ENV, a), _cfg(_LIVE_ENV, new))
        assert len(got) == 1 and got[0].startswith("units_file"), (new, got)
    # Stored run used no units file; this invocation passes one.
    got = bm.resume_config_mismatches(_cfg(_LIVE_ENV), _cfg(_LIVE_ENV, a))
    assert len(got) == 1 and got[0].startswith("units_file")


def test_resume_mismatches_missing_units_file_key_means_none():
    # Runs recorded before units_file was added (e.g. the live baseline-v2 run) resume cleanly
    # from the same shell env when no --units-file is passed.
    current = {**_LIVE_ENV, "SKILLSPECTOR_BENCH_AUTH_WAIT": "1800"}
    assert bm.resume_config_mismatches(_cfg(_LIVE_ENV), _cfg(current, None)) == []


def test_run_config_json_records_units_file(tmp_path):
    f = tmp_path / "u.txt"
    f.write_bytes(b"a\nb\n")
    env = {"SKILLSPECTOR_EXA_X": "on", "PATH": "/bin"}
    cfg = json.loads(bm.run_config_json(env, "abc", str(f)))
    assert cfg == {
        "git_sha": "abc",
        "env": {"SKILLSPECTOR_EXA_X": "on"},
        "units_file": {
            "path": str(f.resolve()),
            "sha256": hashlib.sha256(b"a\nb\n").hexdigest(),
        },
    }
    assert json.loads(bm.run_config_json(env, "abc", None))["units_file"] is None


def _resume_db(tmp_path, config_json):
    """DB with run 'r1' that has one clean unit 'u1' and one errored unit 'u2'."""
    from benchmark.db import open_db

    path = tmp_path / "r.duckdb"
    con, _, _ = open_db(path, None)
    con.execute("INSERT INTO runs (run_id, config_json) VALUES ('r1', ?)", [config_json])
    for unit, status, pred in (("u1", "LLM", True), ("u2", "Error", None)):
        con.execute(
            "INSERT INTO units (run_id, unit_path, is_malicious) VALUES ('r1', ?, TRUE)", [unit]
        )
        con.execute(
            "INSERT INTO classifications (run_id, unit_path, is_malicious, status) "
            "VALUES ('r1', ?, ?, ?)",
            [unit, pred, status],
        )
    con.close()
    return path


def _resume_args(path, dataset, units=("u1",), units_file=None):
    return SimpleNamespace(
        dataset_path=str(dataset),
        from_run=None,
        failures_only=False,
        units_file=units_file,
        output=str(path),
        run_id="r1",
        overwrite=False,
        dataset=None,
        workers=1,
        categories="skill",
        limit=0,
        description=None,
        no_llm=True,
        timeout=1.0,
        auth_wait_seconds=0,
        max_tasks_per_child=1,
    )


@pytest.fixture
def resume_env(monkeypatch, tmp_path):
    """Stub discovery/config so _run_benchmark reaches the resume check without scanning."""
    for k in [k for k in os.environ if k.startswith("SKILLSPECTOR_") or k == "MODEL_OVERRIDE"]:
        monkeypatch.delenv(k)
    for k, v in _LIVE_ENV.items():
        monkeypatch.setenv(k, v)
    unit = SimpleNamespace(
        unit_path="u1", category="skill", group="g", is_malicious=True, label=None
    )
    monkeypatch.setattr(bm, "discover", lambda root: [unit])
    monkeypatch.setattr(bm, "configure_run", lambda no_llm, timeout: ({}, "", "", ""))
    monkeypatch.setattr(bm, "current_git_sha", lambda: "abc")
    return tmp_path


def _classified(path):
    import duckdb

    con = duckdb.connect(str(path), read_only=True)
    try:
        return sorted(r[0] for r in con.execute("SELECT unit_path FROM classifications").fetchall())
    finally:
        con.close()


def test_resume_refuses_when_exa_flag_differs(resume_env):
    path = _resume_db(resume_env, _cfg({**_LIVE_ENV, "SKILLSPECTOR_EXA_GATE": "any"}, None))
    with pytest.raises(click.UsageError, match=r"SKILLSPECTOR_EXA_GATE.*any.*unset"):
        bm._run_benchmark(_resume_args(path, resume_env))
    # Refused before purge_incomplete: the errored unit's rows are still there.
    assert _classified(path) == ["u1", "u2"]


def test_resume_refuses_when_units_file_differs(resume_env):
    f = resume_env / "u.txt"
    f.write_text("u1\n")
    stored = {"path": str(f.resolve()), "sha256": hashlib.sha256(b"other\n").hexdigest()}
    path = _resume_db(resume_env, _cfg(_LIVE_ENV, stored))
    with pytest.raises(click.UsageError, match="units_file"):
        bm._run_benchmark(_resume_args(path, resume_env, units_file=str(f)))
    # And when the run used a units file but this invocation omits it.
    with pytest.raises(click.UsageError, match="units_file"):
        bm._run_benchmark(_resume_args(path, resume_env))


def test_resume_proceeds_when_config_matches(resume_env, capsys):
    path = _resume_db(resume_env, _cfg({**_LIVE_ENV, "SKILLSPECTOR_BENCH_AUTH_WAIT": "1800"}))
    assert bm._run_benchmark(_resume_args(path, resume_env)) == 0
    out = capsys.readouterr().out
    assert "extending run r1" in out and "nothing to scan" in out
    assert "cannot verify" not in out


def test_resume_without_recorded_config_warns_and_proceeds(resume_env, capsys):
    path = _resume_db(resume_env, None)
    assert bm._run_benchmark(_resume_args(path, resume_env)) == 0
    out = capsys.readouterr().out
    assert "cannot verify" in out and "nothing to scan" in out
