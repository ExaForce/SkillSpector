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
