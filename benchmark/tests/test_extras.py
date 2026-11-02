# SPDX-License-Identifier: Apache-2.0
"""Tests for the report extras: health, STB split, validity tiers, attribution, FP by size."""

from __future__ import annotations

import json

import pytest
from test_db import _fresh_db

from benchmark.report import build_report
from benchmark.report.extras import load_extras

EXTRAS_HEADINGS = (
    "Health",
    "SkillTrustBench vs rest",
    "Label-validity tiers",
    "SkillHarm attributed recall",
    "Benign FP rate by package size",
)


def _write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def _add_run(con, run_id, dataset_path, units):
    """``units``: (unit_path, truth_malicious, predicted_malicious | None, n_components)."""
    con.execute(
        "INSERT INTO runs (run_id, dataset_path, use_llm) VALUES (?, ?, FALSE)",
        [run_id, str(dataset_path)],
    )
    for unit_path, truth, pred, n_comp in units:
        con.execute(
            "INSERT INTO units (run_id, unit_path, category, is_malicious) VALUES (?, ?, 'Skills', ?)",
            [run_id, unit_path, truth],
        )
        con.execute(
            "INSERT INTO classifications (run_id, unit_path, is_malicious, status, run_time)"
            " VALUES (?, ?, ?, ?, 1.0)",
            [run_id, unit_path, pred, "Error" if pred is None else "Done"],
        )
        for i in range(n_comp):
            con.execute(
                "INSERT INTO components (run_id, unit_path, path) VALUES (?, ?, ?)",
                [run_id, unit_path, f"f{i}.md"],
            )


def _add_issue(con, run_id, unit_path, idx, severity, file):
    con.execute(
        "INSERT INTO issues (run_id, unit_path, issue_index, rule_id, severity, file)"
        " VALUES (?, ?, ?, 'R1', ?, ?)",
        [run_id, unit_path, idx, severity, file],
    )


def _labelled_dataset(tmp_path):
    skills = tmp_path / "Dataset" / "Skills"
    _write_jsonl(
        skills / "_external_labels.jsonl",
        [
            {"unit": "malware/stb-a", "source_dataset": "SkillTrustBench"},
            {"unit": "malware/stb-b", "source_dataset": "SkillTrustBench"},
            {"unit": "benign/stb-c", "source_dataset": "SkillTrustBench"},
            {"unit": "malware/h1", "source_dataset": "SkillHarm"},
            {"unit": "malware/h2", "source_dataset": "SkillHarm"},
        ],
    )
    _write_jsonl(
        skills / "_boundary_labels.jsonl",
        [
            {"unit_path": "Skills/malware/stb-a", "label_validity": "CORRECT"},
            {"unit_path": "Skills/malware/stb-b", "label_validity": "BROKEN"},
            {"unit_path": "Skills/malware/h1", "label_validity": "UNVERIFIABLE"},
            {"unit_path": "Skills/malware/h2", "label_validity": "WEAK"},
            {"unit_path": "Skills/malware/native", "label_validity": "MISLABELED"},
        ],
    )
    _write_jsonl(
        skills / "_skillharm_injected.jsonl",
        [
            {"unit_path": "Skills/malware/h1", "files": ["SKILL.md"], "method": "target_path"},
            {"unit_path": "Skills/malware/h2", "files": ["scripts/x.py"], "method": "diff"},
        ],
    )
    return tmp_path / "Dataset"


# (unit_path, truth, predicted, n_components)
_UNITS = [
    ("Skills/malware/stb-a", True, True, 1),
    ("Skills/malware/stb-b", True, False, 3),
    ("Skills/benign/stb-c", False, False, 1),
    ("Skills/malware/h1", True, True, 2),
    ("Skills/malware/h2", True, True, 7),
    ("Skills/malware/native", True, False, 25),
    ("Skills/benign/b1", False, True, 1),
    ("Skills/benign/b2", False, False, 4),
    ("Skills/benign/b3", False, True, 30),
    ("Skills/benign/b4", False, False, 21),
]
# An errored scan with no components rows; makes the run unhealthy (1/11 > 1% errors).
_UNITS_WITH_ERROR = [*_UNITS, ("Skills/benign/err", False, None, 0)]


def _db(tmp_path, run_id="r1", units=_UNITS):
    con = _fresh_db()
    _add_run(con, run_id, _labelled_dataset(tmp_path), units)
    # h1: HIGH issue on its injected file -> attributed.
    _add_issue(con, run_id, "Skills/malware/h1", 0, "HIGH", "SKILL.md")
    # h2: HIGH on a non-injected file, LOW on the injected one -> not attributed.
    _add_issue(con, run_id, "Skills/malware/h2", 0, "HIGH", "SKILL.md")
    _add_issue(con, run_id, "Skills/malware/h2", 1, "LOW", "scripts/x.py")
    return con


def _by_key(breakdowns):
    return {b.key: b for b in breakdowns}


def test_extras_stb_split(tmp_path):
    ex = load_extras(_db(tmp_path), "r1", None)
    stb = _by_key(ex.stb_split)
    assert [b.key for b in ex.stb_split] == ["SkillTrustBench", "non-STB"]
    # Malicious units only: the benign STB unit is excluded.
    assert (stb["SkillTrustBench"].n, stb["SkillTrustBench"].tp) == (2, 1)
    assert stb["SkillTrustBench"].recall == 0.5
    assert (stb["non-STB"].n, stb["non-STB"].tp, stb["non-STB"].fn) == (3, 2, 1)


def test_extras_attributed_recall(tmp_path):
    ex = load_extras(_db(tmp_path), "r1", None)
    a = ex.skillharm_attributed
    assert (a.units, a.verdict_tp, a.attributed_tp) == (2, 2, 1)
    assert a.recall == 1.0
    assert a.attributed_recall == 0.5 * a.recall


def test_extras_attributed_counts_only_medium_or_above_on_tps(tmp_path):
    con = _db(tmp_path)
    # MEDIUM on h2's injected file now attributes it; h1 stays attributed.
    _add_issue(con, "r1", "Skills/malware/h2", 2, "MEDIUM", "scripts/x.py")
    assert load_extras(con, "r1", None).skillharm_attributed.attributed_tp == 2
    # A missed unit is never attributed, whatever its issues.
    con.execute("UPDATE classifications SET is_malicious = FALSE WHERE unit_path LIKE '%/h1'")
    a = load_extras(con, "r1", None).skillharm_attributed
    assert (a.verdict_tp, a.attributed_tp, a.recall) == (1, 1, 0.5)


def test_extras_validity_tiers(tmp_path):
    ex = load_extras(_db(tmp_path), "r1", None)
    tiers = _by_key(ex.validity_tiers)
    assert [b.key for b in ex.validity_tiers] == ["working", "intent", "not_malicious"]
    assert (tiers["working"].n, tiers["working"].tp) == (1, 1)
    assert (tiers["intent"].n, tiers["intent"].tp) == (2, 1)  # BROKEN + UNVERIFIABLE
    assert (tiers["not_malicious"].n, tiers["not_malicious"].tp) == (2, 1)  # WEAK + MISLABELED


def test_extras_fp_by_size(tmp_path):
    ex = load_extras(_db(tmp_path, units=_UNITS_WITH_ERROR), "r1", None)
    size = _by_key(ex.fp_by_size)
    assert [b.key for b in ex.fp_by_size] == ["1", "2-5", "21+", "(none)"]
    assert (size["1"].n, size["1"].fp) == (2, 1)  # stb-c, b1
    assert (size["2-5"].n, size["2-5"].fp) == (1, 0)
    assert (size["21+"].n, size["21+"].fp) == (2, 1)
    assert size["21+"].fp_rate == 0.5
    assert (size["(none)"].n, size["(none)"].errors) == (1, 1)


def test_extras_splits(tmp_path):
    split = tmp_path / "split.tsv"
    split.write_text(
        "unit_path\tsplit\nSkills/malware/stb-a\tdev\nSkills/malware/h1\tholdout\n"
        "Skills/malware/not-in-run\tdev\n",
        encoding="utf-8",
    )
    con = _db(tmp_path)
    assert load_extras(con, "r1", None).splits is None
    splits = _by_key(load_extras(con, "r1", split).splits)
    assert set(splits) == {"dev", "holdout", "unassigned"}
    assert (splits["dev"].n, splits["holdout"].n, splits["unassigned"].n) == (1, 1, 8)


def test_extras_splits_rejects_malformed_line(tmp_path):
    split = tmp_path / "split.tsv"
    split.write_text("Skills/malware/stb-a dev\n", encoding="utf-8")
    with pytest.raises(ValueError, match="line 1"):
        load_extras(_db(tmp_path), "r1", split)


def test_extras_missing_labels(tmp_path):
    con = _fresh_db()
    empty = tmp_path / "empty"
    empty.mkdir()
    _add_run(con, "r1", empty, _UNITS)
    ex = load_extras(con, "r1", None)
    assert ex.labels_found is False
    assert ex.stb_split is None
    assert ex.validity_tiers is None
    assert ex.skillharm_attributed is None
    assert ex.health == []
    assert ex.fp_by_size  # needs no labels
    md = build_report(con, "r1")
    assert "labels not found" in md
    assert "Benign FP rate by package size" in md


def test_extras_one_label_file_missing_degrades_that_section_only(tmp_path):
    con = _db(tmp_path)
    (tmp_path / "Dataset" / "Skills" / "_boundary_labels.jsonl").unlink()
    ex = load_extras(con, "r1", None)
    assert ex.labels_found is False
    assert ex.validity_tiers is None
    assert ex.stb_split is not None
    assert ex.skillharm_attributed is not None


def test_report_renders_extras_sections(tmp_path):
    con = _db(tmp_path)
    assert load_extras(con, "r1", None).labels_found is True
    md = build_report(con, "r1")
    for heading in EXTRAS_HEADINGS:
        assert f"## {heading}" in md
    assert "Health: OK" in md
    assert "labels not found" not in md
    assert "## Splits" not in md


def test_report_renders_unhealthy_and_splits(tmp_path):
    con = _db(tmp_path)
    con.execute("UPDATE classifications SET status = 'Error', is_malicious = NULL")
    split = tmp_path / "split.tsv"
    split.write_text("Skills/malware/stb-a\tdev\n", encoding="utf-8")
    md = build_report(con, "r1", split_file=split)
    assert "UNHEALTHY" in md
    assert "Health: OK" not in md
    assert "## Splits" in md
    assert "unassigned" in md


def test_comparison_report_renders_extras_side_by_side(tmp_path):
    con = _db(tmp_path)
    _add_run(con, "r2", tmp_path / "Dataset", _UNITS)
    con.execute(
        "UPDATE classifications SET is_malicious = TRUE"
        " WHERE run_id = 'r2' AND unit_path = 'Skills/malware/stb-b'"
    )
    split = tmp_path / "split.tsv"
    split.write_text("Skills/malware/stb-a\tdev\n", encoding="utf-8")
    md = build_report(con, "r2", base="r1", split_file=split)
    for heading in (*EXTRAS_HEADINGS, "Splits"):
        assert f"## {heading}" in md
    # STB recall moves 0.500 -> 1.000 between base and head.
    stb_row = next(line for line in md.splitlines() if line.startswith("| SkillTrustBench "))
    assert "0.500" in stb_row and "1.000" in stb_row and "▲" in stb_row
    # Fixed-order sections keep their canonical order, not combined size (non-STB is larger).
    assert md.index("| SkillTrustBench ") < md.index("| non-STB ")
    assert md.count("Health: OK") == 2


def test_report_cli_split_file(tmp_path):
    import duckdb
    from click.testing import CliRunner

    from benchmark.db import _EVAL_VIEW, _SCHEMA
    from benchmark.main import report

    db = tmp_path / "bench.duckdb"
    con = duckdb.connect(str(db))
    con.execute(_SCHEMA)
    con.execute(_EVAL_VIEW)
    _add_run(con, "r1", _labelled_dataset(tmp_path), _UNITS)
    con.close()
    split = tmp_path / "split.tsv"
    split.write_text("Skills/malware/stb-a\tholdout\n", encoding="utf-8")
    result = CliRunner().invoke(report, [str(db), "r1", "--split-file", str(split)])
    assert result.exit_code == 0, result.output
    assert "## Splits" in result.output
    assert "| holdout |" in result.output


_HOLDOUT_SPLIT = "".join(
    f"{u}\tholdout\n"
    for u in (
        "Skills/malware/stb-a",  # TP
        "Skills/malware/h1",  # TP
        "Skills/malware/stb-b",  # FN (TP in r2)
        "Skills/benign/b1",  # FP
        "Skills/benign/b3",  # FP
        "Skills/benign/stb-c",  # TN
    )
)


def test_summary_splits_table_has_tp_tn_precision(tmp_path):
    con = _db(tmp_path)
    split = tmp_path / "split.tsv"
    split.write_text(_HOLDOUT_SPLIT, encoding="utf-8")
    holdout = _by_key(load_extras(con, "r1", split).splits)["holdout"]
    assert (holdout.tp, holdout.fp, holdout.tn, holdout.fn) == (2, 2, 1, 1)
    assert holdout.precision == 0.5
    md = build_report(con, "r1", split_file=split)
    assert "| split | n | TP | FP | TN | FN | errors | recall | precision |" in md
    assert "| holdout | 6 | 2 | 2 | 1 | 1 | 0 | 0.667 | 0.500 |" in md


def test_comparison_splits_table_has_precision(tmp_path):
    con = _db(tmp_path)
    _add_run(con, "r2", tmp_path / "Dataset", _UNITS)
    con.execute(
        "UPDATE classifications SET is_malicious = TRUE"
        " WHERE run_id = 'r2' AND unit_path = 'Skills/malware/stb-b'"
    )
    split = tmp_path / "split.tsv"
    split.write_text(_HOLDOUT_SPLIT, encoding="utf-8")
    md = build_report(con, "r2", base="r1", split_file=split)
    splits = md[md.index("## Splits") : md.index("## Timing")]
    assert "base TP | head TP" in splits and "base TN | head TN" in splits
    holdout = [line for line in splits.splitlines() if line.startswith("| holdout ")]
    # Counts row (n, TP, FP, TN, FN per side), recall row, precision row.
    assert "| holdout | 6 | 6 | 2 | 3 | 2 | 2 | 1 | 1 | 1 | 0 |" in holdout
    assert any("0.667" in line and "1.000" in line for line in holdout)
    assert any("0.500" in line and "0.600" in line for line in holdout)
