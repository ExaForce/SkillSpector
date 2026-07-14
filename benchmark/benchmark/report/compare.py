"""Head-to-head comparison of two runs: deltas, coverage, outcome transitions.

The transition analysis is the point of the report: over the units BOTH runs
scanned, which classifications moved (FN->TP newly caught, TP->FN regressions,
...). That is what quantifies whether a change actually helped, and where.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .query import rows

# Default cap on how many regression/fix rows the report lists (full counts are
# always shown). Shared by compare(), build_report(), and the CLI --top option.
DEFAULT_TOP = 25

# outcome pairs (baseline -> candidate) that count as an improvement / a regression.
_FIXED = {("FN", "TP"), ("FP", "TN"), ("ERROR", "TP"), ("ERROR", "TN")}
_REGRESSED = {("TP", "FN"), ("TN", "FP"), ("TP", "ERROR"), ("TN", "ERROR")}


@dataclass
class Coverage:
    both: int = 0
    only_base: int = 0
    only_head: int = 0

    @property
    def total(self) -> int:
        return self.both + self.only_base + self.only_head

    @property
    def nonshared_pct(self) -> float:
        """Share of the union of scanned units that only one run covered."""
        return 100 * (self.only_base + self.only_head) / self.total if self.total else 0.0


@dataclass
class MovedUnit:
    unit_path: str
    base_outcome: str
    head_outcome: str
    category: str | None
    truth_malicious: bool | None
    attack_vector: str | None
    behavior: str | None


@dataclass
class Comparison:
    coverage: Coverage
    fixed: int = 0
    regressed: int = 0
    unchanged: int = 0
    other_moves: int = 0
    regressions: list[MovedUnit] = field(default_factory=list)
    fixes: list[MovedUnit] = field(default_factory=list)
    n_regressions: int = 0  # full counts (lists may be capped by --top)
    n_fixes: int = 0


_COVERAGE_SQL = """
WITH a AS (SELECT DISTINCT unit_path FROM evaluation WHERE run_id = ?),
     b AS (SELECT DISTINCT unit_path FROM evaluation WHERE run_id = ?)
SELECT
    (SELECT count(*) FROM a JOIN b USING (unit_path))                       AS both,
    (SELECT count(*) FROM a WHERE unit_path NOT IN (SELECT unit_path FROM b)) AS only_a,
    (SELECT count(*) FROM b WHERE unit_path NOT IN (SELECT unit_path FROM a)) AS only_b
"""

_MATRIX_SQL = """
WITH a AS (SELECT unit_path, outcome FROM evaluation WHERE run_id = ?),
     b AS (SELECT unit_path, outcome FROM evaluation WHERE run_id = ?)
SELECT a.outcome AS a_out, b.outcome AS b_out, count(*) AS n
FROM a JOIN b USING (unit_path)
GROUP BY a_out, b_out
"""

# Units that moved (a_outcome != b_outcome), with ground-truth context for eyeballing.
_MOVES_SQL = """
WITH a AS (SELECT unit_path, outcome FROM evaluation WHERE run_id = ?),
     b AS (SELECT unit_path, outcome FROM evaluation WHERE run_id = ?)
SELECT a.unit_path, a.outcome AS a_out, b.outcome AS b_out,
       u.category, u.is_malicious, u.attack_vector, u.behavior
FROM a JOIN b USING (unit_path)
JOIN units u ON u.run_id = ? AND u.unit_path = a.unit_path
WHERE a.outcome <> b.outcome
-- Prioritize malicious before benign, then skills before code (this order also
-- decides which rows survive the --top cap in compare()).
ORDER BY u.is_malicious DESC,
         CASE u.category WHEN 'skill' THEN 0 WHEN 'code' THEN 1 ELSE 2 END,
         a.unit_path
"""


def compare(con, run_base: str, run_head: str, top: int = DEFAULT_TOP) -> Comparison:
    cov_row = rows(con, _COVERAGE_SQL, [run_base, run_head])[0]
    coverage = Coverage(
        both=cov_row["both"], only_base=cov_row["only_a"], only_head=cov_row["only_b"]
    )

    matrix = {
        (r["a_out"], r["b_out"]): r["n"] for r in rows(con, _MATRIX_SQL, [run_base, run_head])
    }
    fixed = sum(n for k, n in matrix.items() if k in _FIXED)
    regressed = sum(n for k, n in matrix.items() if k in _REGRESSED)
    unchanged = sum(n for (a, b), n in matrix.items() if a == b)
    other = sum(matrix.values()) - fixed - regressed - unchanged

    moves = rows(con, _MOVES_SQL, [run_base, run_head, run_head])
    regressions, fixes = [], []
    for m in moves:
        mu = MovedUnit(
            unit_path=m["unit_path"],
            base_outcome=m["a_out"],
            head_outcome=m["b_out"],
            category=m["category"],
            truth_malicious=m["is_malicious"],
            attack_vector=m["attack_vector"],
            behavior=m["behavior"],
        )
        if (m["a_out"], m["b_out"]) in _REGRESSED:
            regressions.append(mu)
        elif (m["a_out"], m["b_out"]) in _FIXED:
            fixes.append(mu)

    return Comparison(
        coverage=coverage,
        fixed=fixed,
        regressed=regressed,
        unchanged=unchanged,
        other_moves=other,
        regressions=regressions[:top],
        fixes=fixes[:top],
        n_regressions=len(regressions),
        n_fixes=len(fixes),
    )
