"""Pull per-run metrics out of a benchmark DuckDB into plain dataclasses.

Everything the report needs about a single run is gathered here so the compare
and render layers never touch SQL. Metric definitions mirror the ready-made
``queries/*.sql`` (precision/recall/F1/accuracy) so numbers agree across both
surfaces.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .query import one, rows


def _int(row: dict, key: str) -> int:
    """A count column as an int, treating a missing/NULL value as 0."""
    return row.get(key) or 0


@dataclass
class Confusion:
    """A run's confusion matrix plus the error count (outcome=ERROR)."""

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    errors: int = 0

    @property
    def scored(self) -> int:
        """Units that produced a usable verdict (the metric denominator)."""
        return self.tp + self.fp + self.tn + self.fn

    @property
    def total(self) -> int:
        return self.scored + self.errors

    @property
    def correct(self) -> int:
        """Units classified correctly (TP + TN)."""
        return self.tp + self.tn

    @property
    def incorrect(self) -> int:
        """Units NOT classified correctly: false pos/neg plus errors/timeouts.

        Together with ``correct`` this partitions ``total``, so it stays
        comparable across runs even when their error counts differ (unlike the
        verdict-only rates below).
        """
        return self.fp + self.fn + self.errors

    @property
    def correctness(self) -> float | None:
        """Fraction of ALL scanned units classified correctly (errors count as
        wrong) -- the error-honest counterpart to ``accuracy``."""
        return self.correct / self.total if self.total else None

    @property
    def precision(self) -> float | None:
        d = self.tp + self.fp
        return self.tp / d if d else None

    @property
    def recall(self) -> float | None:
        d = self.tp + self.fn
        return self.tp / d if d else None

    @property
    def f1(self) -> float | None:
        d = 2 * self.tp + self.fp + self.fn
        return 2 * self.tp / d if d else None

    @property
    def accuracy(self) -> float | None:
        return (self.tp + self.tn) / self.scored if self.scored else None


@dataclass
class Timing:
    scans: int = 0
    avg_s: float | None = None
    median_s: float | None = None
    p95_s: float | None = None
    max_s: float | None = None
    total_cpu_s: float | None = None  # sum of per-scan run_time = total scan work


@dataclass
class Breakdown:
    """Per-dimension-value outcome counts (e.g. one row per attack_vector)."""

    key: str
    n: int
    tp: int
    fp: int
    tn: int
    fn: int
    errors: int

    @property
    def recall(self) -> float | None:
        d = self.tp + self.fn
        return self.tp / d if d else None


@dataclass
class RunReport:
    run_id: str
    description: str | None
    model: str | None
    provider: str | None
    region: str | None
    use_llm: bool
    workers: int | None
    sample_limit: int | None
    started_at: object = None
    finished_at: object = None
    confusion: Confusion = field(default_factory=Confusion)
    timing: Timing = field(default_factory=Timing)
    # dimension name -> list[Breakdown], keyed by DIMENSIONS (category, behavior, ...)
    dists: dict[str, list[Breakdown]] = field(default_factory=dict)

    @property
    def est_wall_s(self) -> float | None:
        """Resume-safe estimate of elapsed time: total scan work / worker count.

        Approximate -- ignores ramp-up, the under-saturated tail, and auth pauses,
        so it tends to under-estimate. Unlike finished_at - started_at it isn't
        inflated by idle gaps between resumed sessions.
        """
        cpu = self.timing.total_cpu_s
        if cpu is None or not self.workers:
            return None
        return cpu / self.workers


# Distribution dimensions: each is a column on the evaluation view that the
# report groups by. Order here is the order they render in the report.
DIMENSIONS: tuple[str, ...] = ("category", "behavior", "corpus", "attack_vector")

_CONFUSION_SQL = """
SELECT
    count(*) FILTER (WHERE outcome = 'TP')    AS tp,
    count(*) FILTER (WHERE outcome = 'FP')    AS fp,
    count(*) FILTER (WHERE outcome = 'TN')    AS tn,
    count(*) FILTER (WHERE outcome = 'FN')    AS fn,
    count(*) FILTER (WHERE outcome = 'ERROR') AS errors
FROM evaluation WHERE run_id = ?
"""

_TIMING_SQL = """
SELECT
    count(*)                                AS scans,
    round(avg(run_time), 2)                 AS avg_s,
    round(median(run_time), 2)              AS median_s,
    round(quantile_cont(run_time, 0.95), 2) AS p95_s,
    round(max(run_time), 2)                 AS max_s,
    round(sum(run_time), 1)                 AS total_cpu_s
FROM classifications WHERE run_id = ?
"""


def _breakdown_sql(column: str) -> str:
    return f"""
    SELECT
        coalesce(CAST({column} AS VARCHAR), '(none)') AS key,
        count(*)                                  AS n,
        count(*) FILTER (WHERE outcome = 'TP')    AS tp,
        count(*) FILTER (WHERE outcome = 'FP')    AS fp,
        count(*) FILTER (WHERE outcome = 'TN')    AS tn,
        count(*) FILTER (WHERE outcome = 'FN')    AS fn,
        count(*) FILTER (WHERE outcome = 'ERROR') AS errors
    FROM evaluation
    WHERE run_id = ?
    GROUP BY key
    ORDER BY n DESC, key
    """  # noqa: S608 - column is from the fixed DIMENSIONS tuple, never user input


def load_run(con, run_id: str) -> RunReport:
    """Gather every metric the report needs for one run."""
    meta = one(con, "SELECT * FROM runs WHERE run_id = ?", [run_id])
    conf_row = one(con, _CONFUSION_SQL, [run_id])
    confusion = Confusion(
        tp=_int(conf_row, "tp"),
        fp=_int(conf_row, "fp"),
        tn=_int(conf_row, "tn"),
        fn=_int(conf_row, "fn"),
        errors=_int(conf_row, "errors"),
    )
    t = one(con, _TIMING_SQL, [run_id])
    timing = Timing(
        scans=_int(t, "scans"),
        avg_s=t.get("avg_s"),
        median_s=t.get("median_s"),
        p95_s=t.get("p95_s"),
        max_s=t.get("max_s"),
        total_cpu_s=t.get("total_cpu_s"),
    )
    dists: dict[str, list[Breakdown]] = {}
    for name in DIMENSIONS:
        # Breakdown fields match the SELECT aliases in _breakdown_sql exactly.
        dists[name] = [Breakdown(**r) for r in rows(con, _breakdown_sql(name), [run_id])]
    return RunReport(
        run_id=run_id,
        description=meta.get("description"),
        model=meta.get("model"),
        provider=meta.get("provider"),
        region=meta.get("region"),
        use_llm=bool(meta.get("use_llm")),
        workers=meta.get("workers"),
        sample_limit=meta.get("sample_limit"),
        started_at=meta.get("started_at"),
        finished_at=meta.get("finished_at"),
        confusion=confusion,
        timing=timing,
        dists=dists,
    )
