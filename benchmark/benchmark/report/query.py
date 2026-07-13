"""Tiny DuckDB adapter shared by the data and compare layers.

A thin "run SQL -> list of dict rows" primitive (the rest of the codebase reads
tuples positionally; the report wants named columns). Kept in its own module so
neither ``data`` nor ``compare`` has to import the other's internals for it.
"""

from __future__ import annotations


def rows(con, sql: str, params: list) -> list[dict]:
    """Run a query and return its rows as dicts (no pandas dependency)."""
    cur = con.execute(sql, params)
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]


def one(con, sql: str, params: list) -> dict:
    """Run a query and return its first row as a dict, or ``{}`` if none."""
    result = rows(con, sql, params)
    return result[0] if result else {}
