# SPDX-License-Identifier: Apache-2.0
"""Benchmark test config. Pytest's configfile is the repo-root pyproject, so register here."""


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "slow: copies the seed DuckDB (~170 MB); deselect with -m 'not slow'"
    )
