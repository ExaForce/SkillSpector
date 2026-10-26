# SPDX-License-Identifier: Apache-2.0
"""Tests for the machine-sized --workers default."""

from __future__ import annotations

from benchmark import config


def _machine(monkeypatch, ram_gib: int, cpus: int) -> None:
    sizes = {"SC_PAGE_SIZE": 4096, "SC_PHYS_PAGES": ram_gib * 2**30 // 4096}
    monkeypatch.setattr(config.os, "sysconf", sizes.__getitem__)
    monkeypatch.setattr(config.os, "cpu_count", lambda: cpus)


def test_default_workers_is_capped_on_a_large_machine(monkeypatch):
    _machine(monkeypatch, ram_gib=48, cpus=16)
    assert config.default_workers() == config.MAX_AUTO_WORKERS


def test_default_workers_is_ram_bound_on_a_small_machine(monkeypatch):
    _machine(monkeypatch, ram_gib=8, cpus=16)
    assert config.default_workers() == 8 * 2**30 // 2 // config.WORKER_RAM_BUDGET_BYTES


def test_default_workers_is_cpu_bound_with_few_cores(monkeypatch):
    _machine(monkeypatch, ram_gib=64, cpus=2)
    assert config.default_workers() == 2 * config.WORKERS_PER_CPU
