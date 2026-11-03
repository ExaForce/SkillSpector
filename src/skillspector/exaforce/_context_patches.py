# SPDX-License-Identifier: Apache-2.0
"""Prepend a skill-context header to prompts for files SKILL.md points at (fork behavior).

A file SKILL.md tells the agent to read or run is judged better as an
instruction than as passive documentation. When ``SKILLSPECTOR_EXA_SKILL_CONTEXT``
selects an analyzer node, each batch of a referenced file gets a short header
naming the skill and quoting the SKILL.md lines that refer to it.

``SKILLSPECTOR_EXA_SKILL_CONTEXT``, read on every call:

``off``       (default; also unset or unknown) no header.
``ssd``       ``semantic_security_discovery`` only.
``semantic``  ``semantic_security_discovery``, ``semantic_developer_intent`` and
              ``semantic_quality_policy``.

The header is prepended after batching, so ``get_batches`` token budgeting is
unchanged. Upstream does not keep the node id on the analyzer, so ``__init__``
is intercepted to record it as ``_exa_node``.
"""

from __future__ import annotations

import inspect
import os
import re
import weakref

import yaml

from skillspector.llm_analyzer_base import LLMAnalyzerBase

from . import _skill_refs
from ._patchlib import intercept_method

ENV_VAR = "SKILLSPECTOR_EXA_SKILL_CONTEXT"

_SSD = "semantic_security_discovery"
_SDI = "semantic_developer_intent"
_SQP = "semantic_quality_policy"
_NODES_BY_MODE = {"ssd": frozenset({_SSD}), "semantic": frozenset({_SSD, _SDI, _SQP})}

# id(batch) -> (weakref to batch, header). Batch is unhashable, so key on id and
# confirm identity through the weakref before use (ids can be reused).
_HEADERS: dict[int, tuple[weakref.ref, str]] = {}


def selected_nodes() -> frozenset[str]:
    return _NODES_BY_MODE.get(os.environ.get(ENV_VAR, "").strip().lower(), frozenset())


def _manifest(content: str) -> dict:
    """Frontmatter name/description, mirroring ``build_context._parse_manifest``."""
    if not content.startswith("---"):
        return {}
    end_match = re.search(r"\n---\s*\n", content[3:])
    if not end_match:
        return {}
    try:
        data = yaml.safe_load(content[3 : end_match.start() + 3])
    except yaml.YAMLError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: data[k] for k in ("name", "description") if k in data}


def _init_interceptor(original, self, args, kwargs):
    original(self, *args, **kwargs)
    bound = inspect.signature(original).bind(self, *args, **kwargs)
    bound.apply_defaults()
    self._exa_node = bound.arguments.get("node")


def _get_batches_interceptor(original, self, args, kwargs):
    batches = original(self, *args, **kwargs)
    if getattr(self, "_exa_node", None) not in selected_nodes():
        return batches
    file_cache = inspect.signature(original).bind(self, *args, **kwargs).arguments["file_cache"]
    skill_path = next((p for p in ("SKILL.md", "skill.md") if p in file_cache), None)
    if skill_path is None:
        return batches
    skill_md = file_cache[skill_path]
    refs = _skill_refs.referenced_files(skill_md, sorted(file_cache))
    if not refs:
        return batches
    manifest = _manifest(skill_md)
    for dead in [k for k, (ref, _) in _HEADERS.items() if ref() is None]:
        del _HEADERS[dead]
    for batch in batches:
        if batch.file_path in refs:
            header = _skill_refs.context_header(manifest, refs[batch.file_path])
            _HEADERS[id(batch)] = (weakref.ref(batch), header)
    return batches


def _build_prompt_interceptor(original, self, args, kwargs):
    prompt = original(self, *args, **kwargs)
    batch = inspect.signature(original).bind(self, *args, **kwargs).arguments["batch"]
    entry = _HEADERS.pop(id(batch), None)
    if entry is not None and entry[0]() is batch:
        return entry[1] + "\n\n" + prompt
    return prompt


def apply() -> None:
    cls = LLMAnalyzerBase
    intercept_method(
        cls, "__init__", _init_interceptor, expected_params=("base_prompt", "model", "node")
    )
    intercept_method(
        cls, "get_batches", _get_batches_interceptor, expected_params=("file_paths", "file_cache")
    )
    intercept_method(cls, "build_prompt", _build_prompt_interceptor, expected_params=("batch",))


__all__ = ["ENV_VAR", "apply", "selected_nodes"]
