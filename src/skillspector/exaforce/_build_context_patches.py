# SPDX-License-Identifier: Apache-2.0
"""Flag-gated extracted text for PDF/office files (fork behavior).

Upstream ``build_context._read_file_cache`` reads every component as UTF-8 text, so a
PDF or OOXML file reaches the analyzers as binary garbage. With
``SKILLSPECTOR_EXA_DOC_TEXT=on`` the cache entry of each ``.pdf/.docx/.pptx/.xlsx``
component is replaced by the text ``_doc_text`` extracts from it. With
``SKILLSPECTOR_EXA_HIDDEN_TEXT=on`` hidden runs are additionally marked ``[hidden] ``.

Upstream ``static_runner._is_binary_file`` skips ``.pdf`` by extension, so it is also
patched to let extracted content (recognised by its header) through.

Only the exact value ``on`` enables a flag; both are read on every call.
"""

from __future__ import annotations

import inspect
import os
from collections.abc import Callable
from pathlib import Path

from skillspector.logging_config import get_logger
from skillspector.nodes import build_context
from skillspector.nodes.analyzers import static_runner

from . import _doc_text
from ._patchlib import intercept_module_callable

logger = get_logger(__name__)

DOC_TEXT_ENV = "SKILLSPECTOR_EXA_DOC_TEXT"
HIDDEN_TEXT_ENV = "SKILLSPECTOR_EXA_HIDDEN_TEXT"
EXTRACTED_PREFIX = "[exaforce: text extracted from "
_DOC_EXTENSIONS = (".pdf", ".docx", ".pptx", ".xlsx")


def _flag(name: str) -> bool:
    return os.environ.get(name) == "on"


def _extract(full: Path, ext: str) -> str | None:
    """Rendered text for ``full``, or None if its bytes cannot be read."""
    try:
        size = full.stat().st_size
        cap = _doc_text.MAX_PDF_BYTES if ext == ".pdf" else _doc_text.MAX_ZIP_UNCOMPRESSED
        if size > cap:
            doc = _doc_text.DocText(skipped_reason="limits")  # do not read what we would reject
        else:
            data = full.read_bytes()
            doc = (
                _doc_text.extract_pdf(data) if ext == ".pdf" else _doc_text.extract_ooxml(data, ext)
            )
    except OSError:
        return None
    return _doc_text.render(doc, ext, _flag(HIDDEN_TEXT_ENV))


def _read_cache_interceptor(original: Callable, args: tuple, kwargs: dict) -> object:
    result = original(*args, **kwargs)
    if not _flag(DOC_TEXT_ENV):
        return result
    bound = inspect.signature(original).bind(*args, **kwargs)
    skill_dir, components = bound.arguments["skill_dir"], bound.arguments["components"]
    file_cache, events = result
    for path in components:
        ext = Path(path).suffix.lower()
        if ext not in _DOC_EXTENSIONS or path not in file_cache:
            continue
        text = _extract(Path(skill_dir) / path, ext)
        if text is not None:
            file_cache[path] = text
    return file_cache, events


def _binary_interceptor(original: Callable, args: tuple, kwargs: dict) -> object:
    if _flag(DOC_TEXT_ENV):
        content = inspect.signature(original).bind(*args, **kwargs).arguments["content"]
        if isinstance(content, str) and content.startswith(EXTRACTED_PREFIX):
            return False
    return original(*args, **kwargs)


def apply() -> None:
    intercept_module_callable(
        build_context,
        "_read_file_cache",
        _read_cache_interceptor,
        expected_params=("skill_dir", "components"),
    )
    intercept_module_callable(
        static_runner,
        "_is_binary_file",
        _binary_interceptor,
        expected_params=("path", "content"),
    )
