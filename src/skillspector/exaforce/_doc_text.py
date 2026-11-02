"""Stdlib-only text extraction for PDF and OOXML files, with hidden-text detection.

Pure module: no flags, no patching. It parses untrusted input, so every limit
below is a hard bound and no public function raises on malformed input; it
returns a ``DocText`` with ``skipped_reason`` set, or with zero runs, instead.

``skipped_reason`` values: ``"limits"`` (a size, entry-count, decompression or
text cap tripped). Encrypted, object-stream-only and otherwise unparseable
files are not "skipped": they yield zero runs and render as a header only.
"""

from __future__ import annotations

import base64
import binascii
import html
import io
import re
import zipfile
import zlib
from dataclasses import dataclass, field

MAX_PDF_BYTES = 5_000_000
MAX_STREAM_BYTES = 10_000_000
# Extra bound across all streams of one PDF so many small bombs cannot add up.
MAX_TOTAL_DECOMPRESSED = 50_000_000
MAX_ZIP_ENTRIES = 2_000
MAX_ZIP_UNCOMPRESSED = 20_000_000
MAX_TEXT_CHARS = 200_000
HIDDEN_PREFIX = "[hidden] "
MIN_VISIBLE_FONT_SIZE = 1.5
_MAX_OPERANDS = 64


@dataclass
class DocText:
    text_runs: list[str] = field(default_factory=list)
    hidden_runs: list[str] = field(default_factory=list)
    skipped_reason: str | None = None


# --------------------------------------------------------------------------- render


def _clean(run: str) -> str:
    return " ".join(run.split())


def render(doc: DocText, ext: str, mark_hidden: bool) -> str:
    """Render ``doc`` in the exact extracted-content format."""
    if doc.skipped_reason:
        return f"[exaforce: text extracted from {ext}; 0 hidden spans]\nextraction skipped: {doc.skipped_reason}"
    lines: list[str] = []
    budget = MAX_TEXT_CHARS

    def add(run: str, prefix: str = "") -> None:
        nonlocal budget
        run = _clean(run)
        if not run or budget <= 0:
            return
        run = run[:budget]
        budget -= len(run)
        lines.append(prefix + run)

    for run in doc.text_runs:
        add(run)
    for run in doc.hidden_runs:
        add(run, HIDDEN_PREFIX if mark_hidden else "")
    hidden_count = sum(1 for ln in lines if ln.startswith(HIDDEN_PREFIX)) if mark_hidden else 0
    header = f"[exaforce: text extracted from {ext}; {hidden_count} hidden spans]"
    return "\n".join([header, *lines])


class _RunSink:
    """Collects runs, enforcing the total extracted-character cap."""

    def __init__(self) -> None:
        self.doc = DocText()
        self.chars = 0

    @property
    def full(self) -> bool:
        return self.chars >= MAX_TEXT_CHARS

    def add(self, run: str, hidden: bool = False) -> None:
        run = _clean(run)
        if not run or self.full:
            return
        run = run[: MAX_TEXT_CHARS - self.chars]
        self.chars += len(run)
        (self.doc.hidden_runs if hidden else self.doc.text_runs).append(run)


# --------------------------------------------------------------------------- PDF

_WS = b" \t\r\n\x00\x0c"
_TOKEN = re.compile(rb"[^\s\x00()<>\[\]{}/%]+")
_NAME = re.compile(rb"/[^\s\x00()<>\[\]{}/%]*")
_STRING_SPECIAL = re.compile(rb"[()\\]")
_EOL = re.compile(rb"[\r\n]")
_STREAM = re.compile(rb"(?<!end)stream\r?\n")
_FILTER = re.compile(rb"/Filter\s*(\[[^\]]*\]|/[A-Za-z0-9]+)")
_INLINE_IMAGE_END = re.compile(rb"\sEI(?=[\s]|$)")
_ESCAPES = {
    ord("n"): 10,
    ord("r"): 13,
    ord("t"): 9,
    ord("b"): 8,
    ord("f"): 12,
}
_SKIP_STREAM_MARKERS = (
    b"/ObjStm",
    b"/XRef",
    b"/Subtype/Image",
    b"/Subtype /Image",
    b"/FontFile",
    b"/Length1",
)


def _read_string(data: bytes, i: int) -> tuple[bytes, int]:
    """Read a literal string whose opening ``(`` is at ``i``; returns (bytes, next index)."""
    out = bytearray()
    depth = 1
    i += 1
    n = len(data)
    while i < n:
        m = _STRING_SPECIAL.search(data, i)
        if m is None:
            out += data[i:]
            return bytes(out), n
        out += data[i : m.start()]
        c = data[m.start()]
        i = m.start() + 1
        if c == 0x28:  # (
            depth += 1
            out.append(c)
        elif c == 0x29:  # )
            depth -= 1
            if depth == 0:
                return bytes(out), i
            out.append(c)
        else:  # backslash
            if i >= n:
                break
            e = data[i]
            i += 1
            if e in _ESCAPES:
                out.append(_ESCAPES[e])
            elif 0x30 <= e <= 0x37:
                digits = bytes([e])
                while len(digits) < 3 and i < n and 0x30 <= data[i] <= 0x37:
                    digits += bytes([data[i]])
                    i += 1
                out.append(int(digits, 8) & 0xFF)
            elif e == 0x0D:  # line continuation
                if i < n and data[i] == 0x0A:
                    i += 1
            elif e == 0x0A:
                pass
            else:  # \( \) \\ and unknown escapes: the character itself
                out.append(e)
    return bytes(out), n


def _decode_pdf_string(raw: bytes) -> str:
    if raw.startswith(b"\xfe\xff"):
        text = raw[2:].decode("utf-16-be", errors="ignore")
    else:
        text = raw.decode("latin-1")
    return "".join(ch if ch >= " " else " " for ch in text)


def _is_hidden_colour(op: str, args: list[float]) -> bool:
    if op in ("g", "rg"):
        return bool(args) and all(a >= 0.95 for a in args)
    return bool(args) and all(a <= 0.05 for a in args)  # k


def _run_content_stream(data: bytes, sink: _RunSink) -> None:
    """Walk one content stream, tracking fill colour, render mode and font size."""
    white = False
    mode = 0
    size = float("inf")
    saved: list[tuple[bool, int, float]] = []
    operands: list[object] = []
    arrays: list[list[bytes]] = []
    i = 0
    n = len(data)

    def show(raw: bytes) -> None:
        hidden = white or mode == 3 or size < MIN_VISIBLE_FONT_SIZE
        sink.add(_decode_pdf_string(raw), hidden)

    while i < n and not sink.full:
        c = data[i]
        if c in _WS:
            i += 1
        elif c == 0x25:  # % comment
            m = _EOL.search(data, i)
            i = m.end() if m else n
        elif c == 0x28:  # (
            raw, i = _read_string(data, i)
            if arrays:
                arrays[-1].append(raw)
            else:
                operands.append(raw)
        elif c == 0x3C:  # <
            if data[i + 1 : i + 2] == b"<":
                i += 2
            else:
                end = data.find(b">", i)
                end = n if end < 0 else end
                hexs = re.sub(rb"[^0-9A-Fa-f]", b"", data[i + 1 : end])
                if len(hexs) % 2:
                    hexs += b"0"
                raw = binascii.unhexlify(hexs)
                i = end + 1
                if arrays:
                    arrays[-1].append(raw)
                else:
                    operands.append(raw)
        elif c == 0x3E:  # >
            i += 2 if data[i + 1 : i + 2] == b">" else 1
        elif c == 0x5B:  # [
            arrays.append([])
            i += 1
        elif c == 0x5D:  # ]
            if arrays:
                operands.append(arrays.pop())
            i += 1
        elif c == 0x2F:  # name
            m = _NAME.match(data, i)
            operands.append(m.group()[1:] if m else b"")
            i = m.end() if m else i + 1
        elif c in b")]{}":
            i += 1
        else:
            m = _TOKEN.match(data, i)
            if m is None:
                i += 1
                continue
            i = m.end()
            tok = m.group()
            try:
                num = float(tok)
            except ValueError:
                num = None
            if num is not None:
                if not arrays:
                    operands.append(num)
                continue
            op = tok.decode("latin-1")
            nums = [o for o in operands if isinstance(o, float)]
            if op in ("g", "rg", "k"):
                white = _is_hidden_colour(op, nums)
            elif op == "Tf" and nums:
                size = abs(nums[-1])
            elif op == "Tr" and nums:
                mode = int(nums[-1])
            elif op == "q":
                if len(saved) < 256:
                    saved.append((white, mode, size))
            elif op == "Q":
                if saved:
                    white, mode, size = saved.pop()
            elif op in ("Tj", "'", '"'):
                if operands and isinstance(operands[-1], bytes):
                    show(operands[-1])
            elif op == "TJ":
                if operands and isinstance(operands[-1], list):
                    show(b"".join(operands[-1]))
            elif op == "BI":
                m2 = _INLINE_IMAGE_END.search(data, i)
                i = m2.end() if m2 else n
            operands.clear()
            continue
        if len(operands) > _MAX_OPERANDS:
            del operands[: len(operands) - _MAX_OPERANDS]


def _bounded_inflate(data: bytes, limit: int) -> bytes:
    return zlib.decompressobj().decompress(data, limit)


def _decode_stream(raw: bytes, filters: list[str], budget: int) -> bytes | None:
    """Apply the filter chain; None when unsupported, corrupt or over budget."""
    limit = min(MAX_STREAM_BYTES, budget)
    data = raw
    try:
        for name in filters:
            if name in ("FlateDecode", "Fl"):
                data = _bounded_inflate(data, limit)
            elif name in ("ASCII85Decode", "A85"):
                body = data.strip()
                if body.endswith(b"~>"):
                    body = body[:-2]
                if body.startswith(b"<~"):
                    body = body[2:]
                data = base64.a85decode(body)
            elif name in ("ASCIIHexDecode", "AHx"):
                hexs = re.sub(rb"[^0-9A-Fa-f]", b"", data.split(b">")[0])
                data = binascii.unhexlify(hexs + (b"0" if len(hexs) % 2 else b""))
            else:
                return None
    except (zlib.error, ValueError, binascii.Error):
        return None
    return data


def extract_pdf(data: bytes) -> DocText:
    """Extract visible and hidden text from a PDF's content streams."""
    if len(data) > MAX_PDF_BYTES:
        return DocText(skipped_reason="limits")
    sink = _RunSink()
    try:
        if b"/Encrypt" in data:
            return sink.doc
        budget = MAX_TOTAL_DECOMPRESSED
        pos = 0
        while not sink.full and budget > 0:
            m = _STREAM.search(data, pos)
            if m is None:
                break
            end = data.find(b"endstream", m.end())
            end = len(data) if end < 0 else end
            pos = end + 9
            obj = data.rfind(b"obj", 0, m.start())
            dict_text = data[obj if obj >= 0 else 0 : m.start()]
            if any(marker in dict_text for marker in _SKIP_STREAM_MARKERS):
                continue
            fm = _FILTER.search(dict_text)
            filters = re.findall(rb"/([A-Za-z0-9]+)", fm.group(1)) if fm else []
            body = _decode_stream(data[m.end() : end], [f.decode() for f in filters], budget)
            if body is None:
                continue
            budget -= len(body)
            if b"BT" in body and b"ET" in body:
                _run_content_stream(body, sink)
    except Exception:  # noqa: BLE001 - untrusted input must never raise
        pass
    return sink.doc


# --------------------------------------------------------------------------- OOXML

# ext -> (member matcher, paragraph end tag, text-element regex)
_OOXML = {
    ".docx": (
        re.compile(r"^word/document\.xml$"),
        "</w:p>",
        re.compile(r"<w:t(?:\s[^>]*)?>([^<]*)</w:t>"),
    ),
    ".pptx": (
        re.compile(r"^ppt/slides/slide\d+\.xml$"),
        "</a:p>",
        re.compile(r"<a:t(?:\s[^>]*)?>([^<]*)</a:t>"),
    ),
    ".xlsx": (
        re.compile(r"^xl/sharedStrings\.xml$"),
        "</si>",
        re.compile(r"<t(?:\s[^>]*)?>([^<]*)</t>"),
    ),
}


def _slide_order(name: str) -> tuple[int, str]:
    m = re.search(r"(\d+)\.xml$", name)
    return (int(m.group(1)) if m else 0, name)


def extract_ooxml(data: bytes, ext: str) -> DocText:
    """Extract text from a .docx, .pptx or .xlsx archive (no hidden-text detection)."""
    spec = _OOXML.get(ext.lower())
    if spec is None:
        return DocText()
    member_re, para_end, text_re = spec
    sink = _RunSink()
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if (
                len(infos) > MAX_ZIP_ENTRIES
                or sum(i.file_size for i in infos) > MAX_ZIP_UNCOMPRESSED
            ):
                return DocText(skipped_reason="limits")
            names = sorted(
                (i.filename for i in infos if member_re.match(i.filename)), key=_slide_order
            )
            budget = MAX_ZIP_UNCOMPRESSED
            for name in names:
                if sink.full:
                    break
                with zf.open(name) as fh:
                    raw = fh.read(budget + 1)  # declared sizes can lie; bound the real read
                if len(raw) > budget:
                    return DocText(skipped_reason="limits")
                budget -= len(raw)
                xml = raw.decode("utf-8", errors="replace")
                for para in xml.split(para_end):
                    text = "".join(html.unescape(t) for t in text_re.findall(para))
                    sink.add(text)
    except Exception:  # noqa: BLE001 - untrusted input must never raise
        return DocText()
    return sink.doc
