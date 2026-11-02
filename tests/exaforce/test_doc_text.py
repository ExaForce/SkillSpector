"""Tests for the stdlib PDF/OOXML text extractor."""

import base64
import glob
import io
import os
import zipfile
import zlib

import pytest

from skillspector.exaforce import _doc_text as dt

HIDDEN = "hidden instruction text that is long enough to count"


def _pdf(*streams: tuple[bytes, str], trailer: bytes = b"") -> bytes:
    """Build a minimal PDF. Each stream is (raw_bytes, filter_entry)."""
    out = b"%PDF-1.4\n"
    for n, (body, filt) in enumerate(streams, start=1):
        out += f"{n} 0 obj\n<< {filt} /Length {len(body)} >>\nstream\n".encode() + body
        out += b"\nendstream\nendobj\n"
    return out + trailer + b"%%EOF\n"


def _flate(content: bytes) -> bytes:
    return _pdf((zlib.compress(content), "/Filter /FlateDecode"))


def test_pdf_extracts_visible_and_hidden():
    content = f"BT /F1 12 Tf (visible) Tj 1 1 1 rg ({HIDDEN}) Tj ET".encode()
    a85 = (
        base64.a85encode(zlib.compress(b"BT /F1 12 Tf (second \\(page\\) \\101\\\\) Tj ET")) + b"~>"
    )
    pdf = _pdf(
        (zlib.compress(content), "/Filter /FlateDecode"),
        (a85, "/Filter [/ASCII85Decode /FlateDecode]"),
    )
    doc = dt.extract_pdf(pdf)
    assert doc.skipped_reason is None
    assert doc.text_runs == ["visible", "second (page) A\\"]
    assert doc.hidden_runs == [HIDDEN]


def test_pdf_cmyk_and_gray_white_hidden_and_black_visible():
    content = b"BT /F1 12 Tf 0 0 0 0 k (cmyk white) Tj 0.5 g (gray) Tj 1 g (gray white) Tj ET"
    doc = dt.extract_pdf(_flate(content))
    assert doc.text_runs == ["gray"]
    assert doc.hidden_runs == ["cmyk white", "gray white"]


def test_pdf_render_mode_3_is_hidden():
    doc = dt.extract_pdf(
        _flate(b"BT /F1 12 Tf (shown) Tj 3 Tr [(inv) -10 (isible)] TJ 0 Tr (again) ' ET")
    )
    assert doc.text_runs == ["shown", "again"]
    assert doc.hidden_runs == ["invisible"]


def test_pdf_tiny_font_is_hidden():
    doc = dt.extract_pdf(_flate(b"BT /F1 1 Tf (tiny) Tj /F1 1.5 Tf (edge) Tj ET"))
    assert doc.hidden_runs == ["tiny"]
    assert doc.text_runs == ["edge"]


def test_pdf_size_cap():
    doc = dt.extract_pdf(b"%PDF-1.4\n" + b"x" * dt.MAX_PDF_BYTES)
    assert doc.skipped_reason == "limits"
    assert dt.render(doc, ".pdf", True).endswith("extraction skipped: limits")


def test_pdf_unparseable_streams_yield_header_only():
    garbage = _pdf(
        (b"\x00\x01garbage not zlib", "/Filter /FlateDecode"), (b"zz", "/Filter /LZWDecode")
    )
    encrypted = _flate(b"BT (secret) Tj ET")[:-6] + b"trailer << /Encrypt 9 0 R >>\n%%EOF\n"
    for pdf in (garbage, encrypted, b"not a pdf at all"):
        doc = dt.extract_pdf(pdf)
        assert doc.text_runs == [] and doc.hidden_runs == [] and doc.skipped_reason is None
        assert (
            dt.render(doc, ".pdf", True) == "[exaforce: text extracted from .pdf; 0 hidden spans]"
        )


def test_pdf_flate_stream_decompression_bound(monkeypatch):
    monkeypatch.setattr(dt, "MAX_STREAM_BYTES", 40)
    body = b"BT (kept) Tj ET " + b" " * 1000 + b"BT (lost) Tj ET"
    doc = dt.extract_pdf(_flate(body))
    assert "lost" not in " ".join(doc.text_runs)


def test_text_cap_applies_to_render():
    runs = ["a" * 1000] * 300
    out = dt.render(dt.DocText(text_runs=runs), ".pdf", False)
    assert len("".join(out.split("\n")[1:])) == dt.MAX_TEXT_CHARS


def _zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


def test_ooxml_docx_text():
    xml = (
        b'<w:document><w:body><w:p><w:r><w:t>Hello</w:t></w:r><w:r><w:t xml:space="preserve"> &amp; world</w:t></w:r></w:p>'
        b"<w:p><w:tab/><w:r><w:t>Second</w:t></w:r></w:p></w:body></w:document>"
    )
    doc = dt.extract_ooxml(_zip({"word/document.xml": xml}), ".docx")
    assert doc.text_runs == ["Hello & world", "Second"]
    assert doc.hidden_runs == []


def test_ooxml_pptx_and_xlsx_text():
    slides = {
        "ppt/slides/slide10.xml": b"<a:p><a:r><a:t>ten</a:t></a:r></a:p>",
        "ppt/slides/slide2.xml": b"<a:p><a:r><a:t>two</a:t></a:r></a:p>",
    }
    assert dt.extract_ooxml(_zip(slides), ".pptx").text_runs == ["two", "ten"]
    sst = b"<sst><si><t>cell one</t></si><si><r><t>cell</t></r><r><t> two</t></r></si></sst>"
    assert dt.extract_ooxml(_zip({"xl/sharedStrings.xml": sst}), ".xlsx").text_runs == [
        "cell one",
        "cell two",
    ]


def test_ooxml_zip_bomb_guard():
    many = _zip({f"f{i}.txt": b"x" for i in range(dt.MAX_ZIP_ENTRIES + 1)})
    big = _zip({"word/document.xml": b"<w:t>a</w:t>" + b"0" * (dt.MAX_ZIP_UNCOMPRESSED + 1)})
    for blob in (many, big):
        doc = dt.extract_ooxml(blob, ".docx")
        assert doc.skipped_reason == "limits"
        assert dt.render(doc, ".docx", True) == (
            "[exaforce: text extracted from .docx; 0 hidden spans]\nextraction skipped: limits"
        )


def test_ooxml_bad_zip_yields_header_only():
    doc = dt.extract_ooxml(b"PK\x03\x04 not really", ".docx")
    assert doc == dt.DocText()


def test_render_format_exact():
    doc = dt.DocText(text_runs=["one", "two"], hidden_runs=["secret"])
    assert dt.render(doc, ".pdf", True) == (
        "[exaforce: text extracted from .pdf; 1 hidden spans]\none\ntwo\n[hidden] secret"
    )
    assert dt.render(doc, ".pdf", False) == (
        "[exaforce: text extracted from .pdf; 0 hidden spans]\none\ntwo\nsecret"
    )


_ROOT = "/Users/will/workspace/MalSkillBench"


@pytest.mark.skipif(not os.path.isdir(_ROOT), reason="MalSkillBench dataset not present")
def test_real_skillharm_pdf():
    paths = sorted(
        glob.glob(f"{_ROOT}/Dataset/Skills/malware/*__skillharm-fpp-*/**/*.pdf", recursive=True)
    )[:3]
    assert paths
    for path in paths:
        with open(path, "rb") as fh:
            doc = dt.extract_pdf(fh.read())
        assert sum(len(r) for r in doc.text_runs + doc.hidden_runs) >= 200, path
        assert len(doc.hidden_runs) >= 1, path
