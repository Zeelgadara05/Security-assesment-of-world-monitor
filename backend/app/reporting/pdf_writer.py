"""Minimal, pure-stdlib PDF writer (Phase 9).

The project deliberately avoids heavyweight report dependencies (reportlab /
weasyprint are not in ``requirements.txt``). This module produces a *real*,
valid PDF 1.4 document from the deterministic report sections using only the
Python standard library.

Design goals:

  * **Real, valid PDF** -- a conforming document with a correct xref table and
    trailer, parseable by any PDF reader.
  * **Deterministic** -- identical input sections produce identical bytes, so
    exports are reproducible and comparable.
  * **Redaction-safe** -- it only ever receives the already-redacted report
    text produced by ``reporting.builder``; nothing here invents content.
  * **Conservative typography** -- a simple fixed layout: Helvetica body + a
    bold title band, wrapped paragraphs, page numbers in a footer, no images,
    no compression.

The internal object model is deliberately small: one catalog, one pages tree,
one content stream per text block, one page per printed page.
"""
from __future__ import annotations

import re

# A4 portrait geometry (points).
PAGE_WIDTH = 595.0
PAGE_HEIGHT = 842.0
LEFT_MARGIN = 48.0
RIGHT_MARGIN = 40.0
TOP_MARGIN = 48.0
BOTTOM_MARGIN = 40.0
FOOTER_Y = 28.0

FONT_SIZE_TITLE = 16.0
FONT_SIZE_H = 12.0
FONT_SIZE_BODY = 10.0
LINE_HEIGHT = 14.0
PARA_GAP = 6.0
TITLE_GAP = 14.0

# Helvetica is not monospaced; a conservative average advance width keeps long
# lines from overflowing the right margin.
_ADVANCE = 0.55  # average glyph advance as a fraction of font size

_TEXT_WIDTH_POINTS = PAGE_WIDTH - LEFT_MARGIN - RIGHT_MARGIN


def _escape(text: str) -> str:
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _latin1_safe(text: str) -> str:
    """Map common non-Latin-1 punctuation to ASCII deterministically and drop
    anything else that cannot be represented in the base-14 Helvetica charset
    (which covers Latin-1 only).  This keeps exports byte-stable and parseable.
    """
    replacements = {
        "\u2014": "--", "\u2013": "-", "\u2019": "'", "\u2018": "'",
        "\u201c": '"', "\u201d": '"', "\u2026": "...", "\u00a0": " ",
        "\u2192": "->", "\u2022": "-", "\u00b7": ".", "\u00e2\u20ac\u201d": "--",
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    return text.encode("latin-1", "replace").decode("latin-1")


def _max_chars(size: float) -> int:
    return max(8, int(_TEXT_WIDTH_POINTS / (size * _ADVANCE)))


def _wrap(text: str, size: float) -> list[str]:
    """Wrap text into lines that fit the printable width for ``size``."""
    limit = _max_chars(size)
    if not text:
        return [""]
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        # Hard-split over-long tokens (e.g. long URLs) so they never overflow.
        while len(word) > limit:
            if current:
                lines.append(current)
                current = ""
            lines.append(word[:limit])
            word = word[limit:]
        if not current:
            current = word
        elif len(current) + 1 + len(word) <= limit:
            current = f"{current} {word}"
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


def _strip_markdown(text: str) -> str:
    """Apply a light, deterministic markdown→plain transformation.

    Inline code ticks and emphasis markers are removed so the PDF stays
    readable; tables are dropped from the PDF (they remain fully available in
    the JSON/HTML forms). Headings are detected separately.
    """
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"\*([^*]+)\*", r"\1", text)
    text = re.sub(r"^#{1,3}\s+", "", text)
    text = text.replace("**", "").replace("`", "")
    return text.strip()


def _is_heading(line: str) -> bool:
    return bool(re.match(r"^#{1,3}\s", line))


def _table_row(line: str) -> bool:
    return bool(re.match(r"^\s*\|", line)) or bool(re.match(r"^\s*\|?[-:| ]+\|?\s*$", line))


class _Block:
    __slots__ = ("text", "size", "bold", "gap")

    def __init__(self, text: str, size: float, bold: bool = False, gap: float = 2.0):
        self.text = text
        self.size = size
        self.bold = bold
        self.gap = gap


def _page_objects(sections: list[dict], *, title: str, generated_at: str,
                  fingerprint: str) -> list[tuple[bytes, str, int]]:
    """Lay out sections into printable pages.

    Returns a list of ``(content_bytes, footer_text, page_number)`` tuples.
    The footer carries the page number and the report fingerprint so each page
    is traceable to a specific export.
    """
    blocks: list[_Block] = [
        _Block(title, FONT_SIZE_TITLE, bold=True, gap=TITLE_GAP),
        _Block(f"Generated: {generated_at}", FONT_SIZE_BODY),
        _Block(f"Report fingerprint: {fingerprint or 'n/a'}", FONT_SIZE_BODY),
    ]
    for section in sections:
        md = section.get("markdown") or ""
        blocks.append(_Block(section.get("title") or section.get("id") or "",
                             FONT_SIZE_H, bold=True, gap=8.0))
        paragraphs = re.split(r"\n\s*\n", md)
        for paragraph in paragraphs:
            for line in paragraph.splitlines():
                if not line.strip() or _table_row(line):
                    continue
                if _is_heading(line):
                    text = _strip_markdown(line)
                    blocks.append(_Block(text, FONT_SIZE_H, bold=True, gap=6.0))
                else:
                    text = _strip_markdown(line)
                    if text:
                        blocks.append(_Block(text, FONT_SIZE_BODY))

    pages: list[tuple[bytes, str, int]] = []
    y = PAGE_HEIGHT - TOP_MARGIN
    content: list[str] = []
    page_no = 1

    def _flush():
        nonlocal y, content, page_no
        footer = (
            f"BT /F1 8 Tf 1 0 0 1 {LEFT_MARGIN} {FOOTER_Y} Tm "
            f"({_escape(_latin1_safe(f'CyberAgent assessment report - page {page_no} - fingerprint {fingerprint or 'n/a'}'))}) Tj ET"
        )
        content.append(footer)
        stream = "\n".join(content).encode("latin-1")
        pages.append((stream, f"page {page_no}", page_no))

    for block in blocks:
        lines = _wrap(block.text, block.size)
        needed = len(lines) * LINE_HEIGHT + block.gap
        if y - needed < BOTTOM_MARGIN:
            _flush()
            y = PAGE_HEIGHT - TOP_MARGIN
            content = []
            page_no += 1
        for line in lines:
            content.append(
                f"BT /{'B2' if block.bold else 'F1'} "
                f"{block.size} Tf 1 0 0 1 {LEFT_MARGIN} {y:.1f} Tm "
                f"({_escape(_latin1_safe(line))}) Tj ET"
            )
            y -= LINE_HEIGHT
        y -= block.gap

    _flush()
    return pages


def render_pdf(sections: list[dict], *, title: str,
               generated_at: str | None = None,
               fingerprint: str = "") -> bytes:
    """Render a valid PDF 1.4 document from report sections.

    ``sections`` mirrors the ``ReportSection`` model: each dict has at least
    ``title`` and ``markdown``. Output is deterministic for identical input.
    """
    import datetime

    generated = generated_at or datetime.datetime.now(datetime.UTC).isoformat()
    pages = _page_objects(sections, title=title, generated_at=generated,
                          fingerprint=fingerprint)

    # --- object graph ----------------------------------------------------
    # 1: catalog, 2: pages tree, then per page: [page obj, content obj].
    objects: list[str] = []
    page_refs: list[str] = []

    def _new(**_) -> None:
        pass

    # catalog
    objects.append("<< /Type /Catalog /Pages 2 0 R >>")
    pages_node_ids = [2]
    next_id = 3
    for _ in pages:
        pages_node_ids.append(next_id)  # page object id
        next_id += 2
    # content streams
    content_streams = [stream for (stream, _foot, _no) in pages]

    # pages tree node
    kids = " ".join(f"{oid} 0 R" for oid in pages_node_ids[1:])
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>")
    for i, (stream, _foot, _no) in enumerate(pages):
        page_oid = pages_node_ids[1 + i]
        content_oid = page_oid + 1
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH:.0f} {PAGE_HEIGHT:.0f}] "
            f"/Resources << /Font << /F1 {content_oid + 1} 0 R /B2 {content_oid + 2} 0 R >> >> "
            f"/Contents {content_oid} 0 R >>"
        )
        objects.append(f"<< /Length {len(stream)} >>\nstream\n{stream.decode('latin-1')}\nendstream")

    # fonts
    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

    # resource resolve: page texts reference F1 (body) / B2 (bold). The font
    # objects are appended after all content objects, so their ids depend on
    # the number of objects already emitted. We emit page + content pairs then
    # the two font objects -> font ids = last two. Because content streams
    # may reference /F1 and /B2 by name only, no forward id needed.
    out: list[str] = ["%PDF-1.4"]
    offsets: dict[int, int] = {}

    def _emit(obj: str) -> int:
        uid = len(out)  # object number = index in out (1-based after header)
        offsets[uid] = _byte_offset(out)
        out.append(f"{uid} 0 obj\n{obj}\nendobj")
        return uid

    # object numbers must be 1..N sequential: out is ['%PDF-1.4', obj1, ...]
    _emit(objects[0])      # 1 catalog
    _emit(objects[1])      # 2 pages tree
    for i, (stream, _foot, _no) in enumerate(pages):
        _emit(objects[2 + i * 2])       # page i
        _emit(objects[2 + i * 2 + 1])   # content i
    _emit(objects[-2])     # Helvetica
    _emit(objects[-1])     # Helvetica-Bold

    xref_offset = _byte_offset(out)
    out.append("xref")
    out.append(f"0 {len(offsets) + 1}")
    out.append("0000000000 65535 f ")
    for oid in range(1, len(offsets) + 1):
        out.append(f"{offsets[oid]:010d} 00000 n ")
    out.append("trailer")
    out.append(f"<< /Size {len(offsets) + 1} /Root 1 0 R >>")
    out.append("startxref")
    out.append(str(xref_offset))
    out.append("%%EOF")

    body = "\n".join(out)
    return body.encode("latin-1")


def _byte_offset(lines: list[str]) -> int:
    """Byte offset of the object that follows when appended after ``lines``."""
    return len("\n".join(lines)) + 1


__all__ = ["render_pdf"]