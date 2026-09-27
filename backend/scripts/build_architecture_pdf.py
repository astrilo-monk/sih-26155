"""Architecture document (deliverable: max 2 pages) as a PDF, generated from docs/architecture-brief.md.

    python scripts/build_architecture_pdf.py     # writes docs/architecture-brief.pdf

The Markdown is the source; never edit the PDF by hand. Reads the subset the brief uses: headings, paragraphs,
one fenced block, pipe tables, **bold**, *italic*, `code` and [links](...). Exits 1 if the PDF is over 2 pages.
"""

from __future__ import annotations

import re
import sys
from html import escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "docs" / "architecture-brief.md"
OUTPUT = ROOT / "docs" / "architecture-brief.pdf"
MAX_PAGES = 2

INK, MUTED, RULE, ACCENT = colors.HexColor("#111111"), colors.HexColor("#555555"), colors.HexColor("#cccccc"), \
    colors.HexColor("#d9480f")
STYLES = {
    "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=13, leading=16, textColor=INK, spaceAfter=2),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=9.5, leading=12, textColor=ACCENT,
                         spaceBefore=5, spaceAfter=2),
    "p": ParagraphStyle("p", fontName="Helvetica", fontSize=7.8, leading=10, textColor=INK, spaceAfter=3),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=7.3, leading=9, textColor=INK),
    "code": ParagraphStyle("code", fontName="Courier", fontSize=6.6, leading=8, textColor=INK),
}


def inline(text: str) -> str:
    """Markdown inline syntax to ReportLab paragraph markup; everything else escaped."""
    text = escape(text, quote=False)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"`([^`]+)`", r'<font face="Courier">\1</font>', text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    return re.sub(r"(?<![*\w])\*([^*]+)\*(?!\*)", r"<i>\1</i>", text)


def table(rows: list[str]) -> Table:
    cells = [[c.strip() for c in r.strip().strip("|").split("|")] for r in rows]
    cells = [r for r in cells if not all(re.fullmatch(r":?-+:?", c) for c in r)]  # drop the |---| rule
    data = [[Paragraph(inline(c), STYLES["cell"]) for c in r] for r in cells]
    width = A4[0] - 3 * cm
    # first column a label, the last the explanation: middle columns (short values) stay narrow
    n = len(cells[0])
    first, middle = (0.28, 0.0) if n == 2 else (0.2, 0.16)
    widths = [width * first] + [width * middle] * (n - 2) + [width * (1 - first - middle * (n - 2))]
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, INK), ("LINEBELOW", (0, 1), (-1, -1), 0.3, RULE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
    ]))
    return t


def flowables(markdown: str) -> list:
    out, para, lines = [], [], markdown.splitlines()

    def flush():
        if para:
            out.append(Paragraph(inline(" ".join(para)), STYLES["p"]))
            para.clear()

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            flush()
            j = i + 1
            while not lines[j].startswith("```"):
                j += 1
            out.append(Preformatted("\n".join(lines[i + 1:j]), STYLES["code"]))
            out.append(Spacer(1, 3))
            i = j + 1
            continue
        if line.startswith("|"):
            flush()
            j = i
            while j < len(lines) and lines[j].startswith("|"):
                j += 1
            out += [table(lines[i:j]), Spacer(1, 3)]
            i = j
            continue
        if line.startswith("#"):
            flush()
            level = "h1" if line.startswith("# ") else "h2"
            out.append(Paragraph(inline(line.lstrip("#").strip()), STYLES[level]))
        elif not line.strip():
            flush()
        else:
            para.append(line.strip())
        i += 1
    flush()
    return out


def build(source: Path = SOURCE, output: Path = OUTPUT) -> int:
    pages = []

    def footer(canvas, doc):
        pages.append(doc.page)
        canvas.setFont("Helvetica", 6.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(1.5 * cm, 0.8 * cm, "NetAuditAI · SIH 2026 PS 26155 · generated from docs/architecture-brief.md")
        canvas.drawRightString(A4[0] - 1.5 * cm, 0.8 * cm, f"{doc.page}")

    doc = SimpleDocTemplate(str(output), pagesize=A4, leftMargin=1.5 * cm, rightMargin=1.5 * cm,
                            topMargin=1.2 * cm, bottomMargin=1.3 * cm, title="NetAuditAI architecture",
                            author="NetAuditAI")
    doc.build(flowables(source.read_text(encoding="utf-8")), onFirstPage=footer, onLaterPages=footer)
    return len(pages)


if __name__ == "__main__":
    n = build()
    print(f"{OUTPUT.relative_to(ROOT)}: {n} page(s)")
    sys.exit(0 if n <= MAX_PAGES else 1)
