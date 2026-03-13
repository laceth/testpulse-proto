#!/usr/bin/env python3
"""Convert README.md to a styled PDF using fpdf2 + markdown.

Usage:
    python scripts/readme_to_pdf.py [README.md] [output.pdf]
"""
from __future__ import annotations

import html as html_mod
import re
import sys
from pathlib import Path

import markdown
from fpdf import FPDF


# DejaVu font paths
_FONT_DIR = "/usr/share/fonts/truetype/dejavu"


class ReadmePDF(FPDF):
    """Custom PDF with header/footer for TestPulse documentation."""

    title_text = "TestPulse Proto v1"

    def _register_fonts(self):
        """Register DejaVu Unicode TTF fonts."""
        self.add_font("DejaVu", "", f"{_FONT_DIR}/DejaVuSans.ttf")
        self.add_font("DejaVu", "B", f"{_FONT_DIR}/DejaVuSans-Bold.ttf")
        self.add_font("DejaVu", "I", f"{_FONT_DIR}/DejaVuSans-Oblique.ttf")
        self.add_font("DejaVu", "BI", f"{_FONT_DIR}/DejaVuSans-BoldOblique.ttf")
        self.add_font("DejaVuMono", "", f"{_FONT_DIR}/DejaVuSansMono.ttf")
        self.add_font("DejaVuMono", "B", f"{_FONT_DIR}/DejaVuSansMono-Bold.ttf")

    def header(self):
        self.set_font("DejaVu", "B", 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, self.title_text, align="L")
        self.cell(0, 8, "Phase 1 \u2014 CLI Diagnostic Toolkit", align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(200, 200, 200)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("DejaVu", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def chapter_title(self, level: int, title: str):
        sizes = {1: 18, 2: 14, 3: 12, 4: 11}
        size = sizes.get(level, 10)
        self.ln(4 if level <= 2 else 2)
        if level <= 2:
            self.set_draw_color(60, 120, 200)
            self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
            self.ln(3)
        self.set_font("DejaVu", "B", size)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, size * 0.6, title)
        self.ln(2)

    def body_text(self, text: str, bold: bool = False, code: bool = False):
        if code:
            self.set_font("DejaVuMono", "", 7.5)
            self.set_text_color(40, 40, 40)
            # Light gray background for code blocks
            self.set_fill_color(245, 245, 245)
            lines = text.split("\n")
            for line in lines:
                safe = line.replace("\t", "    ")
                w = self.w - self.l_margin - self.r_margin
                self.cell(w, 4, safe, fill=True, new_x="LMARGIN", new_y="NEXT")
            self.ln(2)
        else:
            self.set_font("DejaVu", "B" if bold else "", 9.5)
            self.set_text_color(40, 40, 40)
            self.set_x(self.l_margin)
            w = self.w - self.l_margin - self.r_margin
            self.multi_cell(w, 5, text)
            self.ln(1)

    def add_table(self, headers: list[str], rows: list[list[str]]):
        """Render a markdown table."""
        self.set_font("DejaVuMono", "", 7)
        self.set_text_color(40, 40, 40)

        n_cols = len(headers)
        usable = self.w - self.l_margin - self.r_margin
        col_w = usable / n_cols

        # Header row
        self.set_font("DejaVu", "B", 7.5)
        self.set_fill_color(60, 120, 200)
        self.set_text_color(255, 255, 255)
        for h in headers:
            self.cell(col_w, 6, h.strip(), border=1, fill=True, align="C")
        self.ln()

        # Data rows
        self.set_font("DejaVu", "", 7)
        self.set_text_color(40, 40, 40)
        for i, row in enumerate(rows):
            if i % 2 == 0:
                self.set_fill_color(245, 248, 255)
            else:
                self.set_fill_color(255, 255, 255)
            max_lines = 1
            cell_texts = []
            for j, cell in enumerate(row):
                txt = cell.strip()
                # Strip backticks and bold markers for PDF
                txt = txt.replace("`", "").replace("**", "")
                txt = _strip_formatting(txt)
                cell_texts.append(txt)
                # Estimate lines needed
                lines_needed = max(1, len(txt) // int(col_w / 1.8) + 1)
                max_lines = max(max_lines, lines_needed)

            row_h = max(6, max_lines * 4.5)

            # Check page break
            if self.get_y() + row_h > self.h - self.b_margin - 10:
                self.add_page()
                # Re-draw header on new page
                self.set_font("DejaVu", "B", 7.5)
                self.set_fill_color(60, 120, 200)
                self.set_text_color(255, 255, 255)
                for h in headers:
                    self.cell(col_w, 6, h.strip(), border=1, fill=True, align="C")
                self.ln()
                self.set_font("DejaVu", "", 7)
                self.set_text_color(40, 40, 40)
                if i % 2 == 0:
                    self.set_fill_color(245, 248, 255)
                else:
                    self.set_fill_color(255, 255, 255)

            x_start = self.get_x()
            y_start = self.get_y()
            for j, txt in enumerate(cell_texts):
                self.set_xy(x_start + j * col_w, y_start)
                self.multi_cell(col_w, 4.5, txt, border=1, fill=True, max_line_height=row_h)
            self.set_xy(x_start, y_start + row_h)
        self.ln(3)

    def blockquote(self, text: str):
        self.set_font("DejaVu", "I", 9)
        self.set_text_color(80, 80, 80)
        self.set_fill_color(240, 245, 255)
        x = self.get_x()
        self.set_draw_color(60, 120, 200)
        self.rect(self.l_margin, self.get_y(), self.w - self.l_margin - self.r_margin, 8, style="F")
        self.line(self.l_margin, self.get_y(), self.l_margin, self.get_y() + 8)
        self.set_x(self.l_margin + 4)
        clean = text.replace("**", "").strip()
        self.multi_cell(0, 5, clean)
        self.ln(2)

    def bullet(self, text: str, indent: int = 0):
        self.set_font("DejaVu", "", 9)
        self.set_text_color(40, 40, 40)
        x = self.l_margin + indent * 5
        self.set_x(x)
        clean = text.replace("`", "").replace("**", "")
        self.cell(4, 5, chr(8226))
        w = self.w - self.get_x() - self.r_margin
        self.multi_cell(w, 5, clean)

    def hrule(self):
        self.ln(2)
        self.set_draw_color(200, 200, 200)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(3)


def _strip_formatting(text: str) -> str:
    """Remove markdown inline formatting for PDF text."""
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"\*([^*]+)\*", r"\1", text)
    text = text.replace("\u2705", "[OK]").replace("\u26a0\ufe0f", "[!]").replace("\u274c", "[X]")
    text = text.replace("\u2714", "[OK]").replace("\u2718", "[X]")
    text = text.replace("\u2197", "->").replace("\u2192", "->").replace("\u2190", "<-")
    return text


def parse_and_render(md_path: Path, pdf_path: Path):
    """Parse README.md and render to PDF."""
    lines = md_path.read_text(encoding="utf-8").splitlines()

    pdf = ReadmePDF(orientation="P", unit="mm", format="A4")
    pdf._register_fonts()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.alias_nb_pages()
    pdf.add_page()

    # Title page content
    pdf.set_font("DejaVu", "B", 26)
    pdf.set_text_color(30, 60, 120)
    pdf.ln(20)
    pdf.cell(0, 15, "TestPulse Proto v1", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("DejaVu", "", 13)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 8, "Phase 1 CLI Diagnostic Toolkit", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    pdf.set_font("DejaVu", "", 10)
    pdf.cell(0, 6, "802.1X RADIUS/dot1x Test Automation for Forescout", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(8)
    pdf.set_draw_color(60, 120, 200)
    pdf.line(60, pdf.get_y(), pdf.w - 60, pdf.get_y())
    pdf.ln(8)
    pdf.set_font("DejaVu", "I", 9)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 6, "19 tools | 6 categories | 7 parsers | 70+ event kinds | 6 diagram types",
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, "Generated from README.md", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.add_page()

    i = 0
    in_code = False
    code_buf: list[str] = []
    in_table = False
    table_headers: list[str] = []
    table_rows: list[list[str]] = []

    # Skip the first title line (we made a title page)
    skip_first_title = True

    while i < len(lines):
        line = lines[i]

        # --- Code blocks ---
        if line.strip().startswith("```"):
            if in_code:
                # End code block
                pdf.body_text("\n".join(code_buf), code=True)
                code_buf.clear()
                in_code = False
            else:
                # Flush any pending table
                if in_table:
                    pdf.add_table(table_headers, table_rows)
                    in_table = False
                    table_headers = []
                    table_rows = []
                in_code = True
            i += 1
            continue

        if in_code:
            code_buf.append(line)
            i += 1
            continue

        # --- Table rows ---
        if "|" in line and line.strip().startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            # Check if separator row
            if all(re.match(r"^[-:]+$", c.strip()) for c in cells if c.strip()):
                i += 1
                continue
            if not in_table:
                in_table = True
                table_headers = cells
            else:
                table_rows.append(cells)
            i += 1
            continue
        else:
            # Flush pending table
            if in_table:
                pdf.add_table(table_headers, table_rows)
                in_table = False
                table_headers = []
                table_rows = []

        # --- Headers ---
        heading = re.match(r"^(#{1,4})\s+(.+)$", line)
        if heading:
            level = len(heading.group(1))
            title = _strip_formatting(heading.group(2))
            if skip_first_title and level == 1:
                skip_first_title = False
                i += 1
                continue
            pdf.chapter_title(level, title)
            i += 1
            continue

        # --- Horizontal rule ---
        if line.strip() in ("---", "***", "___"):
            pdf.hrule()
            i += 1
            continue

        # --- Blockquote ---
        if line.strip().startswith(">"):
            text = _strip_formatting(line.strip().lstrip("> "))
            pdf.blockquote(text)
            i += 1
            continue

        # --- Bullet list ---
        bullet_match = re.match(r"^(\s*)[-*]\s+(.+)$", line)
        if bullet_match:
            indent = len(bullet_match.group(1)) // 2
            text = _strip_formatting(bullet_match.group(2))
            pdf.bullet(text, indent)
            i += 1
            continue

        # --- Numbered list ---
        num_match = re.match(r"^(\s*)\d+\.\s+(.+)$", line)
        if num_match:
            indent = len(num_match.group(1)) // 2
            text = _strip_formatting(num_match.group(2))
            pdf.bullet(text, indent)
            i += 1
            continue

        # --- Blank line ---
        if not line.strip():
            pdf.ln(2)
            i += 1
            continue

        # --- Regular paragraph ---
        text = _strip_formatting(line.strip())
        if text:
            pdf.body_text(text)
        i += 1

    # Flush
    if in_code and code_buf:
        pdf.body_text("\n".join(code_buf), code=True)
    if in_table:
        pdf.add_table(table_headers, table_rows)

    pdf.output(str(pdf_path))
    print(f"[OK] PDF written: {pdf_path} ({pdf_path.stat().st_size / 1024:.0f} KB)")


def main():
    md_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("README.md")
    pdf_path = Path(sys.argv[2]) if len(sys.argv) > 2 else md_path.with_suffix(".pdf")
    parse_and_render(md_path, pdf_path)


if __name__ == "__main__":
    main()
