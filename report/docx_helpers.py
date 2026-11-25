"""Вспомогательные функции оформления отчёта (python-docx): TNR 14, поля 30/15/20/20 мм."""
from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

FONT = "Times New Roman"


class Report:
    def __init__(self):
        self.doc = Document()
        self.fig = 0
        self.tab = 0
        self.lst = 0
        d = self.doc
        s = d.sections[0]
        s.page_height, s.page_width = Cm(29.7), Cm(21.0)
        s.left_margin, s.right_margin, s.top_margin, s.bottom_margin = Cm(3), Cm(1.5), Cm(2), Cm(2)
        st = d.styles["Normal"]
        st.font.name = FONT
        st.font.size = Pt(14)
        st.element.rPr.rFonts.set(qn("w:eastAsia"), FONT)
        pf = st.paragraph_format
        pf.space_after = Pt(0)
        pf.space_before = Pt(0)
        pf.line_spacing = 1.15
        for name, size in (("Heading 1", 14), ("Heading 2", 14), ("Heading 3", 14)):
            h = d.styles[name]
            h.font.name = FONT
            h.font.size = Pt(size)
            h.font.bold = True
            h.font.italic = False
            h.font.color.rgb = RGBColor(0, 0, 0)
            rpr = h.element.get_or_add_rPr()
            rf = rpr.find(qn("w:rFonts"))
            if rf is None:
                rf = OxmlElement("w:rFonts")
                rpr.append(rf)
            for a in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
                rf.set(qn(a), FONT)
            for a in ("w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme"):
                if rf.get(qn(a)) is not None:
                    del rf.attrib[qn(a)]
            h.paragraph_format.space_before = Pt(12)
            h.paragraph_format.space_after = Pt(6)
            h.paragraph_format.keep_with_next = True
            h.paragraph_format.first_line_indent = Cm(1.25)
        self._page_numbers()

    # ------------------------------------------------------------ базовые элементы
    def _page_numbers(self):
        p = self.doc.sections[0].footer.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run()
        for t, txt in (("begin", None), (None, "PAGE"), ("end", None)):
            if t:
                e = OxmlElement("w:fldChar")
                e.set(qn("w:fldCharType"), t)
            else:
                e = OxmlElement("w:instrText")
                e.set(qn("xml:space"), "preserve")
                e.text = txt
            r._r.append(e)
        r.font.size = Pt(12)
        self.doc.sections[0].different_first_page_header_footer = True

    def center(self, text, bold=False, size=14, space_after=0, italic=False):
        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_after = Pt(space_after)
        r = p.add_run(text)
        r.bold, r.italic = bold, italic
        r.font.size = Pt(size)
        return p

    def right(self, text, space_after=0):
        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        p.paragraph_format.space_after = Pt(space_after)
        p.add_run(text)
        return p

    def blank(self, n=1):
        for _ in range(n):
            self.doc.add_paragraph()

    def page_break(self):
        self.doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    def h1(self, text):
        return self.doc.add_heading(text, level=1)

    def h2(self, text):
        return self.doc.add_heading(text, level=2)

    def _rich(self, p, text):
        """**жирный** и `код` внутри абзаца."""
        import re

        for part in re.split(r"(\*\*[^*]+\*\*|`[^`]+`)", text):
            if not part:
                continue
            if part.startswith("**"):
                r = p.add_run(part[2:-2])
                r.bold = True
            elif part.startswith("`"):
                r = p.add_run(part[1:-1])
                r.font.name = "Courier New"
                r.font.size = Pt(12)
            else:
                p.add_run(part)

    def para(self, text, indent=True):
        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        if indent:
            p.paragraph_format.first_line_indent = Cm(1.25)
        self._rich(p, text)
        return p

    def bullets(self, items, numbered=False):
        for i, it in enumerate(items, 1):
            p = self.doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            p.paragraph_format.left_indent = Cm(1.25)
            p.paragraph_format.first_line_indent = Cm(-0.6)
            self._rich(p, (f"{i}) " if numbered else "– ") + it)

    # ------------------------------------------------------------ таблицы
    @staticmethod
    def _shade(cell, color):
        tcPr = cell._tc.get_or_add_tcPr()
        sh = OxmlElement("w:shd")
        sh.set(qn("w:val"), "clear")
        sh.set(qn("w:color"), "auto")
        sh.set(qn("w:fill"), color)
        tcPr.append(sh)

    def table(self, title, header, rows, widths=None, size=11, fills=None):
        self.tab += 1
        cap = self.doc.add_paragraph()
        cap.paragraph_format.space_before = Pt(6)
        cap.paragraph_format.keep_with_next = True
        r = cap.add_run(f"Таблица {self.tab} — {title}")
        r.font.size = Pt(12)
        t = self.doc.add_table(rows=1, cols=len(header))
        t.style = "Table Grid"
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        for i, h in enumerate(header):
            c = t.rows[0].cells[i]
            c.text = ""
            run = c.paragraphs[0].add_run(h)
            run.bold = True
            run.font.size = Pt(size)
            c.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
            self._shade(c, "D9E2F3")
        for ri, row in enumerate(rows):
            cells = t.add_row().cells
            for i, v in enumerate(row):
                cells[i].text = ""
                p = cells[i].paragraphs[0]
                txt = str(v)
                if txt.startswith("`") and txt.endswith("`"):
                    run = p.add_run(txt[1:-1])
                    run.font.name = "Courier New"
                    run.font.size = Pt(size - 1)
                else:
                    self._rich(p, txt)
                    for run in p.runs:
                        run.font.size = Pt(size)
                if fills and fills(ri, i, txt):
                    self._shade(cells[i], fills(ri, i, txt))
        # повтор шапки на следующих страницах
        trPr = t.rows[0]._tr.get_or_add_trPr()
        th = OxmlElement("w:tblHeader")
        th.set(qn("w:val"), "true")
        trPr.append(th)
        if widths:
            for row in t.rows:
                for i, w in enumerate(widths):
                    row.cells[i].width = Cm(w)
        self.doc.add_paragraph().paragraph_format.space_after = Pt(0)
        return t

    # ------------------------------------------------------------ листинги и рисунки
    def listing(self, title, code, size=9):
        self.lst += 1
        cap = self.doc.add_paragraph()
        cap.paragraph_format.space_before = Pt(6)
        cap.paragraph_format.keep_with_next = True
        r = cap.add_run(f"Листинг {self.lst} — {title}")
        r.font.size = Pt(12)
        t = self.doc.add_table(rows=1, cols=1)
        t.style = "Table Grid"
        c = t.rows[0].cells[0]
        self._shade(c, "F3F4F6")
        c.text = ""
        lines = code.rstrip("\n").split("\n")
        p = c.paragraphs[0]
        p.paragraph_format.line_spacing = 1.0
        for i, line in enumerate(lines):
            run = p.add_run(line)
            run.font.name = "Courier New"
            run.font.size = Pt(size)
            if i < len(lines) - 1:
                run.add_break()
        self.doc.add_paragraph()

    def figure(self, path, title, width_cm=16.0):
        self.fig += 1
        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.keep_with_next = True
        p.paragraph_format.space_before = Pt(6)
        p.add_run().add_picture(path, width=Cm(width_cm))
        cap = self.doc.add_paragraph()
        cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        cap.paragraph_format.space_after = Pt(8)
        r = cap.add_run(f"Рисунок {self.fig} — {title}")
        r.font.size = Pt(12)
        return self.fig

    def toc(self):
        p = self.doc.add_paragraph()
        r = p.add_run()
        b = OxmlElement("w:fldChar"); b.set(qn("w:fldCharType"), "begin")
        i = OxmlElement("w:instrText"); i.set(qn("xml:space"), "preserve"); i.text = 'TOC \\o "1-2" \\h \\z \\u'
        s = OxmlElement("w:fldChar"); s.set(qn("w:fldCharType"), "separate")
        t = OxmlElement("w:t"); t.text = "Оглавление обновится при открытии (F9)."
        e = OxmlElement("w:fldChar"); e.set(qn("w:fldCharType"), "end")
        for x in (b, i, s, t, e):
            r._r.append(x)
        # попросить Word обновить поля при открытии
        settings = self.doc.settings.element
        upd = OxmlElement("w:updateFields")
        upd.set(qn("w:val"), "true")
        settings.append(upd)

    def save(self, path):
        self.doc.save(path)
