"""PDF rendering of the configuration change audit (reportlab)."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

from .audit import DEFAULT_AUDIT_FIELDS, _format_time, audit_fields, audit_text, report_fields, report_period, severity_summary
from .i18n import language_of, tr


FONT_DIR = Path(__file__).resolve().parent / "fonts"
FONT = "LibreOXISans"
FONT_BOLD = "LibreOXISans-Bold"
SEVERITY_COLOR = {"low": "#6c757d", "medium": "#d39e00", "high": "#fd7e14", "critical": "#dc3545"}


def _register_fonts() -> None:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    if FONT in pdfmetrics.getRegisteredFontNames():
        return
    # DejaVu Sans covers Slovak diacritics (the reportlab built-in fonts do not).
    pdfmetrics.registerFont(TTFont(FONT, str(FONT_DIR / "DejaVuSans.ttf")))
    pdfmetrics.registerFont(TTFont(FONT_BOLD, str(FONT_DIR / "DejaVuSans-Bold.ttf")))


def build_pdf(settings, report: dict, subject: str) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from xml.sax.saxutils import escape
    from django.utils import timezone

    _register_fonts()
    lang = language_of(settings)
    base = ParagraphStyle("base", fontName=FONT, fontSize=8.5, leading=11)
    small = ParagraphStyle("small", parent=base, fontSize=8, textColor=colors.HexColor("#495057"))
    header = ParagraphStyle("header", parent=base, fontName=FONT_BOLD, textColor=colors.HexColor("#212529"))
    title = ParagraphStyle("title", parent=base, fontName=FONT_BOLD, fontSize=15, leading=19, spaceAfter=2)
    device_title = ParagraphStyle("device", parent=base, fontName=FONT_BOLD, fontSize=11, leading=14, spaceBefore=8)
    badge = ParagraphStyle("badge", parent=base, fontName=FONT_BOLD, textColor=colors.white, alignment=TA_CENTER)

    fields = [field for field in report_fields(settings) if field != "ip"]
    labels = dict(audit_fields(lang))
    widths = {"time": 35 * mm, "severity": 23 * mm, "category": 40 * mm, "old": 55 * mm, "new": 55 * mm}
    page_width = landscape(A4)[0] - 24 * mm
    change_width = page_width - sum(widths.get(field, 0) for field in fields if field != "change")
    widths["change"] = max(change_width, 60 * mm)

    period = report_period(settings, report)
    summary = severity_summary(report, lang)
    generated = timezone.localtime().strftime(getattr(settings, "datetime_format", "%d.%m.%Y %H:%M:%S"))

    story = [
        Paragraph(escape(tr("report.title", lang)), title),
        Paragraph(escape(tr("report.period", lang, period=period) + "    ·    " + tr("report.generated", lang, time=generated)), small),
        Spacer(1, 3 * mm),
        Paragraph(
            escape(
                tr("report.changes", lang, total=report["total"]) + (f" ({summary})" if summary else "")
                + "    ·    " + tr("report.devices", lang, count=len(report["devices"]))
            ),
            header,
        ),
        Spacer(1, 2 * mm),
    ]
    if not report["devices"]:
        story.append(Paragraph(escape(tr("report.no_changes", lang)), base))

    for device in report["devices"]:
        name = device["name"] + (f" ({device['ip']})" if device.get("ip") and "ip" in (getattr(settings, "audit_fields", None) or DEFAULT_AUDIT_FIELDS) else "")
        story.append(Paragraph(escape(name), device_title))
        for author in device.get("authors", []):
            story.append(Paragraph(escape(tr("report.saved_by", lang, author=author)), small))
        story.append(Spacer(1, 1.5 * mm))

        rows = [[Paragraph(escape(labels[field]), header) for field in fields]]
        styles = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e9ecef")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#dee2e6")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for index, change in enumerate(device["changes"], start=1):
            row = []
            for column, field in enumerate(fields):
                if field == "time":
                    value = _format_time(change["when"], settings)
                elif field == "severity":
                    row.append(Paragraph(escape(change["severity_label"]), badge))
                    styles.append(("BACKGROUND", (column, index), (column, index), colors.HexColor(SEVERITY_COLOR[change["severity"]])))
                    continue
                elif field == "category":
                    value = change["category_label"]
                elif field == "change":
                    value = audit_text(change, lang)
                else:
                    value = change.get(field, "")
                row.append(Paragraph(escape(str(value)), base))
            rows.append(row)
        table = Table(rows, colWidths=[widths[field] for field in fields], repeatRows=1)
        table.setStyle(TableStyle(styles))
        story.append(table)

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont(FONT, 7.5)
        canvas.setFillColor(colors.HexColor("#6c757d"))
        canvas.drawString(12 * mm, 8 * mm, subject[:150])
        canvas.drawRightString(landscape(A4)[0] - 12 * mm, 8 * mm, tr("report.page", lang, page=doc.page))
        canvas.restoreState()

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        leftMargin=12 * mm,
        rightMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=14 * mm,
        title=subject,
        author="NetBox LibreOXI",
    )
    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
