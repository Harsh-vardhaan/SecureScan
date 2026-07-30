"""In-memory PDF generation for normalized SecureScan report contexts."""

from copy import deepcopy
from html import escape
from io import BytesIO
from typing import Any, Dict, Iterable, List

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


REPORT_VERSION = "1.0"
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")
SEVERITY_COLORS = {
    "Critical": "#991B1B",
    "High": "#DC2626",
    "Medium": "#D97706",
    "Low": "#0369A1",
    "Info": "#475569",
}


def _safe_text(value: Any, default: str = "N/A") -> str:
    """Return escaped text suitable for a ReportLab Paragraph."""
    if value is None:
        return default
    rendered = str(value).strip()
    return escape(rendered) if rendered else default


def _mapping(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _styles() -> Dict[str, ParagraphStyle]:
    """Build readable styles using standard built-in fonts only."""
    sample = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "SecureScanTitle", parent=sample["Title"], fontName="Helvetica-Bold",
            fontSize=24, leading=29, textColor=colors.HexColor("#0F172A"),
            alignment=TA_CENTER, spaceAfter=8,
        ),
        "subtitle": ParagraphStyle(
            "SecureScanSubtitle", parent=sample["Normal"], fontName="Helvetica",
            fontSize=11, leading=15, textColor=colors.HexColor("#475569"),
            alignment=TA_CENTER, spaceAfter=5,
        ),
        "heading": ParagraphStyle(
            "SecureScanHeading", parent=sample["Heading2"], fontName="Helvetica-Bold",
            fontSize=15, leading=19, textColor=colors.HexColor("#075985"),
            spaceBefore=10, spaceAfter=8, keepWithNext=1,
        ),
        "finding": ParagraphStyle(
            "SecureScanFinding", parent=sample["Heading3"], fontName="Helvetica-Bold",
            fontSize=11, leading=14, textColor=colors.HexColor("#0F172A"),
            spaceAfter=5, keepWithNext=1,
        ),
        "body": ParagraphStyle(
            "SecureScanBody", parent=sample["BodyText"], fontName="Helvetica",
            fontSize=9, leading=13, textColor=colors.HexColor("#1E293B"),
            spaceAfter=6,
        ),
        "small": ParagraphStyle(
            "SecureScanSmall", parent=sample["BodyText"], fontName="Helvetica",
            fontSize=7.5, leading=10, textColor=colors.HexColor("#334155"),
        ),
        "table_header": ParagraphStyle(
            "SecureScanTableHeader", parent=sample["Normal"], fontName="Helvetica-Bold",
            fontSize=7.5, leading=9, textColor=colors.white,
        ),
    }


def _section(title: str, styles: Dict[str, ParagraphStyle]) -> Paragraph:
    return Paragraph(_safe_text(title), styles["heading"])


def _detail_table(
    rows: Iterable[tuple[str, Any]],
    styles: Dict[str, ParagraphStyle],
    widths: tuple[float, float] = (46 * mm, 126 * mm),
) -> Table:
    """Create a wrapped two-column label/value table."""
    data = [
        [
            Paragraph(f"<b>{_safe_text(label)}</b>", styles["body"]),
            Paragraph(_safe_text(value), styles["body"]),
        ]
        for label, value in rows
    ]
    table = Table(data, colWidths=list(widths), hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E0F2FE")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _footer(canvas: Any, document: Any, generated_at: str) -> None:
    """Draw report version, timestamp, and page number."""
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
    canvas.line(document.leftMargin, 13 * mm, A4[0] - document.rightMargin, 13 * mm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#475569"))
    canvas.drawString(document.leftMargin, 9 * mm, f"SecureScan - Report version {REPORT_VERSION}")
    canvas.drawCentredString(A4[0] / 2, 9 * mm, generated_at)
    canvas.drawRightString(A4[0] - document.rightMargin, 9 * mm, f"Page {document.page}")
    canvas.restoreState()


def generate_pdf_report(report_context: Dict[str, Any]) -> bytes:
    """Return an A4 PDF from normalized report context without filesystem writes.

    The function has no Flask, SQLite, scanner, or analyzer dependencies and
    does not mutate ``report_context``.
    """
    if not isinstance(report_context, dict):
        raise ValueError("report_context must be a dictionary")

    context = deepcopy(report_context)
    metadata = _mapping(context.get("metadata"))
    target = _mapping(context.get("target"))
    severity_counts = _mapping(context.get("severity_counts"))
    ports = _items(context.get("open_ports"))
    findings = _items(context.get("findings"))
    recommendations = _items(context.get("recommendations"))
    limitations = context.get("limitations")
    if not isinstance(limitations, list):
        limitations = []

    styles = _styles()
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer, pagesize=A4, rightMargin=19 * mm, leftMargin=19 * mm,
        topMargin=18 * mm, bottomMargin=20 * mm,
        title=f"SecureScan Report {metadata.get('report_id', 'N/A')}",
        author="SecureScan", subject="Authorized vulnerability assessment report",
    )
    story: List[Any] = [
        Paragraph("SecureScan", styles["title"]),
        Paragraph("Automated Vulnerability Assessment Platform", styles["subtitle"]),
        Spacer(1, 5 * mm),
        Paragraph("Professional Vulnerability Assessment Report", styles["title"]),
        Spacer(1, 4 * mm),
        _detail_table(
            [
                ("Report ID", metadata.get("report_id")),
                ("Report version", metadata.get("report_version", REPORT_VERSION)),
                ("Generated", metadata.get("generated_at")),
                ("Target", target.get("name")),
                ("Overall risk", context.get("overall_risk", "Info")),
                (
                    "Classification",
                    metadata.get("classification", "Authorized Security Assessment"),
                ),
            ],
            styles,
        ),
        Spacer(1, 7 * mm),
        _section("Authorization and Scope", styles),
        Paragraph(
            "This report documents an <b>authorized, limited network assessment</b>. "
            "The recorded scan covered the top 100 TCP ports with limited service-version "
            "probing. No exploitation was performed.",
            styles["body"],
        ),
        _section("Executive Summary", styles),
        Paragraph(_safe_text(context.get("executive_summary")), styles["body"]),
        _section("Assessment Details", styles),
        _detail_table(
            [
                ("Database scan ID", metadata.get("scan_id")),
                ("Target", target.get("name")),
                ("Hostname", target.get("hostname")),
                ("Resolved address", target.get("resolved_address")),
                ("Host status", target.get("host_status")),
                ("Scan start time", metadata.get("scan_started_at")),
                ("Duration", f"{_safe_text(target.get('scan_duration_seconds'), '0')} seconds"),
                ("Overall risk", context.get("overall_risk", "Info")),
            ],
            styles,
        ),
        _section("Severity Summary", styles),
    ]

    severity_data = [
        [Paragraph(level, styles["table_header"]) for level in SEVERITY_ORDER],
        [
            Paragraph(
                f'<font color="{SEVERITY_COLORS[level]}"><b>'
                f'{_safe_text(severity_counts.get(level), "0")}</b></font>',
                styles["body"],
            )
            for level in SEVERITY_ORDER
        ],
    ]
    severity_table = Table(severity_data, colWidths=[34.4 * mm] * 5, repeatRows=1)
    severity_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend([severity_table, Spacer(1, 4 * mm), _section("Open Ports", styles)])

    if ports:
        headers = ("Port", "Protocol", "State", "Service", "Product", "Version")
        port_data = [[Paragraph(header, styles["table_header"]) for header in headers]]
        for port in ports:
            port_data.append(
                [
                    Paragraph(_safe_text(port.get("port"), "0"), styles["small"]),
                    Paragraph(_safe_text(port.get("protocol")), styles["small"]),
                    Paragraph(_safe_text(port.get("state")), styles["small"]),
                    Paragraph(_safe_text(port.get("service")), styles["small"]),
                    Paragraph(_safe_text(port.get("product")), styles["small"]),
                    Paragraph(_safe_text(port.get("version")), styles["small"]),
                ]
            )
        port_table = Table(
            port_data,
            colWidths=[15 * mm, 20 * mm, 18 * mm, 32 * mm, 50 * mm, 37 * mm],
            repeatRows=1,
        )
        port_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#075985")),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(port_table)
    else:
        story.append(
            Paragraph(
                "No open ports were recorded within the limited top-100 TCP-port scan scope.",
                styles["body"],
            )
        )

    story.append(_section("Security Findings", styles))
    if findings:
        for index, finding in enumerate(findings, start=1):
            story.append(
                Paragraph(
                    f"{index}. {_safe_text(finding.get('title'), 'Security observation')} "
                    f"({_safe_text(finding.get('rule_id'), 'UNKNOWN')})",
                    styles["finding"],
                )
            )
            port_protocol = (
                f"{_safe_text(finding.get('protocol'), 'TCP')}/"
                f"{_safe_text(finding.get('port'), '0')}"
            )
            story.extend(
                [
                    _detail_table(
                        [
                            ("Severity", finding.get("severity")),
                            ("Category", finding.get("category")),
                            ("Port / protocol", port_protocol),
                            ("Confidence", finding.get("confidence")),
                        ],
                        styles,
                        widths=(38 * mm, 134 * mm),
                    ),
                    Spacer(1, 2 * mm),
                    Paragraph(
                        f"<b>Description:</b> {_safe_text(finding.get('description'))}",
                        styles["body"],
                    ),
                    Paragraph(
                        f"<b>Evidence:</b> {_safe_text(finding.get('evidence'))}",
                        styles["body"],
                    ),
                    Paragraph(
                        f"<b>Recommendation:</b> {_safe_text(finding.get('recommendation'))}",
                        styles["body"],
                    ),
                    Spacer(1, 4 * mm),
                ]
            )
    else:
        story.append(
            Paragraph(
                "No rule-based security concerns were recorded for this limited assessment. "
                "This does not prove that the target is fully secure.",
                styles["body"],
            )
        )

    story.append(_section("Prioritized Recommendations", styles))
    if recommendations:
        rank = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
        prioritized = sorted(
            recommendations,
            key=lambda item: rank.get(str(item.get("severity")), len(SEVERITY_ORDER)),
        )
        for index, item in enumerate(prioritized, start=1):
            affected_service = (
                f"{_safe_text(item.get('protocol'), 'TCP')}/"
                f"{_safe_text(item.get('port'), '0')}"
            )
            story.append(
                Paragraph(
                    f"<b>{index}. [{_safe_text(item.get('severity'), 'Info')}] "
                    f"{_safe_text(item.get('title'), 'Security observation')} "
                    f"({affected_service})</b><br/>"
                    f"{_safe_text(item.get('recommendation'))}",
                    styles["body"],
                )
            )
    else:
        story.append(
            Paragraph(
                "No finding-specific recommendations were generated. "
                "Continue routine monitoring and security review.",
                styles["body"],
            )
        )

    story.append(_section("Limitations", styles))
    if limitations:
        for limitation in limitations:
            story.append(Paragraph(f"- {_safe_text(limitation)}", styles["body"]))
    else:
        story.append(Paragraph("No additional limitations were recorded.", styles["body"]))

    story.extend(
        [
            _section("Disclaimer", styles),
            Paragraph(_safe_text(context.get("disclaimer")), styles["body"]),
        ]
    )
    generated_at = str(metadata.get("generated_at") or "N/A")

    def footer_callback(canvas: Any, doc: Any) -> None:
        _footer(canvas, doc, generated_at)

    document.build(story, onFirstPage=footer_callback, onLaterPages=footer_callback)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
