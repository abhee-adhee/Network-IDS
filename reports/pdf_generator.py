from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from database.database import (
    get_total_alerts,
    get_high_alerts,
    get_top_attacker,
    get_all_alerts,
)


def generate_pdf_report(filename="reports/Sentinel_Report.pdf"):

    total = get_total_alerts()
    high = get_high_alerts()
    top = get_top_attacker()
    alerts = get_all_alerts()

    doc = SimpleDocTemplate(filename)

    styles = getSampleStyleSheet()

    elements = []

    # ----------------------------
    # Title
    # ----------------------------

    elements.append(
        Paragraph("<b><font size=22>Sentinel IDS Report</font></b>", styles["Title"])
    )

    elements.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%d %B %Y %H:%M:%S')}",
            styles["Normal"],
        )
    )

    elements.append(Spacer(1, 20))

    # ----------------------------
    # Summary
    # ----------------------------

    elements.append(
        Paragraph("<b>Alert Summary</b>", styles["Heading2"])
    )

    summary = [
        ["Metric", "Value"],
        ["Total Alerts", str(total)],
        ["High Severity", str(high)],
        ["Top Attacker", top],
    ]

    table = Table(summary)

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

                ("GRID", (0, 0), (-1, -1), 1, colors.black),

                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),

                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ]
        )
    )

    elements.append(table)

    elements.append(Spacer(1, 20))

    # ----------------------------
    # Recent Alerts
    # ----------------------------

    elements.append(
        Paragraph("<b>Recent Alerts</b>", styles["Heading2"])
    )

    data = [["Time", "Alert", "Source", "Severity"]]

    for alert in alerts[:20]:

        data.append(
            [
                alert[0],
                alert[1],
                alert[2],
                alert[3],
            ]
        )

    alert_table = Table(data)

    alert_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

                ("GRID", (0, 0), (-1, -1), 1, colors.black),

                ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),

                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]
        )
    )

    elements.append(alert_table)

    elements.append(Spacer(1, 20))

    # ----------------------------
    # Recommendations
    # ----------------------------

    elements.append(
        Paragraph("<b>Recommendations</b>", styles["Heading2"])
    )

    recommendations = [
        "• Investigate repeated HIGH severity alerts.",
        "• Review suspicious source IP addresses.",
        "• Keep firewall and IDS rules updated.",
        "• Monitor the network continuously.",
    ]

    for rec in recommendations:
        elements.append(Paragraph(rec, styles["Normal"]))

    doc.build(elements)

    print(f"\nPDF generated successfully: {filename}")
