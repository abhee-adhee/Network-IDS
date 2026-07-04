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
    get_statistics_db,
)


def generate_pdf_report(
    filename="reports/Sentinel_Report.pdf",
    analysis_type="Live Capture",
    pcap_filename=None,
    packets_processed=None,
):

    total  = get_total_alerts()
    high   = get_high_alerts()
    top    = get_top_attacker()
    alerts = get_all_alerts()
    stats  = get_statistics_db()
    generated_at = datetime.now().strftime("%d %B %Y %H:%M:%S")

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
        Paragraph(f"Generated: {generated_at}", styles["Normal"])
    )

    elements.append(Spacer(1, 20))

    # ----------------------------
    # Analysis Information
    # ----------------------------

    elements.append(
        Paragraph("<b>Analysis Information</b>", styles["Heading2"])
    )

    analysis_rows = [
        ["Field", "Value"],
        ["Analysis Type", analysis_type],
        ["Analysis Time", generated_at],
    ]

    if analysis_type != "Live Capture" and pcap_filename:
        analysis_rows.insert(2, ["File Name", pcap_filename])

    if packets_processed is not None:
        analysis_rows.append(["Packets Processed", str(packets_processed)])

    analysis_table = Table(analysis_rows, colWidths=[160, 300])
    analysis_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    elements.append(analysis_table)
    elements.append(Spacer(1, 20))

    # ----------------------------
    # Alert Summary
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

    table = Table(summary, colWidths=[160, 300])

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    elements.append(table)
    elements.append(Spacer(1, 20))

    # ----------------------------
    # Protocol Statistics
    # ----------------------------

    elements.append(
        Paragraph("<b>Protocol Statistics</b>", styles["Heading2"])
    )

    proto_data = [
        ["Protocol / Metric", "Count"],
        ["TCP",          str(stats.get("tcp", 0))],
        ["UDP",          str(stats.get("udp", 0))],
        ["ICMP",         str(stats.get("icmp", 0))],
        ["Total Packets",str(stats.get("total_packets", 0))],
        ["Unique IPs",   str(stats.get("unique_ips", 0))],
    ]

    proto_table = Table(proto_data, colWidths=[160, 300])
    proto_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    elements.append(proto_table)
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

    if len(data) == 1:
        data.append(["—", "No alerts found", "—", "—"])

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
