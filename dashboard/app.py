import os
from collections import Counter
from flask import Flask, render_template, jsonify, send_file

from database.database import get_all_alerts, get_total_alerts, get_high_alerts, get_top_attacker
from stats.packet_stats import get_statistics
from reports.generator import generate_report
from reports.pdf_generator import generate_pdf_report

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/dashboard-data")
def dashboard_data():
    alerts = get_all_alerts()
    total_alerts = get_total_alerts()
    high_alerts = get_high_alerts()
    top_attacker = get_top_attacker()
    stats = get_statistics()

    # Calculate Medium and Low alerts from all alerts (format: [timestamp, type, ip, severity])
    medium_alerts = sum(1 for alert in alerts if alert[3] == "MEDIUM")
    low_alerts = sum(1 for alert in alerts if alert[3] == "LOW")

    # Data for Timeline (Counts per alert type or simply recent alerts over time)
    # To simplify, let's just count alerts per day/hour, or just pass recent alerts directly.
    # We will pass raw data and let the frontend do simple grouping.
    
    # Protocol distribution
    protocols = {
        "TCP": stats.get("tcp", 0),
        "UDP": stats.get("udp", 0),
        "ICMP": stats.get("icmp", 0)
    }

    # Severity distribution
    severities = {
        "HIGH": high_alerts,
        "MEDIUM": medium_alerts,
        "LOW": low_alerts
    }

    # Top Attackers for Bar Chart (Top 5)
    attacker_counts = Counter([alert[2] for alert in alerts])
    top_5_attackers = dict(attacker_counts.most_common(5))

    return jsonify({
        "stats": stats,
        "alert_stats": {
            "total": total_alerts,
            "high": high_alerts,
            "medium": medium_alerts,
            "low": low_alerts
        },
        "top_attacker": top_attacker,
        "recent_alerts": alerts[:100],  # send up to 100 recent alerts for the table
        "charts": {
            "protocols": protocols,
            "severities": severities,
            "top_attackers": top_5_attackers
        }
    })


@app.route("/export/txt")
def export_txt():
    report_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "reports", "report.txt"))
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    generate_report(filename=report_path)
    return send_file(report_path, as_attachment=True)


@app.route("/export/pdf")
def export_pdf():
    report_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "reports", "Sentinel_Report.pdf"))
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    generate_pdf_report(filename=report_path)
    return send_file(report_path, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
