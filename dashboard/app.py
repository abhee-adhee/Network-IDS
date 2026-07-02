import os
from collections import Counter
from flask import Flask, render_template, jsonify, send_file, request

from database.database import get_all_alerts, get_total_alerts, get_high_alerts, get_top_attacker
from database.database import (
    get_all_alerts,
    get_total_alerts,
    get_high_alerts,
    get_top_attacker,
    get_statistics_db
)
from reports.generator import generate_report
from reports.pdf_generator import generate_pdf_report
from config.rule_loader import load_rules, save_rules

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/settings", methods=["GET", "POST"])
def settings():
    success_msg = None
    error_msg = None
    
    # Load current rules
    rules = load_rules()
    print("DEBUG:", rules)
    if request.method == "POST":
        try:
            # Parse form data and validate
            new_rules = {
                "syn_flood": {
                    "enabled": request.form.get("syn_flood_enabled") == "on",
                    "threshold": int(request.form.get("syn_flood_threshold", 10)),
                    "severity": request.form.get("syn_flood_severity", "HIGH")
                },
                "port_scan": {
                    "enabled": request.form.get("port_scan_enabled") == "on",
                    "threshold": int(request.form.get("port_scan_threshold", 10)),
                    "severity": request.form.get("port_scan_severity", "HIGH")
                }
            }
            
            # Validation
            valid_severities = ["LOW", "MEDIUM", "HIGH"]
            is_valid = True
            
            for rule_name, config in new_rules.items():
                if config["threshold"] < 1 or config["threshold"] > 10000:
                    error_msg = f"Invalid threshold for {rule_name.replace('_', ' ').title()}. Must be between 1 and 10000."
                    is_valid = False
                    break
                if config["severity"] not in valid_severities:
                    error_msg = f"Invalid severity for {rule_name.replace('_', ' ').title()}."
                    is_valid = False
                    break
            
            if is_valid:
                # Save rules
                saved = save_rules(new_rules)
                if saved:
                    success_msg = "Configuration Saved Successfully"
                    rules = new_rules  # Update template with new values
                else:
                    error_msg = "Unable to save configuration"
                    
        except ValueError:
            error_msg = "Invalid threshold value. Please enter a valid number."
            
    return render_template("settings.html", rules=rules, success_msg=success_msg, error_msg=error_msg)



@app.route("/api/dashboard-data")
def dashboard_data():
    alerts = get_all_alerts()
    total_alerts = get_total_alerts()
    high_alerts = get_high_alerts()
    top_attacker = get_top_attacker()
    stats = get_statistics_db()

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
