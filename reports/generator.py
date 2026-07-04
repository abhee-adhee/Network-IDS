from datetime import datetime

from database.database import (
    get_total_alerts,
    get_high_alerts,
    get_top_attacker,
    get_all_alerts,
    get_statistics_db,
)


def generate_report(
    filename="reports/report.txt",
    analysis_type="Live Capture",
    pcap_filename=None,
    packets_processed=None,
):

    total = get_total_alerts()
    high  = get_high_alerts()
    top   = get_top_attacker()
    alerts = get_all_alerts()
    stats  = get_statistics_db()
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(filename, "w") as f:

        f.write("=" * 60 + "\n")
        f.write("           Sentinel IDS Report\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"Generated     : {generated_at}\n")
        f.write(f"Report Type   : Incident Summary\n\n")

        # ----------------------------
        # Analysis Info
        # ----------------------------
        f.write("Analysis Information\n")
        f.write("-" * 60 + "\n")
        f.write(f"Analysis Type : {analysis_type}\n")

        if analysis_type != "Live Capture" and pcap_filename:
            f.write(f"File Name     : {pcap_filename}\n")

        f.write(f"Analysis Time : {generated_at}\n")

        if packets_processed is not None:
            f.write(f"Packets Proc. : {packets_processed}\n")

        f.write("\n")

        # ----------------------------
        # Alert Summary
        # ----------------------------
        f.write("Alert Summary\n")
        f.write("-" * 60 + "\n")
        f.write(f"Total Alerts  : {total}\n")
        f.write(f"High Severity : {high}\n")
        f.write(f"Top Attacker  : {top}\n\n")

        # ----------------------------
        # Protocol Statistics
        # ----------------------------
        f.write("Protocol Statistics\n")
        f.write("-" * 60 + "\n")
        f.write(f"TCP           : {stats.get('tcp', 0)}\n")
        f.write(f"UDP           : {stats.get('udp', 0)}\n")
        f.write(f"ICMP          : {stats.get('icmp', 0)}\n")
        f.write(f"Total Packets : {stats.get('total_packets', 0)}\n")
        f.write(f"Unique IPs    : {stats.get('unique_ips', 0)}\n\n")

        # ----------------------------
        # Recent Alerts
        # ----------------------------
        f.write("Recent Alerts\n")
        f.write("-" * 60 + "\n")

        if alerts:
            for alert in alerts[:20]:
                f.write(
                    f"{alert[0]} | "
                    f"{alert[1]} | "
                    f"{alert[2]} | "
                    f"{alert[3]}\n"
                )
        else:
            f.write("No alerts found.\n")

        f.write("\n")
        f.write("=" * 60 + "\n")
        f.write("End of Report\n")
        f.write("=" * 60 + "\n")

    print(f"\nReport generated: {filename}")
