from datetime import datetime

from database.database import (
    get_total_alerts,
    get_high_alerts,
    get_top_attacker,
    get_all_alerts,
)


def generate_report(filename="reports/report.txt"):

    total = get_total_alerts()
    high = get_high_alerts()
    top = get_top_attacker()
    alerts = get_all_alerts()

    with open(filename, "w") as f:

        f.write("=" * 60 + "\n")
        f.write("           Sentinel IDS Report\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"Generated : {datetime.now()}\n\n")

        f.write("Summary\n")
        f.write("-" * 60 + "\n")

        f.write(f"Total Alerts : {total}\n")
        f.write(f"High Alerts  : {high}\n")
        f.write(f"Top Attacker : {top}\n\n")

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
