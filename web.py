from flask import Flask, render_template
from stats.packet_stats import get_statistics
from database.database import (
    get_all_alerts,
    get_total_alerts,
    get_high_alerts,
    get_top_attacker
)

app = Flask(
    __name__,
    template_folder="dashboard/templates",
    static_folder="dashboard/static"
)


@app.route("/")
def home():
    stats = get_statistics()
    alerts = get_all_alerts()

    total = get_total_alerts()

    high = get_high_alerts()

    top = get_top_attacker()

    return render_template(
        "index.html",
        alerts=alerts,
        total=total,
        high=high,
        top=top,
        stats=stats
    )


if __name__ == "__main__":
    app.run(debug=True)
