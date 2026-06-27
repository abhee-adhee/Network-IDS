from flask import Flask, render_template

from database.database import get_all_alerts

app = Flask(__name__)


@app.route("/")
def index():

    alerts = get_all_alerts()

    return render_template(
        "index.html",
        alerts=alerts
    )


if __name__ == "__main__":
    app.run(debug=True)
