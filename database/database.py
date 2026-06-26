import sqlite3

DB_NAME = "ids.db"


def initialize_database():

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        timestamp TEXT,

        alert_type TEXT,

        source_ip TEXT,

        severity TEXT
    )
    """)

    conn.commit()
    conn.close()


def save_alert(alert):

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""

        INSERT INTO alerts
        (timestamp, alert_type, source_ip, severity)

        VALUES (?, ?, ?, ?)

    """, (

        alert["timestamp"],
        alert["type"],
        alert["source"],
        alert["severity"]

    ))

    conn.commit()
    conn.close()
