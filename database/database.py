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
def get_total_alerts():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM alerts")

    total = cursor.fetchone()[0]

    conn.close()

    return total

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
def get_high_alerts():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""

        SELECT COUNT(*)

        FROM alerts

        WHERE severity='HIGH'

    """)

    total = cursor.fetchone()[0]

    conn.close()

    return total
def get_top_attacker():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""

        SELECT source_ip,
               COUNT(*) as hits

        FROM alerts

        GROUP BY source_ip

        ORDER BY hits DESC

        LIMIT 1

    """)

    row = cursor.fetchone()

    conn.close()

    if row:
        return row[0]

    return "None"

def get_all_alerts():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT timestamp,
           alert_type,
           source_ip,
           severity
    FROM alerts
    ORDER BY id DESC
    """)

    alerts = cursor.fetchall()

    conn.close()

    return alerts
