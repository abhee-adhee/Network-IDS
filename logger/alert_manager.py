from datetime import datetime
from database.database import save_alert


def raise_alert(alert):

    print("🔥 ALERT MANAGER CALLED 🔥")

    alert["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    print("\n" + "=" * 50)
    print("🚨 SECURITY ALERT")
    print("=" * 50)

    print(f"Time      : {alert['timestamp']}")
    print(f"Type      : {alert['type']}")
    print(f"Source IP : {alert['source']}")
    print(f"Severity  : {alert['severity']}")

    print("=" * 50)

    save_alert(alert)
