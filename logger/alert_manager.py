from datetime import datetime


def raise_alert(alert):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "=" * 50)
    print("🚨 SECURITY ALERT")
    print("=" * 50)

    print(f"Time      : {timestamp}")
    print(f"Type      : {alert['type']}")
    print(f"Source IP : {alert['source']}")
    print(f"Severity  : {alert['severity']}")

    print("=" * 50)
