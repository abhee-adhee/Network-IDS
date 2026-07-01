from database.database import initialize_database
from capture.engine import start_capture


def print_banner():

    print("=" * 55)
    print("             Sentinel IDS v0.6")
    print("=" * 55)
    print("Real-Time Network Intrusion Detection System")
    print("=" * 55)


def main():

    initialize_database()

    print_banner()

    start_capture()


if __name__ == "__main__":
    main()
