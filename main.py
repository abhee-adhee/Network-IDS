from database.database import initialize_database
from capture.engine import start_capture
from sources.pcap_reader import analyze_pcap

def print_banner():

    print("=" * 55)
    print("             Sentinel IDS v0.9")
    print("=" * 55)
    print("Live & Offline Intrusion Detection System")
    print("=" * 55)


def main():

    initialize_database()

    while True:

        print_banner()

        print("\n1. Live Capture")
        print("2. Analyze PCAP")
        print("0. Exit")

        choice = input("\nSelect Option: ").strip()

        if choice == "1":

            start_capture()

        elif choice == "2":

            file_path = input("\nEnter PCAP file path: ").strip()

            analyze_pcap(file_path)

        elif choice == "0":

            print("\nExiting Sentinel IDS...")
            break

        else:

            print("\nInvalid option. Please try again.\n")


if __name__ == "__main__":
    main()
