from detector.detector import detect
from parser.packet_parser import parse_packet
from scapy.all import sniff, get_if_list
from stats.packet_stats import update_statistics

# ---------------------------------
# Configuration
# ---------------------------------

DEBUG = False


# ---------------------------------
# Interface Discovery
# ---------------------------------

def list_interfaces():
    return get_if_list()


# ---------------------------------
# Packet Handler
# ---------------------------------

def handle_packet(packet):

    parsed = parse_packet(packet)

    # Ignore unsupported packets
    if parsed is None:
        return

    if DEBUG:
        print(parsed)

    update_statistics(parsed)

    detect(parsed)


# ---------------------------------
# Capture Engine
# ---------------------------------

def start_capture():

    interfaces = list_interfaces()

    print("\nAvailable Interfaces:\n")

    for i, iface in enumerate(interfaces):
        print(f"  {i}. {iface}")

    while True:

        try:

            choice = int(input("\nSelect Interface: "))

            if 0 <= choice < len(interfaces):
                break

            print("Invalid selection.")

        except ValueError:

            print("Please enter a valid number.")

    selected = interfaces[choice]

    print("\n" + "=" * 55)
    print(f"Monitoring Interface : {selected}")
    print("Status               : RUNNING")
    print("Press Ctrl+C to stop.")
    print("=" * 55 + "\n")

    try:

        sniff(
            iface=selected,
            prn=handle_packet,
            store=False
        )

    except KeyboardInterrupt:

        print("\n")
        print("=" * 55)
        print("Capture stopped.")
        print("Thank you for using Sentinel IDS.")
        print("=" * 55)
