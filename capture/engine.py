from detector.detector import detect
from parser.packet_parser import parse_packet
from scapy.all import sniff, get_if_list


def list_interfaces():
    return get_if_list()


def handle_packet(packet):

    print("1. Packet arrived")

    parsed = parse_packet(packet)

    print("2. Parser returned:", parsed)

    if parsed:
        print("3. Calling detector")
        detect(parsed)

    print("4. Done")


def start_capture():

    interfaces = list_interfaces()

    print("Available Interfaces:")

    for i, iface in enumerate(interfaces):
        print(f"{i}. {iface}")

    choice = int(input("\nSelect Interface: "))

    selected = interfaces[choice]

    print(f"\nListening on {selected}...\n")

    sniff(
        iface=selected,
        prn=handle_packet,
        store=False
    )
