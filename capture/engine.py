from scapy.all import sniff, get_if_list

def list_interfaces():
    return get_if_list()

def start_capture():
    interfaces = list_interfaces()

    print("Available Interfaces:")

    for i, iface in enumerate(interfaces):
        print(f"{i}. {iface}")

    choice = int(input("Select Interface: "))
    selected = interfaces[choice]

    print(f"Capturing on {selected}...")

    sniff(
        iface=selected,
        prn=lambda pkt: pkt.summary(),
        store=False
    )
