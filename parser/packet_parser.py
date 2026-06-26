from scapy.layers.inet import IP, TCP, UDP, ICMP
from parser.models import ParsedPacket


def parse_packet(packet):

    if not packet.haslayer(IP):
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = "UNKNOWN"
    src_port = None
    dst_port = None
    tcp_flags = None

    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
        tcp_flags = str(packet[TCP].flags)

    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    return ParsedPacket(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags
    )
