from parser.packet_parser import parse_packet
from detector.detector import detect
from stats.packet_stats import update_statistics


def process_packet(packet):
    """
    Shared packet processing pipeline.

    Accepts a raw Scapy packet and performs:

    Packet Parsing
        ↓
    Statistics Update
        ↓
    Detection
    """

    parsed = parse_packet(packet)

    if parsed is None:
        return None

    update_statistics(parsed)

    detect(parsed)

    return parsed
