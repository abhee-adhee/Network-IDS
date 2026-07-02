from scapy.all import rdpcap

from sources.packet_pipeline import process_packet

from database.database import (
    get_statistics_db,
    get_total_alerts,
    get_high_alerts,
    get_top_attacker,
)


def analyze_pcap(file_path):
    """
    Analyze an offline PCAP file.

    Every packet is passed through the same
    processing pipeline used for live capture.
    """

    try:

        packets = rdpcap(file_path)

    except FileNotFoundError:

        print(f"\nPCAP file not found:\n{file_path}")
        return

    except Exception as e:

        print(f"\nUnable to read PCAP:\n{e}")
        return

    total_packets = len(packets)

    stats = get_statistics_db()

    print("\n" + "=" * 55)
    print("        Sentinel PCAP Analysis Summary")
    print("=" * 55)

    print(f"File                : {file_path}")
    print(f"Packets Processed   : {total_packets}")

    print()
    print(f"Total Alerts        : {get_total_alerts()}")
    print(f"High Severity       : {get_high_alerts()}")

    print()
    print("Protocol Statistics")
    print("-" * 25)

    print(f"TCP                 : {stats['tcp']}")
    print(f"UDP                 : {stats['udp']}")
    print(f"ICMP                : {stats['icmp']}")

    print()
    print(f"Unique IPs          : {stats['unique_ips']}")
    print(f"Top Attacker        : {get_top_attacker()}")

    print("\nAnalysis Completed Successfully")
    print("=" * 55)
