from scapy.all import rdpcap

from sources.packet_pipeline import process_packet


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

    print("\n" + "=" * 55)
    print("Offline PCAP Analysis")
    print("=" * 55)
    print(f"File          : {file_path}")
    print(f"Total Packets : {total_packets}")
    print("=" * 55 + "\n")

    for index, packet in enumerate(packets, start=1):

        process_packet(packet)

        if index % 100 == 0 or index == total_packets:
            print(f"Processed {index}/{total_packets} packets")

    print("\n" + "=" * 55)
    print("PCAP Analysis Complete")
    print("=" * 55)
