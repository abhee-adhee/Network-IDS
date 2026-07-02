from collections import defaultdict
from database.database import update_statistics_db
# -------------------------
# Global Statistics
# -------------------------

total_packets = 0

protocol_counter = defaultdict(int)

unique_ips = set()


# -------------------------
# Update Statistics
# -------------------------

def update_statistics(packet):

    global total_packets

    total_packets += 1

    protocol_counter[packet.protocol] += 1

    unique_ips.add(packet.src_ip)

    # Persist latest statistics to SQLite
    update_statistics_db(
        total_packets,
        protocol_counter["TCP"],
        protocol_counter["UDP"],
        protocol_counter["ICMP"],
        len(unique_ips)
    )


# -------------------------
# Get Statistics
# -------------------------

def get_statistics():

    return {

        "total_packets": total_packets,

        "tcp": protocol_counter["TCP"],

        "udp": protocol_counter["UDP"],

        "icmp": protocol_counter["ICMP"],

        "unique_ips": len(unique_ips)

    }

