# Detection Rules
from collections import defaultdict

# -----------------------------
# Rule State
# -----------------------------

# Counts SYN packets from each source IP
syn_counter = defaultdict(int)

# Tracks unique destination ports contacted by each source IP
port_scan_tracker = defaultdict(set)


# -----------------------------
# SYN Flood Detection
# -----------------------------

def syn_flood_rule(packet):
    if packet.protocol == "TCP":
        return {
            "type": "TCP Packet",
            "source": packet.src_ip,
            "severity": "LOW"
        }
    if packet.protocol != "TCP":
        return None

    if packet.tcp_flags != "S":
        return None

    syn_counter[packet.src_ip] += 1

    if syn_counter[packet.src_ip] >= 10:
        return {
            "type": "SYN Flood",
            "source": packet.src_ip,
            "severity": "HIGH"
        }

    return None


# -----------------------------
# Port Scan Detection
# -----------------------------

def port_scan_rule(packet):

    if packet.protocol != "TCP":
        return None

    port_scan_tracker[packet.src_ip].add(packet.dst_port)

    if len(port_scan_tracker[packet.src_ip]) >= 10:
        return {
            "type": "Port Scan",
            "source": packet.src_ip,
            "severity": "HIGH"
        }

    return None
