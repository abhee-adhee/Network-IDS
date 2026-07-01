# Detection Rules

from collections import defaultdict
from config.rule_loader import load_rules

# Load rules configuration once
rules = load_rules()

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

    rule_config = rules.get("syn_flood", {})
    
    if not rule_config.get("enabled", True):
        return None

    # Only inspect TCP packets
    if packet.protocol != "TCP":
        return None

    # Only SYN packets
    if packet.tcp_flags != "S":
        return None

    syn_counter[packet.src_ip] += 1

    if syn_counter[packet.src_ip] >= rule_config.get("threshold", 10):

        return {
            "type": "SYN Flood",
            "source": packet.src_ip,
            "severity": rule_config.get("severity", "HIGH")
        }

    return None


# -----------------------------
# Port Scan Detection
# -----------------------------

def port_scan_rule(packet):

    rule_config = rules.get("port_scan", {})
    
    if not rule_config.get("enabled", True):
        return None

    # Only inspect TCP packets
    if packet.protocol != "TCP":
        return None

    # Ignore packets without a destination port
    if packet.dst_port is None:
        return None

    # Store unique destination ports contacted by this source
    port_scan_tracker[packet.src_ip].add(packet.dst_port)

    if len(port_scan_tracker[packet.src_ip]) >= rule_config.get("threshold", 10):

        return {
            "type": "Port Scan",
            "source": packet.src_ip,
            "severity": rule_config.get("severity", "HIGH")
        }

    return None