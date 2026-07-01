import sys
import os

# Add root to sys path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from detector.rules import syn_flood_rule, port_scan_rule
from config.rule_loader import DEFAULT_RULES

class MockPacket:
    def __init__(self, src_ip, dst_port=80, protocol="TCP", tcp_flags="S"):
        self.src_ip = src_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.tcp_flags = tcp_flags

def test_integration():
    print("Testing SYN Flood Rule Config Integration...")
    # Trigger syn flood rule with exactly 10 packets (assuming default threshold is 10)
    for _ in range(9):
        syn_flood_rule(MockPacket(src_ip="192.168.1.100"))
    
    alert = syn_flood_rule(MockPacket(src_ip="192.168.1.100"))
    if alert:
        print(f"PASS: SYN Flood Alert Triggered: {alert}")
    else:
        print("FAIL: SYN Flood Alert Not Triggered")

    print("\nTesting Port Scan Rule Config Integration...")
    # Trigger port scan rule with 10 different ports (assuming default threshold is 10)
    for port in range(1, 10):
        port_scan_rule(MockPacket(src_ip="10.0.0.50", dst_port=port, tcp_flags="S"))
        
    alert2 = port_scan_rule(MockPacket(src_ip="10.0.0.50", dst_port=10, tcp_flags="S"))
    if alert2:
        print(f"PASS: Port Scan Alert Triggered: {alert2}")
    else:
        print("FAIL: Port Scan Alert Not Triggered")

if __name__ == "__main__":
    test_integration()
