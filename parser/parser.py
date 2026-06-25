from scapy.layers.inet import IP, TCP, UDP, ICMP

def parse_packet(packet):

    if packet.haslayer(IP):
        print("Source:", packet[IP].src)
        print("Destination:", packet[IP].dst)

    if packet.haslayer(TCP):
        print("Protocol: TCP")

    elif packet.haslayer(UDP):
        print("Protocol: UDP")

    elif packet.haslayer(ICMP):
        print("Protocol: ICMP")
