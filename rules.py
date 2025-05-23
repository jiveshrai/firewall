# Sample rules
from scapy.all import IP, TCP, UDP

BLACKLISTED_IPS = {"192.168.1.10", "10.0.0.99"}
BLOCKED_PORTS = {23, 4444, 5555}  # Telnet, common malware ports

def is_blocked(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        if ip_layer.src in BLACKLISTED_IPS or ip_layer.dst in BLACKLISTED_IPS:
            return True

        if packet.haslayer(TCP) and (packet[TCP].dport in BLOCKED_PORTS or packet[TCP].sport in BLOCKED_PORTS):
            return True
        if packet.haslayer(UDP) and (packet[UDP].dport in BLOCKED_PORTS or packet[UDP].sport in BLOCKED_PORTS):
            return True

    return False
