from utils import current_timestamp
from scapy.all import IP, TCP, UDP


def log_blocked_packet(packet):
    print(f"\n[!] Blocked Packet at {current_timestamp()}:")
    print(f"    Source IP      : {packet[IP].src}")
    print(f"    Destination IP : {packet[IP].dst}")
    if packet.haslayer(TCP):
        print(f"    Protocol       : TCP")
        print(f"    Src Port       : {packet[TCP].sport}")
        print(f"    Dst Port       : {packet[TCP].dport}")
    elif packet.haslayer(UDP):
        print(f"    Protocol       : UDP")
        print(f"    Src Port       : {packet[UDP].sport}")
        print(f"    Dst Port       : {packet[UDP].dport}")

    with open("blocked_packets.log", "a") as f:
        f.write(f"{current_timestamp()} - BLOCKED: {packet.summary()}\n")
