from scapy.all import IP, TCP, UDP
from netfilterqueue import Packet
from rules import is_blocked
from logger import log_blocked_packet

def process_packet(packet: Packet):
    scapy_packet = IP(packet.get_payload())

    if is_blocked(scapy_packet):
        log_blocked_packet(scapy_packet)
        packet.drop()
    else:
        packet.accept()
