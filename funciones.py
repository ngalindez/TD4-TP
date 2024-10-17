from scapy.all import TCP, IP
from scapy.all import *
import canalruidoso as f  # Correr pip install canalruidoso en la terminal
import time


def info_packet(packet):
    print(f"Flags: {packet[0][TCP].flags}")
    print(f"#SEQ: {packet[0][TCP].seq}")
    print(f"#ACK: {packet[0][TCP].ack}")



def enviar_pkt(seq_a, ack_a, flags_, dest_ip, source_ip, dest_port, src_port):
    ip = IP(dst=dest_ip, src=source_ip)
    tcp = TCP(dport=dest_port, sport=src_port, flags=flags_, seq=seq_a, ack=ack_a)
    packet = ip/tcp
    info_packet(packet)
    return packet

def escuchar(timeout_, puerto_):
    interface = "Software Loopback Interface 1"

    print(f"Listening for TCP packets on port {puerto_}...")
    filter_str = f"tcp port {puerto_}"

    pkt_capturado = sniff(
        iface=interface, prn=info_packet, count=1, timeout=timeout_, filter=filter_str,)
    return pkt_capturado
