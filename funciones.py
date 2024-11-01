from scapy.all import TCP, IP
from scapy.all import *
import canalruidoso as f  # Correr pip install canalruidoso en la terminal


def info_packet(packet):
    print(f"Flags: {packet[0][TCP].flags}")
    print(f"#SEQ: {packet[0][TCP].seq}")
    print(f"#ACK: {packet[0][TCP].ack}")
    print(f"#Checksum: {packet[0][TCP].chksum}")


def verify_checksum(packet):

    # extraigo el checksum del paquete que me llegó
    chksum0 = packet[TCP].chksum
    packet[TCP].chksum = None  # borro el valor viejo del paquete
    packet = packet.__class__(bytes(packet))  # recalculo el checksum
    chksum1 = packet[TCP].chksum
    # print(f"#Checksum calculado: {packet[TCP].chksum}\n")

    return chksum0 == chksum1


def build_pkt(seq_a, ack_a, flags_, dest_ip, source_ip, dest_port, src_port):
    ip = IP(dst=dest_ip, src=source_ip)
    tcp = TCP(dport=dest_port, sport=src_port,
              flags=flags_, seq=seq_a, ack=ack_a)
    packet = ip/tcp
    return packet


def filter_function(packet, port):
    return packet.haslayer(TCP) and packet[TCP].dport == port


def listen(timeout_, puerto_,interface):

    print(f"Listening for TCP packets on port {puerto_}...\n")

    pkt_capturado = sniff(
        iface=interface,
        prn=info_packet,
        count=1,
        timeout=timeout_,
        lfilter=lambda pkt: filter_function(pkt, puerto_))

    return pkt_capturado
