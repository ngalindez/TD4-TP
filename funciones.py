from scapy.all import *
from scapy.all import TCP, IP
import canalruidoso as f
import time


def envio_paquetes_seguro(seq, ack, flags, src_ip, dest_ip, src_port, dest_port):
    ip = IP(dst=dest_ip, src=src_ip)
    tcp = TCP(dport=dest_port, sport=src_port, flags=flags, seq=seq, ack=ack)
    packet = ip/tcp
    f.envio_paquetes_inseguro(packet)


def info_packet(packet):
    print(f"\nSource port: {packet[TCP].sport}")
    print(f"Destination port: {packet[TCP].dport}")
    print(f"Flags: {packet[TCP].flags}")
    print(f"#SEQ: {packet[TCP].seq}")
    print(f"#ACK: {packet[TCP].ack}")
    print(f"Checksum: {packet[TCP].chksum}\n")


def filter_function_server(packet):
    return packet.haslayer(TCP) and packet[TCP].dport == 9000


interface = 'lo0'  # MacOS


def listen(listen_port):
    print(f"Listening for TCP packets on port {listen_port}...")
    pkt_capturado = sniff(
        iface=interface, prn=info_packet, count=1, timeout=60, lfilter=filter_function_server)
    return pkt_capturado
