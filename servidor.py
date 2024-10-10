from scapy.all import *
from scapy.all import TCP
import canalruidoso as f  # Correr pip install canalruidoso en la terminal

# Mostramos todas las interfaces
# print(conf.ifaces)


def info_packet(packet):
    print(f"\nSource port: {packet[TCP].sport}")
    print(f"Destination port: {packet[TCP].dport}")
    print(f"Flags: {packet[TCP].flags}")
    print(f"#SEQ: {packet[TCP].seq}")
    print(f"#ACK: {packet[TCP].ack}")
    print(f"Checksum: {packet[TCP].chksum}\n")


def filter_function_server(packet):
    return packet.haslayer(TCP) and packet[TCP].dport == 8000


# Esto lo tienen que completar con el nombre de la interfaz que tenga el 127.0.0.1 si se recibe el paquete en la misma computadora que lo envio.
interface = "lo0"


def listen(listen_port):
    print(f"Listening for TCP packets on port {listen_port}...")
    pkt_capturado = sniff(
        iface=interface, prn=info_packet, count=1, timeout=60, lfilter=filter_function_server)
    return pkt_capturado


listen(8000)
