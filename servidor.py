from scapy.all import *
import canalruidoso as f  # Correr pip install canalruidoso en la terminal

# Mostramos todas las interfaces
# print(conf.ifaces)


def info_packet(packet):
    print(f"\nSource port: {packet[TCP].sport}")
    print(f"Destination port: {packet[TCP].dport}")
    print(f"Flags: {packet[TCP].flags}")
    print(f"#SEQ: {packet[TCP].seq}")
    print(f"#ACK: {packet[TCP].ack}")
    print(f"Checksum {packet[TCP].chksum}\n")


# Esto lo tienen que completar con el nombre de la interfaz que tenga el 127.0.0.1 si se recibe el paquete en la misma computadora que lo envio.
interface = "lo0"

listen_port = 8000  # Elegir el puerto que esta escuchando

print(f"Listening for TCP packets on port {listen_port}...")
filter_str = f"tcp port {listen_port}"

# Escuchar en ese puerto
pkt_capturado = sniff(
    iface=interface, prn=info_packet, count=1, timeout=60)
