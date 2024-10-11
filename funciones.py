from scapy.all import *
from scapy.all import TCP, IP
import canalruidoso as f
import time


# Elegimos #SEQ aleatorio para el primer paquete
rand = random.randint(0, 1024)


def envio_paquetes_seguro(flags, src_port, dest_port, src_ip='127.0.0.1', dest_ip='127.0.0.1', last_pkt=IP()/TCP(seq=-1, ack=rand)):
    ip = IP(dst=dest_ip, src=src_ip)
    tcp = TCP(dport=dest_port, sport=src_port, flags=flags,
              seq=last_pkt[TCP].ack, ack=last_pkt[TCP].seq + 1)
    packet = ip/tcp
    f.envio_paquetes_inseguro(packet)

    # # idea, para hacer que espere hasta recibir una respuesta a ese paquete
    # pkt = listen(src_port)
    # while not pkt:
    #     pkt = listen(src_port)
        


def process_packet(packet):
    print(f"\nSource port: {packet[TCP].sport}")
    print(f"Destination port: {packet[TCP].dport}")
    print(f"Flags: {packet[TCP].flags}")
    print(f"#SEQ: {packet[TCP].seq}")
    print(f"#ACK: {packet[TCP].ack}")
    print(f"Checksum: {packet[TCP].chksum}\n")

    # completar con casos para todas las flags

    src_port = packet[TCP].sport
    dest_port = packet[TCP].dport

    # if packet[TCP].flags == 'S':
    #     envio_paquetes_seguro('SA', dest_port, src_port, last_pkt=packet)
    #     # dest_port y src_port están al revés porque esta es la respuesta al paquete anterior
    # if packet[TCP].flags == 'SA':
    #     envio_paquetes_seguro('A', dest_port, src_port, last_pkt=packet)
    # if packet[TCP].flags == 'A':
    #     envio_paquetes_seguro('A', dest_port, src_port, last_pkt=packet)
    # if packet[TCP].flags == 'F':
    #     # acá no quiero hacer nada porque se trata aparte este caso
    # if packet[TCP].flags == 'FA':
    #     envio_paquetes_seguro('A', dest_port, src_port, last_pkt=packet)


def filter_function_server(packet):
    return packet.haslayer(TCP) and packet[TCP].dport == 9000


def filter_function_client(packet):
    return packet.haslayer(TCP) and packet[TCP].dport == 6000


interface = 'lo0'  # macOS


def listen(listen_port, user):
    print(f"Listening for TCP packets on port {listen_port}...")
    pkt_capturado = sniff(
        iface=interface, prn=process_packet, count=1, timeout=60, lfilter=filter_function_server if user == 'server' else filter_function_client)
    return pkt_capturado
