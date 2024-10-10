from scapy.all import *
import canalruidoso as f  # Correr pip install canalruidoso en la terminal
import time


source_ip = '127.0.0.1'
dest_ip = '127.0.0.1'
dest_port = 5000
src_port = 8000
seq_ = 5

def info_packet(packet):
    print(f"\nSource port: {packet[0][TCP].sport}")
    print(f"Destination port: {packet[0][TCP].dport}")
    print(f"Flags: {packet[0][TCP].flags}")
    print(f"#SEQ: {packet[0][TCP].seq}")
    print(f"#ACK: {packet[0][TCP].ack}")
    print(f"Checksum {packet[0][TCP].chksum}\n")
    print(f"Checksum: {packet[0][TCP].chksum}\n")

def enviar_pkt(seq_a, ack_a, flags_):
    ip = IP(dst=dest_ip, src=source_ip)

    # Creamos la parte de TCP
    tcp = TCP(dport=dest_port, sport=src_port, flags = flags_, seq = seq_ + seq_ - seq_a, ack = ack_a + 1)

    # Los combinamos
    packet = ip/tcp
    return packet

def escuchar(timeout_):
    interface = "Software Loopback Interface 1"

    listen_port = 8000  # Elegir el puerto que esta escuchando
    print(f"Listening for TCP packets on port {listen_port}...")
    filter_str = f"tcp port {listen_port}"

    pkt_capturado = sniff(
        iface=interface, prn=lambda x: info_packet, count=1, timeout=timeout_, filter=filter_str,)
    return pkt_capturado



    

# Escuchar en ese puerto
    
    pkt_capturado = sniff(iface=interface, filter=filter_str,
                        prn=lambda x: x.show(), count=1, timeout=timeout_)
    

    return pkt_capturado


tcp_pkt = escuchar(60)

if tcp_pkt:
    seq_1 = tcp_pkt[0][TCP].seq
    

    tcp_pkt.clear
    while not tcp_pkt or tcp_pkt[0][TCP].ack != seq_ + 1:
        f.envio_paquetes_inseguro(enviar_pkt(seq_, seq_1, "SA"))
        tcp_pkt = escuchar(3)

            


timer_ = 20
time.sleep(timer_)

#f timer_ == 20:
#    f.envio_paquetes_inseguro(enviar_pkt(tcp_pkt.ack, tcp_pkt.seq, "F"))

# print(pkt_capturado.stats)
