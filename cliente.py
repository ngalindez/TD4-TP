import canalruidoso as f  # Correr pip install canalruidoso en la terminal
from scapy.all import *  # Correr pip install scapy en la terminal

# Elegimos parametros
source_ip = '127.0.0.1'
dest_ip = '127.0.0.1'
dest_port = 8000
src_port = 5000
timeout_ = 3
seq_ = 500

# Creamos la parte de IP

def enviar_pkt(seq_a:int, ack_a:int, flags_):
    ip = IP(dst=dest_ip, src=source_ip)

    # Creamos la parte de TCP
    tcp = TCP(dport=dest_port, sport=src_port, flags = flags_, seq = seq_ + seq_ - seq_a, ack = ack_a + 1)

    # Los combinamos
    packet = ip/tcp
    return packet


def escuchar(timeout_):

# Mostramos todas las interfaces
    print(conf.ifaces)

# Esto lo tienen que completar con el nombre de la interfaz que tenga el 127.0.0.1 si se recibe el paquete en la misma computadora que lo envio.
    interface = "Software Loopback Interface 1"

    listen_port = 8000  # Elegir el puerto que esta escuchando

    print(f"Listening for TCP packets on port {listen_port}...")
    filter_str = f"tcp port {listen_port}"

# Escuchar en ese puerto
    pkt_capturado = sniff(iface=interface, filter=filter_str,
                        prn=lambda x: x.show(), count=1, timeout=timeout_)
    return pkt_capturado

# "Enviamos" el paquete

tcp_pkt = []

while not tcp_pkt or tcp_pkt[0][TCP].ack != seq_ + 1:
    f.envio_paquetes_inseguro(enviar_pkt(seq_, -1, "S"))
    tcp_pkt = escuchar(3)

    
rcv = tcp_pkt[0][TCP]
seq_1 = rcv.seq
seq_ = rcv.ack
tcp_pkt.clear

while not tcp_pkt or tcp_pkt[0][TCP].ack != seq_ + 1:
    f.envio_paquetes_inseguro(enviar_pkt(seq_, seq_1, "A"))
    tcp_pkt = escuchar(3)

