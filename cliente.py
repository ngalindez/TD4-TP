import canalruidoso as f  # Correr pip install canalruidoso en la terminal
from scapy.all import *  # Correr pip install scapy en la terminal
import time

# Elegimos parametros
src_ip = '127.0.0.1'
dest_ip = '127.0.0.1'
src_port = 5000
dest_port = 8000

# Creamos la parte de IP
ip = IP(dst=dest_ip, src=src_ip)

# Creamos la parte de TCP
tcp = TCP(dport=dest_port, sport=src_port, flags="S")


# Los combinamos
packet = ip/tcp


def envio_paquetes_seguro(seq, ack, flags, src_ip, dest_ip, src_port, dest_port):
    ip = IP(dst=dest_ip, src=src_ip)
    tcp = TCP(dport=dest_port, sport=src_port, flags=flags, seq=seq, ack=ack)
    packet = ip/tcp
    f.envio_paquetes_inseguro(packet)


envio_paquetes_seguro(11, 0, "S", '127.0.0.1', '127.0.0.1', 5000, 8000)
