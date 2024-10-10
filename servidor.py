from scapy.all import *
from scapy.all import TCP
import canalruidoso as f  # Correr pip install canalruidoso en la terminal
from funciones import *

# Parámetros
src_ip = '127.0.0.1'
dest_ip = '127.0.0.1'
src_port = 9000
dest_port = 6000

pkt = listen(9000)
envio_paquetes_seguro(500, pkt[TCP].seq + 1, "SA",
                      src_ip, dest_ip, src_port, dest_port)
