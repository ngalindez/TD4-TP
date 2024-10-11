import canalruidoso as f  # Correr pip install canalruidoso en la terminal
from scapy.all import *  # Correr pip install scapy en la terminal
from funciones import *

# Parametros
src_ip = '127.0.0.1'
dest_ip = '127.0.0.1'
src_port = 6000
dest_port = 9000

# Apertura de conexión, SYN
envio_paquetes_seguro('S', 6000, 9000)
pkt = listen(6000, 'client')

while not pkt[TCP].flags == 'SA':
    pkt = listen(6000, 'client')

envio_paquetes_seguro('A', 6000, 9000, last_pkt=pkt)

while pkt[TCP].flags != "F":
    pkt = listen(6000, 'client')
    envio_paquetes_seguro('A', 6000, 9000, last_pkt=pkt)
    ...

# FIN + ACK
envio_paquetes_seguro('FA', 6000, 9000, last_pkt=pkt)
