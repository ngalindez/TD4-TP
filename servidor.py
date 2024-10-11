from scapy.all import *
from scapy.all import TCP
import canalruidoso as f  # Correr pip install canalruidoso en la terminal
from funciones import *
import time

# Parámetros
src_ip = '127.0.0.1'
dest_ip = '127.0.0.1'
src_port = 9000
dest_port = 6000

while not pkt or pkt[TCP].flags != 'S':
    pkt = listen(9000, 'server')

# SYN + ACK
envio_paquetes_seguro('SA', 9000, 6000, last_pkt=pkt)

while not pkt[TCP].flags == 'A':
    pkt = listen(9000, 'server')

# ya recibí un paquete con ACK, arranco el timer de conexión
ahora = time.time()

while time.time() < ahora + 20:
    ...

# Cierre de conexión, FIN
envio_paquetes_seguro('F', 9000, 6000, last_pkt=pkt)

while not pkt[TCP].flags == 'FA':
    pkt = listen(9000, 'server')

# ACK final
envio_paquetes_seguro('A', 9000, 6000, last_pkt=pkt)
