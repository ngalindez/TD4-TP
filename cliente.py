import canalruidoso as f  # Correr pip install canalruidoso en la terminal
from scapy.all import *  # Correr pip install scapy en la terminal
from funciones import *

# Elegimos parametros
src_ip = '127.0.0.1'
dest_ip = '127.0.0.1'
src_port = 6000
dest_port = 9000


envio_paquetes_seguro(11, 0, "S", '127.0.0.1', '127.0.0.1', 6000, 9000)
pkt = listen(6000)
