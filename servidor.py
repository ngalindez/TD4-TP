from scapy.all import *
from scapy.all import TCP
import canalruidoso as f  # Correr pip install canalruidoso en la terminal
from funciones import *
import time

# Parámetros
_src_ip = '127.0.0.1'
_dest_ip = '127.0.0.1'
_src_port = 9000
_dest_port = 6000
_interface = 'lo0'

servidor = SocketRDT(_src_ip, _src_port, _dest_ip, _dest_port, _interface)

# pkt = servidor.listen()
while servidor.last_pkt_rcvd == None:
    pkt = servidor.listen()
# servidor.envio_paquetes_seguro('A')
# servidor.listen()
servidor.terminar_conexion()
