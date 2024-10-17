import canalruidoso as f  # Correr pip install canalruidoso en la terminal
from scapy.all import *  # Correr pip install scapy en la terminal
from funciones import *

# Parametros
_src_ip = '127.0.0.1'
_dest_ip = '127.0.0.1'
_src_port = 6000
_dest_port = 9000
_interface = 'lo0'

cliente = SocketRDT(_src_ip, _src_port, _dest_ip, _dest_port, _interface)
cliente.iniciar_conexion()
while cliente.conn_established:
    cliente.listen()
    if not cliente.conn_established:
        break
    cliente.envio_paquetes_seguro('A')
