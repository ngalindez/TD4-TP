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

start_time = time.time()

while servidor.last_pkt_rcvd == None:
    pkt = servidor.listen()
if servidor.conn_established:
    while time.time() - start_time < 5:
        servidor.envio_paquetes_seguro('A')
        pkt_capturado = servidor.listen()
        if pkt_capturado == None:  # se pasó el timeout
            servidor.proporciones['Demorado'] += 1
            print('Paquete demorado')
            servidor.reenviar_ultimo()
    servidor.terminar_conexion()
servidor.mostrar_estadisticas()
