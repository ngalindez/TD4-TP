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


while not servidor.conn_established:
    pkt = servidor.listen()

start_time = time.time()
#servidor.envio_paquetes_seguro('A')

while time.time() - start_time < 20:
    pkt_capturado = servidor.listen()

    # if not servidor.verify_packet(pkt_capturado):
    #     continue

    # servidor.envio_paquetes_seguro('A')

# while True:
#     pkt_capturado = servidor.listen()  # Escucha un último paquete
#     if servidor.verify_packet(pkt_capturado):
#         break
servidor.terminar_conexion()

servidor.mostrar_estadisticas()
