from funciones import *

# Elegimos parametros
source_ip = '192.168.56.1'
dest_ip = '192.168.56.1'
dest_port = 8000
src_port = 5000
seq_ = 500

tcp_pkt = None


while not tcp_pkt or (TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack < seq_ + 1):
    enviar_thread = threading.Thread(
        target=f.envio_paquetes_inseguro,  # Pasamos la función sin ejecutar
        args=(enviar_pkt(seq_, -1, "S", dest_ip, source_ip, dest_port, src_port),)  # Pasamos los argumentos a la función
    )
    
    # Inicia el hilo de envío de paquetes
    enviar_thread.start()
    tcp_pkt = escuchar(3, src_port)
    
    if tcp_pkt:
        info_packet(tcp_pkt[0][TCP]) 

rcv = tcp_pkt[0][TCP]
seq_1 = rcv.seq
seq_ = rcv.ack
tcp_pkt = None

while not tcp_pkt or (TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack < seq_ + 1):
    enviar_thread = threading.Thread(
        target=f.envio_paquetes_inseguro,  # Pasamos la función sin ejecutar
        args=(enviar_pkt(seq_, seq_1, "A", dest_ip, source_ip, dest_port, src_port),)  # Pasamos los argumentos a la función
    )
    
    # Inicia el hilo de envío de paquetes
    enviar_thread.start()
    tcp_pkt = escuchar(3, src_port)


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
print(cliente.conn_established)
while cliente.conn_established:
    cliente.listen()
    if not cliente.conn_established:
        break
    cliente.envio_paquetes_seguro('A')

