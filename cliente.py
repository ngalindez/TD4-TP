from funciones import *

# Elegimos parametros
source_ip = '127.0.0.1'
dest_ip = '127.0.0.1'
dest_port = 8000
src_port = 5000
timeout_ = 3
seq_ = 500

tcp_pkt = [[]]

while not tcp_pkt or tcp_pkt[0][TCP].ack != seq_ + 1:
    f.envio_paquetes_inseguro(enviar_pkt(seq_, -1, "S", dest_ip, source_ip, dest_port, src_port, seq_))
    tcp_pkt = escuchar(3, src_port)

rcv = tcp_pkt[0][TCP]
seq_1 = rcv.seq
seq_ = rcv.ack
tcp_pkt.clear

while not tcp_pkt or tcp_pkt[0][TCP].ack != seq_ + 1:
    f.envio_paquetes_inseguro(enviar_pkt(seq_, seq_1, "A"))
    tcp_pkt = escuchar(3, src_port)

