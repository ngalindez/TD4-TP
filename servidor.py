from funciones import *

source_ip = '127.0.0.1'
dest_ip = '127.0.0.1'
dest_port = 5000
src_port = 8000
seq_ = 5

tcp_pkt = escuchar(60)

if tcp_pkt:
    seq_1 = tcp_pkt[0][TCP].seq
    
    tcp_pkt.clear
    while not tcp_pkt or tcp_pkt[0][TCP].ack != seq_ + 1:
        f.envio_paquetes_inseguro(enviar_pkt(seq_, seq_1, "SA", dest_ip, source_ip, dest_port, src_port, seq_))
        tcp_pkt = escuchar(3)

            


timer_ = 20
time.sleep(timer_)

#f timer_ == 20:
#    f.envio_paquetes_inseguro(enviar_pkt(tcp_pkt.ack, tcp_pkt.seq, "F"))

# print(pkt_capturado.stats)
