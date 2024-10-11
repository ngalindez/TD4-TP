from funciones import *

source_ip = '192.168.56.1'
dest_ip = '192.168.56.1'
dest_port = 5000
src_port = 8000
seq_ = 5

tcp_pkt = escuchar(60, src_port)

if tcp_pkt:
    seq_1 = tcp_pkt[0][TCP].seq
    tcp_pkt = None
    
    while not tcp_pkt or (TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack < seq_ + 1):
        enviar_thread = threading.Thread(
        target=f.envio_paquetes_inseguro,  # Pasamos la función sin ejecutar
        args=(enviar_pkt(seq_, seq_1, "SA", dest_ip, source_ip, dest_port, src_port),)  # Pasamos los argumentos a la función
        )
    
    # Inicia el hilo de envío de paquetes
        enviar_thread.start()

        tcp_pkt = escuchar(3, src_port)

            


timer_ = 20
time.sleep(timer_)

#f timer_ == 20:
#    f.envio_paquetes_inseguro(enviar_pkt(tcp_pkt.ack, tcp_pkt.seq, "F"))

# print(pkt_capturado.stats)
