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

