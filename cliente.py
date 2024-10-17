from funciones import *

# Elegimos parametros
source_ip = '192.168.56.1'
dest_ip = '192.168.56.1'
dest_port = 8000
src_port = 5000
seq_ = 500

tcp_pkt = None
threads = []

while not tcp_pkt or (TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack < seq_ + 1):

    enviar_thread_S = threading.Thread(
        target=f.envio_paquetes_inseguro,  # Pasamos la función sin ejecutar
        args=(enviar_pkt(seq_, -1, "S", dest_ip, source_ip, dest_port, src_port),)  # Pasamos los argumentos a la función
    )
    
    # Inicia el hilo de envío de paquetes
    threads.append(enviar_thread_S)
    enviar_thread_S.start()
    tcp_pkt = escuchar(3, src_port)

for thread in threads:
    thread.join()


rcv = tcp_pkt[0][TCP]
seq_1 = rcv.seq
seq_ = rcv.ack
tcp_pkt = None
threads.clear()

while True:
    tcp_pkt = escuchar(3, src_port)
    if tcp_pkt and TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack != seq_ + 1:
        enviar_thread_AS = threading.Thread(
        target=f.envio_paquetes_inseguro,  # Pasamos la función sin ejecutar
        args=(enviar_pkt(seq_, seq_1, "A", dest_ip, source_ip, dest_port, src_port),)  # Pasamos los argumentos a la función
        )
        threads.append(enviar_thread_AS)
    
        # Inicia el hilo de envío de paquetes
        enviar_thread_AS.start()
        tcp_pkt = None

    
    elif tcp_pkt and TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack == seq_ + 1:
        for thread in threads:
            thread.join()
        break

rcv = tcp_pkt[0][TCP]
seq_1 = rcv.seq
seq_ = rcv.ack
tcp_pkt = None
threads.clear()


timer_ = 60
start_time = time.time()

while time.time() - start_time < timer_:
    
    if tcp_pkt and TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack != seq_ + 1:
        enviar_thread_FA = threading.Thread(
        target=f.envio_paquetes_inseguro,  # Pasamos la función sin ejecutar
        args=(enviar_pkt(seq_, seq_1, "FA", dest_ip, source_ip, dest_port, src_port),)  # Pasamos los argumentos a la función
        )
        threads.append(enviar_thread_FA)
        # Inicia el hilo de envío de paquetes
        enviar_thread_FA.start()
    elif tcp_pkt and TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack == seq_ + 1:
        for thread in threads:
            thread.join()
            threads.clear()
        break
    tcp_pkt = escuchar(3, src_port)




