from funciones import *

source_ip = '192.168.56.1'
dest_ip = '192.168.56.1'
dest_port = 5000
src_port = 8000
seq_ = 5

tcp_pkt = escuchar(60, src_port)
threads = []

if tcp_pkt:
    seq_1 = tcp_pkt[0][TCP].seq
    tcp_pkt = None
    
    while not tcp_pkt or (TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack < seq_ + 1):
        enviar_thread_SA = threading.Thread(
        target=f.envio_paquetes_inseguro,  # Pasamos la función sin ejecutar
        args=(enviar_pkt(seq_, seq_1, "SA", dest_ip, source_ip, dest_port, src_port),)  # Pasamos los argumentos a la función
        )
        threads.append(enviar_thread_SA)
        # Inicia el hilo de envío de paquetes
        enviar_thread_SA.start()

        tcp_pkt = escuchar(3, src_port)

for thread in threads:
    thread.join()
            
rcv = tcp_pkt[0][TCP]
seq_1 = rcv.seq
seq_ = rcv.ack
tcp_pkt = None

threads.clear()

timer_ = 20
time.sleep(timer_)

while not tcp_pkt or (TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack < seq_ + 1):
        enviar_thread_F = threading.Thread(
        target=f.envio_paquetes_inseguro,  # Pasamos la función sin ejecutar
        args=(enviar_pkt(seq_, seq_1, "F", dest_ip, source_ip, dest_port, src_port),)  # Pasamos los argumentos a la función
        )
        threads.append(enviar_thread_F)
        # Inicia el hilo de envío de paquetes
        enviar_thread_F.start()

        tcp_pkt = escuchar(3, src_port)

for thread in threads:
    thread.join()

threads.clear()
timer_ = 20
start_time = time.time()


rcv = tcp_pkt[0][TCP]
seq_1 = rcv.seq
seq_ = rcv.ack
tcp_pkt = None

while time.time() - start_time < timer_:
    tcp_pkt = escuchar(3, src_port)
    if tcp_pkt and TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack != seq_ + 1:
        enviar_thread_AF = threading.Thread(
            target=f.envio_paquetes_inseguro,  # Pasamos la función sin ejecutar
            args=(enviar_pkt(seq_, seq_1, "A", dest_ip, source_ip, dest_port, src_port),)  # Pasamos los argumentos a la función
            )
        threads.append(enviar_thread_AF)
    # Inicia el hilo de envío de paquetes
        enviar_thread_AF.start()

for thread in threads:
    thread.join()

threads.clear()