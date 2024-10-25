from funciones import *

# Elegimos parametros
source_ip = '192.168.56.1'
dest_ip = '192.168.56.1'
dest_port = 8000
src_port = 5000
seq_ = 500
ack_ = None
tcp_pkt = None
i = 0

while i < 10:
    seq_ = 500
    ack_ = None
    tcp_pkt = None

    # Mando el SYN al servidor y escucho por 3 segundos haber si me llega el SA del servidor. 
    # En caso de que no me llegue ningun paquete o que este no tengo numero de ACK correcto o no se verifique el checksum,
    # me mantengo en el ciclo y vuelvo a mandar el msj de SYN.
    while not tcp_pkt or (TCP in tcp_pkt[0] and (tcp_pkt[0][TCP].ack < seq_ + 1 or not verify_checksum(tcp_pkt[0]))):
        tcp_pkt = None
        f.envio_paquetes_inseguro(enviar_pkt(seq_, 0, "S", dest_ip, source_ip, dest_port, src_port))
        tcp_pkt = escuchar(3, src_port)

    # Vacio tcp_pkt y actualizo los numeros de ACK y SEQ.
    rcv = tcp_pkt[0][TCP]
    ack_ = rcv.seq
    seq_ = rcv.ack
    tcp_pkt = None

    # Mando el A del mensaje de SA del servidor.
    f.envio_paquetes_inseguro(enviar_pkt(seq_, ack_ + 1, "A", dest_ip, source_ip, dest_port, src_port))
    

    while True:
        # escucho esperando recibir el mensaje de F.
        tcp_pkt = escuchar(3, src_port)

        # si me llega un paquete viejo (que ya recibi), vuelvo a mandar el mensaje anterior de A del SA del servidor.
        if tcp_pkt and TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack < seq_ + 1:
            f.envio_paquetes_inseguro(enviar_pkt(seq_, ack_ + 1, "A", dest_ip, source_ip, dest_port, src_port))
            tcp_pkt = None
        # si me llega un paquete con numero de ACK correcto pero con checksum mal, reenvio el A del SA del servidor.
        elif tcp_pkt and TCP in tcp_pkt[0] and not verify_checksum(tcp_pkt[0]):
            f.envio_paquetes_inseguro(enviar_pkt(seq_, ack_ + 1, "A", dest_ip, source_ip, dest_port, src_port))
            tcp_pkt = None
        # si me llega un paquete con ACK correcto y con checksum bien, salgo del ciclo.
        elif tcp_pkt and TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack >= seq_ + 1:
            
            break


    # Vacio tcp_pkt y actualizo los numeros de ACK y SEQ.
    rcv = tcp_pkt[0][TCP]
    ack_ = rcv.seq
    seq_ = rcv.ack
    tcp_pkt = None

    # Empiezo un timer por si no me llega el ACK del FIN, al momento que termina se cierra la conexion forzosamente.
    timer_ = 60
    start_time = time.time()

    while time.time() - start_time < timer_:

        # Mando el FA si es la primera iteracion o en el caso de ya haberlo mandado, si epserando el ACK, no me llega un ningun paquete o con ACK menor.
        if not tcp_pkt or (TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack < seq_ + 1):
            print("entre aca")
            f.envio_paquetes_inseguro(enviar_pkt(seq_, ack_ + 1, "FA", dest_ip, source_ip, dest_port, src_port))
            tcp_pkt = None
        # Mando el FA si me llego un paquete con ACK correcto pero con checksum mal.
        elif TCP in tcp_pkt[0] and not verify_checksum(tcp_pkt[0]):
            print("entre aca 2")
            f.envio_paquetes_inseguro(enviar_pkt(seq_, ack_ + 1, "FA", dest_ip, source_ip, dest_port, src_port))
            tcp_pkt = None
        # Salgo del ciclo si me llega el ACK correcto con checksum correcto 
        elif tcp_pkt and TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack >= seq_ + 1:
            break
        # escucho para esperar el ACK del FA
        tcp_pkt = escuchar(3, src_port)

    # Llego aca si me llego el ACK correcto con checksum correcto o se termino el timer de 60 seg y cierro la conexion de manera forzosa ya que nunca me llego el ACK.
    i += 1



