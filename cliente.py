from funciones import *

# Elegimos parametros
source_ip = '127.0.0.1'
dest_ip = '127.0.0.1'
dest_port = 9000
src_port = 6000
seq_ = 500
ack_ = None
tcp_pkt = None
i = 0

while i < 1:
    seq_ = 500
    ack_ = None
    tcp_pkt = None
    # Mando el SYN al servidor y escucho por 3 segundos haber si me llega el SA del servidor. 
    # En caso de que no me llegue ningun paquete o que este no tengo numero de ACK correcto o no se verifique el checksum,
    # me mantengo en el ciclo y vuelvo a mandar el msj de SYN.
    while not tcp_pkt or (TCP in tcp_pkt[0] and (tcp_pkt[0][TCP].ack < seq_ + 1 or not verify_checksum(tcp_pkt[0]))):
        tcp_pkt = None
        packet = build_pkt(seq_, 0, "S", dest_ip,
                           source_ip, dest_port, src_port)
        f.envio_paquetes_inseguro(packet)
        print('------------------------------')
        tcp_pkt = escuchar(3, src_port)

    # Vacio tcp_pkt y actualizo los numeros de ACK y SEQ.
    rcv = tcp_pkt[0][TCP]
    ack_ = rcv.seq
    seq_ = rcv.ack
    tcp_pkt = None

    packet = build_pkt(seq_, ack_ + 1, "A", dest_ip,
                       source_ip, dest_port, src_port)
    f.envio_paquetes_inseguro(packet)
    print('------------------------------')
    
    print('Conexión establecida\n')

    while True:
        tcp_pkt = escuchar(3, src_port)

        if tcp_pkt and TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack < seq_ + 1:

            packet = build_pkt(seq_, ack_ + 1, "A", dest_ip,
                               source_ip, dest_port, src_port)
            f.envio_paquetes_inseguro(packet)
            tcp_pkt = None
            print('------------------------------')

        elif tcp_pkt and TCP in tcp_pkt[0] and not verify_checksum(tcp_pkt[0]):

            packet = build_pkt(seq_, ack_ + 1, "A", dest_ip,
                               source_ip, dest_port, src_port)
            f.envio_paquetes_inseguro(packet)
            tcp_pkt = None
            print('------------------------------')

        elif tcp_pkt and TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack >= seq_ + 1:
            break

    # Vacio tcp_pkt y actualizo los numeros de ACK y SEQ.
    rcv = tcp_pkt[0][TCP]
    ack_ = rcv.seq
    seq_ = rcv.ack
    tcp_pkt = None

    timer_ = 60
    start_time = time.time()

    while time.time() - start_time < timer_:

        if not tcp_pkt or (TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack < seq_ + 1):

            packet = build_pkt(seq_, ack_ + 1, "FA", dest_ip,
                               source_ip, dest_port, src_port)
            f.envio_paquetes_inseguro(packet)
            tcp_pkt = None
            print('------------------------------')

        elif TCP in tcp_pkt[0] and not verify_checksum(tcp_pkt[0]):

            packet = build_pkt(seq_, ack_ + 1, "FA", dest_ip,
                               source_ip, dest_port, src_port)
            f.envio_paquetes_inseguro(packet)
            tcp_pkt = None
            print('------------------------------')

        elif tcp_pkt and TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack >= seq_ + 1:
            break

        tcp_pkt = escuchar(3, src_port)
        print('Conexión cerrada')

    i += 1
