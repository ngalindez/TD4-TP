from funciones import *

source_ip = '127.0.0.1'
dest_ip = '127.0.0.1'
dest_port = 6000
src_port = 9000
seq_ = 5
ack_ = None
i = 0

while i < 1:
    # Vacio tcp_pkt y actualizo los numeros de ACK y SEQ.
    seq_ = 5
    ack_ = None
    tcp_pkt = None

    while not tcp_pkt or tcp_pkt[0][TCP].flags != "S" or not verify_checksum(tcp_pkt[0]):
        tcp_pkt = escuchar(60, src_port)

    if tcp_pkt:
        ack_ = tcp_pkt[0][TCP].seq
        tcp_pkt = None

        while not tcp_pkt or (TCP in tcp_pkt[0] and (tcp_pkt[0][TCP].ack < seq_ + 1 or not verify_checksum(tcp_pkt[0]))):
            packet = build_pkt(seq_, ack_ + 1, "SA", dest_ip,
                               source_ip, dest_port, src_port)
            f.envio_paquetes_inseguro(packet)
            print('------------------------------')
            tcp_pkt = escuchar(3, src_port)

    print('Conexión establecida\n')

    # Vacio tcp_pkt y actualizo los numeros de ACK y SEQ.
    rcv = tcp_pkt[0][TCP]
    ack_ = rcv.seq
    seq_ = rcv.ack
    tcp_pkt = None

    timer_ = 20
    time.sleep(timer_)

    while not tcp_pkt or (TCP in tcp_pkt[0] and (tcp_pkt[0][TCP].ack < seq_ + 1 or not verify_checksum(tcp_pkt[0]))):

        packet = build_pkt(seq_, ack_ + 1, "F", dest_ip,
                           source_ip, dest_port, src_port)
        f.envio_paquetes_inseguro(packet)
        print('------------------------------')
        tcp_pkt = escuchar(3, src_port)

    timer_ = 20
    start_time = time.time()

    # Vacio tcp_pkt y actualizo los numeros de ACK y SEQ.
    rcv = tcp_pkt[0][TCP]
    ack_ = rcv.seq
    seq_ = rcv.ack
    tcp_pkt = None

    packet = build_pkt(seq_, ack_ + 1, "A", dest_ip,
                       source_ip, dest_port, src_port)
    f.envio_paquetes_inseguro(packet)
    print('------------------------------')

    while time.time() - start_time < timer_:

        if tcp_pkt and TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack >= seq_ and verify_checksum(tcp_pkt[0]):

            packet = build_pkt(seq_, ack_ + 1, "A", dest_ip,
                               source_ip, dest_port, src_port)
            f.envio_paquetes_inseguro(packet)
            print('------------------------------')
            tcp_pkt = None

        tcp_pkt = escuchar(3, src_port)

    i += 1
print('Conexión cerrada')
