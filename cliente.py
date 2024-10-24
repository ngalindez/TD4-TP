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

while i < 1:
    seq_ = 500
    ack_ = None
    tcp_pkt = None
    while not tcp_pkt or (TCP in tcp_pkt[0] and (tcp_pkt[0][TCP].ack < seq_ + 1 or not verify_checksum(tcp_pkt[0]))):
        tcp_pkt = None
        f.envio_paquetes_inseguro(enviar_pkt(
            seq_, 0, "S", dest_ip, source_ip, dest_port, src_port))
        tcp_pkt = escuchar(3, src_port)

    rcv = tcp_pkt[0][TCP]
    ack_ = rcv.seq
    seq_ = rcv.ack
    f.envio_paquetes_inseguro(enviar_pkt(
        seq_, ack_ + 1, "A", dest_ip, source_ip, dest_port, src_port))
    tcp_pkt = None

    while True:
        tcp_pkt = escuchar(3, src_port)

        if tcp_pkt and TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack < seq_ + 1:
            f.envio_paquetes_inseguro(enviar_pkt(
                seq_, ack_ + 1, "A", dest_ip, source_ip, dest_port, src_port))
            tcp_pkt = None
        elif tcp_pkt and TCP in tcp_pkt[0] and not verify_checksum(tcp_pkt[0]):
            f.envio_paquetes_inseguro(enviar_pkt(
                seq_, ack_ + 1, "A", dest_ip, source_ip, dest_port, src_port))
            tcp_pkt = None

        elif tcp_pkt and TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack >= seq_ + 1:

            break

    print("sali del loop")

    rcv = tcp_pkt[0][TCP]
    ack_ = rcv.seq
    seq_ = rcv.ack
    tcp_pkt = None

    timer_ = 60
    start_time = time.time()

    while time.time() - start_time < timer_:

        if not tcp_pkt or (TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack < seq_ + 1):
            print("entre aca")
            f.envio_paquetes_inseguro(enviar_pkt(
                seq_, ack_ + 1, "FA", dest_ip, source_ip, dest_port, src_port))
            tcp_pkt = None

        elif TCP in tcp_pkt[0] and not verify_checksum(tcp_pkt[0]):
            print("entre aca 2")
            f.envio_paquetes_inseguro(enviar_pkt(
                seq_, ack_ + 1, "FA", dest_ip, source_ip, dest_port, src_port))
            tcp_pkt = None

        elif tcp_pkt and TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack >= seq_ + 1:
            print("justo antes del break")
            break

        tcp_pkt = escuchar(3, src_port)

    i += 1
