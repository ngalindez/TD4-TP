from funciones import *

source_ip = '192.168.56.1'
dest_ip = '192.168.56.1'
dest_port = 5000
src_port = 8000
seq_ = 5
ack_ = None
i = 0

while i < 10:
    seq_ = 5
    ack_ = None
    tcp_pkt = None
    # Escucha hasta que le llegue un paquete con flag S y con checksum correcto 
    while not tcp_pkt or tcp_pkt[0][TCP].flags != "S" or not verify_checksum(tcp_pkt[0]):
        tcp_pkt = escuchar(60, src_port)

    ack_ = tcp_pkt[0][TCP].seq
    tcp_pkt = None
        
    # Mando el primer SA y escucho. Si llega un paquete con un ACK correcto y verifica el checksum, salgo del ciclo.
    # Si no llega un paquete en los tres segundos de timout o no verifica el checksum o me llega un paquete con numero
    # de ACK no esperado, vuelvo a enviar el SA
    while not tcp_pkt or (TCP in tcp_pkt[0] and (tcp_pkt[0][TCP].ack < seq_ + 1 or not verify_checksum(tcp_pkt[0]))):
        f.envio_paquetes_inseguro(enviar_pkt(seq_, ack_ + 1, "SA", dest_ip, source_ip, dest_port, src_port))
        tcp_pkt = escuchar(3, src_port)

    # Vacio tcp_pkt y actualizo los numeros de ACK y SEQ.
    rcv = tcp_pkt[0][TCP]
    ack_ = rcv.seq
    seq_ = rcv.ack
    tcp_pkt = None
   
    # Espero 20 segundos para mandar el FIN.
    timer_ = 20
    time.sleep(timer_)

    # Envio el paquete de FIN con los ACK y SEQ correspondientes y espero por el ACK de ese FIN.
    # Si llega un paquete con un ACK correcto y verifica el checksum, salgo del ciclo.
    # Si no llega un paquete en los tres segundos de timout o no verifica el checksum o me llega un paquete con numero
    # de ACK no esperado, vuelvo a enviar el F
    while not tcp_pkt or (TCP in tcp_pkt[0] and (tcp_pkt[0][TCP].ack < seq_ + 1 or not verify_checksum(tcp_pkt[0]))):
        f.envio_paquetes_inseguro(enviar_pkt(seq_, ack_ + 1, "F", dest_ip, source_ip, dest_port, src_port))
        tcp_pkt = escuchar(3, src_port)
            
    # Pongo un timer de 20 seg para que escuche por si el el cliente requiere que le vuelva enviar el ACK de su fin, cuando se termine este, se termina la conexion. 
    timer_ = 20
    start_time = time.time()

    # Vacio tcp_pkt y actualizo los numeros de ACK y SEQ.
    rcv = tcp_pkt[0][TCP]
    ack_ = rcv.seq
    seq_ = rcv.ack
    tcp_pkt = None

    # Como me va a haber llegado el FA del cliente, le mando el ACK del FIN del cliente.
    f.envio_paquetes_inseguro(enviar_pkt(seq_, ack_ + 1, "A", dest_ip, source_ip, dest_port, src_port))

    # El servidor escucha hasta que pasen los 20 segundos
    while time.time() - start_time < timer_:
        # Si en esos 20 segundo le me vuelve a llegar un paquete y es el de FA del cliente (con Checksum correcto), le vuelvo a enviar el A.
        if tcp_pkt and TCP in tcp_pkt[0] and tcp_pkt[0][TCP].ack >= seq_ and verify_checksum(tcp_pkt[0]):
            f.envio_paquetes_inseguro(enviar_pkt(seq_, ack_ + 1, "A", dest_ip, source_ip, dest_port, src_port))
            tcp_pkt = None

        tcp_pkt = escuchar(3, src_port)

    # Se cierra la conexion al terminar los 20 seg.
    i += 1
    