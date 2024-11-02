from funciones import *
import random

source_ip = '127.0.0.1'
src_port = 9000
interface = "lo0"

def conexion_servidor(source_ip,src_port,interface):
    # Vacio tcp_pkt y seteo los numeros de ACK y SEQ.
    seq_ = random.randint(1, 1000)
    ack_ = None
    tcp_pkt = None

    # Escucha hasta que le llegue un paquete con flag S y con checksum correcto.
    while not tcp_pkt or tcp_pkt[0][TCP].flags != "S" or not verify_checksum(tcp_pkt[0]):
        tcp_pkt = listen(60, src_port,interface)

    ack_ = tcp_pkt[0][TCP].seq
    dest_port = tcp_pkt[0][TCP].sport
    dest_ip = tcp_pkt[0][IP].src
    tcp_pkt = None

    # Mando el primer SA y escucho. Si llega un paquete con un ACK correcto y verifica el checksum, salgo del ciclo.
    # Si no llega un paquete en los tres segundos de timout o no verifica el checksum o me llega un paquete con numero
    # de ACK no esperado, vuelvo a enviar el SA.
    
    while not correcto(tcp_pkt,seq_,ack_+1,dest_port,flags="A"):
        
        packet = build_pkt(seq_, ack_ + 1, "SA", dest_ip,
                           source_ip, dest_port, src_port)
        f.envio_paquetes_inseguro(packet)
        print('------------------------------')
        tcp_pkt = listen(3, src_port,interface)

    print('Conexión establecida\n')

    # Vacio tcp_pkt y actualizo los numeros de ACK y SEQ.
    rcv = tcp_pkt[0][TCP]
    ack_ = rcv.seq
    seq_ = rcv.ack
    tcp_pkt = None

    # Espero 20 segundos para mandar el FIN.
    timer_ = 3
    time.sleep(timer_)

    # Envio el paquete de FIN con los ACK y SEQ correspondientes y espero por el ACK de ese FIN.
    # Si llega un paquete con un ACK correcto y verifica el checksum, salgo del ciclo.
    # Si no llega un paquete en los tres segundos de timout o no verifica el checksum o me llega un paquete con numero
    # de ACK no esperado, vuelvo a enviar el F.
    while not correcto(tcp_pkt,seq_,ack_+1,dest_port,flags="FA"):

        packet = build_pkt(seq_, ack_ + 1, "F", dest_ip,
                           source_ip, dest_port, src_port)
        f.envio_paquetes_inseguro(packet)
        print('------------------------------')
        tcp_pkt = listen(3, src_port,interface)

    # Pongo un timer de 20 seg para que escuche por si el el cliente requiere que le vuelva enviar el ACK de su fin,
    # cuando se termine este, se termina la conexion.
    timer_ = 20
    start_time = time.time()

    # Vacio tcp_pkt y actualizo los numeros de ACK y SEQ.
    rcv = tcp_pkt[0][TCP]
    ack_ = rcv.seq
    seq_ = rcv.ack
    tcp_pkt = None

    # Como me va a haber llegado el FA del cliente, le mando el ACK del FIN del cliente.
    packet = build_pkt(seq_, ack_ + 1, "A", dest_ip,
                       source_ip, dest_port, src_port)
    f.envio_paquetes_inseguro(packet)
    print('------------------------------')

    # El servidor escucha hasta que pasen los 20 segundos.
    while time.time() - start_time < timer_:
        
        tcp_pkt = listen(3, src_port,interface)
        # Si en esos 20 segundo le me vuelve a llegar un paquete y es el de FA del cliente (con Checksum correcto),
        # le vuelvo a enviar el A.
        if correcto(tcp_pkt,seq_-1,ack_,dest_port,flags="FA"):
            packet = build_pkt(seq_, ack_ + 1, "A", dest_ip,
                               source_ip, dest_port, src_port)
            f.envio_paquetes_inseguro(packet)
            print('------------------------------')
            tcp_pkt = None

    # Se cierra la conexion al terminar los 20 seg.
    print('Conexión cerrada')

conexion_servidor(source_ip=source_ip,src_port=src_port,interface=interface)