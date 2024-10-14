from scapy.all import *
from scapy.all import TCP, IP
import canalruidoso as f
import time


# Elegimos #SEQ aleatorio para el primer paquete
rand = random.randint(0, 1024)

char2flag = {'S': 'SYN', 'A': 'ACK', 'F': 'FIN',
             'SA': 'SYN + ACK', 'FA': 'FIN + ACK', 'RST': 'RESET'}


class SocketRDT:

    def info_packet(self, packet):
        print(f"\nSource port: {packet[TCP].sport}")
        print(f"Destination port: {packet[TCP].dport}")
        print(f"Flags: {packet[TCP].flags}")
        print(f"#SEQ: {packet[TCP].seq}")
        print(f"#ACK: {packet[TCP].ack}")
        print(f"Checksum: {packet[TCP].chksum}\n")

    def __init__(self, src_ip, src_port, dest_ip, dest_port, interface):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.interface = interface
        self.last_pkt_rcvd = None
        self.last_pkt_sent = None
        self.conn_established = False

    def filter_function(self, packet):
        return packet.haslayer(TCP) and packet[TCP].dport == self.src_port

    def listen(self):
        print(f"Listening for TCP packets on port {self.src_port}...")
        pkt_capturado = sniff(
            iface=self.interface,
            prn=self.info_packet,
            count=1,
            timeout=60,
            lfilter=self.filter_function)
        self.last_pkt_rcvd = pkt_capturado[0]

        # Para asegurarme de que recibí el que quiero
        # is self.last_pkt_sent es None, self.last_pkt_rcvd es el primero que recibo
        SEQ_esperado = self.last_pkt_rcvd[TCP].ack if self.last_pkt_sent is None else self.last_pkt_sent[TCP].seq + 1
        if self.last_pkt_rcvd[TCP].ack != SEQ_esperado:
            self.listen()

        # Para el three-way-handshake
        if self.last_pkt_rcvd[TCP].flags == 'S' and not self.conn_established:

            self.envio_paquetes_seguro(_flags='SA')
            self.listen()

            if self.last_pkt_rcvd[TCP].flags == 'A':
                self.conn_established = True

        # Para el cierre de conexión
        if self.last_pkt_rcvd[TCP].flags == 'F' and self.conn_established:
            self.envio_paquetes_seguro(_flags='FA')

            # Ahora el self.last_pkt_rcvd fue actualizado por envio_paquetes_seguro
            if self.last_pkt_rcvd[TCP].flags == 'A':
                self.conn_established = False

        return self.last_pkt_rcvd

    def envio_paquetes_seguro(self, _flags, last_pkt=None):
        # Armo el paquete con las partes IP y TCP
        last_pkt = self.last_pkt_rcvd if last_pkt is None else last_pkt
        ip = IP(dst=self.dest_ip, src=self.src_ip)
        tcp = TCP(dport=self.dest_port,
                  sport=self.src_port,
                  flags=_flags,
                  seq=last_pkt[TCP].ack,
                  ack=last_pkt[TCP].seq + 1)
        packet = ip/tcp

        f.envio_paquetes_inseguro(packet)
        self.last_pkt_sent = packet

    def iniciar_conexion(self):
        # Elegimos #SEQ aleatorio para el primer paquete, lo guardo como atributo para otro caso
        self.rand_SEQ = random.randint(0, 1024)
        self.envio_paquetes_seguro(
            _flags='S',
            last_pkt=IP()/TCP(seq=-1, ack=self.rand_SEQ))

        while self.last_pkt_rcvd == None or (self.last_pkt_rcvd[TCP].flags != 'SA'):
            self.listen()

        self.envio_paquetes_seguro(_flags='A')
        self.conn_established = True

    def terminar_conexion(self):
        if not self.conn_established:
            return
        self.envio_paquetes_seguro(_flags='F')
        while self.last_pkt_rcvd[TCP].flags != 'FA':
            self.listen()

        self.envio_paquetes_seguro(_flags='A')
