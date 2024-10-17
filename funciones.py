from scapy.all import *
from scapy.all import TCP, IP
import canalruidoso as f
import time


class SocketRDT:

    def __init__(self, src_ip, src_port, dest_ip, dest_port, interface):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.interface = interface
        self.last_pkt_rcvd = None
        self.last_pkt_sent = None
        self.conn_established = False
        self.proporciones = {'Perdido': 0,
                             'Demorado': 0, 'Corrupto': 0, 'Normal': 0}

    def info_packet(self, packet):
        print(f"\nSource port: {packet[TCP].sport}")
        print(f"Destination port: {packet[TCP].dport}")
        print(f"Flags: {packet[TCP].flags}")
        print(f"#SEQ: {packet[TCP].seq}")
        print(f"#ACK: {packet[TCP].ack}")
        print(f"Checksum: {packet[TCP].chksum}\n")

    def filter_function(self, packet):
        return packet.haslayer(TCP) and packet[TCP].dport == self.src_port

    def verify_checksum(packet):
        # extraigo el checksum del paquete que me llegó
        chksum0 = packet[TCP].chksum

        packet[TCP].chksum = None  # borro el valor viejo del paquete

        chksum1 = sum(bytes(packet[TCP]))

        return chksum0 == chksum1

    def reenviar_ultimo(self):
        # Este paquete va a hacer de "último paquete recibido correctamente" para que el paquete que reenvio tenga #SEQ y #ACK correctos
        _last_pkt = IP()/TCP()
        _last_pkt[TCP].ack = self.last_pkt_sent[TCP].seq
        _last_pkt[TCP].seq = self.last_pkt_sent[TCP].ack - 1

        # Si me llegó un #ACK que no esperaba o el paquete está corrupto, reenvio el último paquete
        self.envio_paquetes_seguro(
            self.last_pkt_sent[TCP].flags, last_pkt=_last_pkt)

    def listen(self):
        print(f"Listening for TCP packets on port {self.src_port}...")
        pkt_capturado = sniff(
            iface=self.interface,
            prn=self.info_packet,
            count=1,
            timeout=60,
            lfilter=self.filter_function)
        self.last_pkt_rcvd = pkt_capturado[0]

        if not self.verify_checksum(self.last_pkt_rcvd):
            self.proporciones['Corrupto'] += 1
            self.reenviar_ultimo()
            self.listen()

        # Para asegurarme de que recibí el que quiero
        # si self.last_pkt_sent == None, self.last_pkt_rcvd es el primero que recibo
        ACK_esperado = self.last_pkt_rcvd[TCP].ack if self.last_pkt_sent is None else self.last_pkt_sent[TCP].seq + 1

        if self.last_pkt_rcvd[TCP].ack != ACK_esperado:
            self.reenviar_ultimo()
            self.listen()

        self.proporciones['Normal'] += 1

        # Para el three-way-handshake
        if self.last_pkt_rcvd[TCP].flags == 'S' and not self.conn_established:

            # Elijo un #SEQ random para el servidor
            rand_SEQ = random.randint(0, 1024)
            # se lo cambio a self.last_pkt_rcvd para no tener que cambiar toda la función. Después funciona normal
            self.last_pkt_rcvd[TCP].ack = rand_SEQ

            # Mando un SA y espero que me llegue un A
            while self.last_pkt_rcvd[TCP].flags != 'A':
                self.envio_paquetes_seguro(_flags='SA', )
                self.listen()

            if self.last_pkt_rcvd[TCP].flags == 'A':
                self.conn_established = True

        # Para el cierre de conexión
        if self.last_pkt_rcvd[TCP].flags == 'F' and self.conn_established:
            # Mando un FA y espero a que me llegue un A
            while self.last_pkt_rcvd[TCP].flags != 'A':
                self.envio_paquetes_seguro(_flags='FA')
                self.listen()

            if self.last_pkt_rcvd[TCP].flags == 'A':
                self.conn_established = False
                print('Connection closed')

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

        en_bytes = bytes(packet)
        packet[TCP].chksum = sum(en_bytes)

        f.envio_paquetes_inseguro(packet)
        self.last_pkt_sent = packet

    def iniciar_conexion(self):
        # Elegimos #SEQ aleatorio para el primer paquete
        rand_SEQ = random.randint(0, 1024)
        self.envio_paquetes_seguro(
            _flags='S',
            last_pkt=IP()/TCP(seq=-1, ack=rand_SEQ))

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
        self.conn_established = False
        print('Connection closed')

    def mostrar_estadisticas(self):
        total = self.proporciones['Normal'] + self.proporciones['Corrupto'] + \
            self.proporciones['Demorado'] + self.proporciones['Perdido']

        print(f"\nTotal enviados: {total}")
        print(f"Normal: {100 * self.proporciones['Normal'] / total}%")
        print(f"Corrupto: {100 * self.proporciones['Corrupto'] / total}%")
        print(f"Demorado: {100 * self.proporciones['Demorado'] / total}%")
        print(f"Perdido: {100 * self.proporciones['Perdido'] / total}%")
