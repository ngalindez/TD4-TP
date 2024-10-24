import canalruidoso as f  # Correr pip install canalruidoso en la terminal
import time
import threading
import time
from funciones import verify_checksum, filter_function_server
from scapy.all import send, sniff, IP, TCP
import random

# Variables para almacenar stats

pkts_enviados = 0
pkts_recibidos = 0
pkts_demorados = 0
pkts_corruptos = 0
tiempo_receive = {}  # mapea #SEQ <--> tiempo de recepción
tiempo_send = {}  # mapea #SEQ <--> tiempo de send


ip_ = '127.0.0.1'
client_port = 6000
server_port = 9000
rand_seq = 0

# Packet sending thread


def enviar_paquetes():
    global pkts_enviados, tiempo_send
    for i in range(10):
        ip = IP(dst=ip_, src=ip_)
        tcp = TCP(dport=client_port, sport=server_port, seq=rand_seq + i)
    pkt = ip/tcp

    send_time = time.time()
    tiempo_send[pkt[TCP].seq] = send_time
    pkts_enviados += 1
    f.envio_paquetes_inseguro(pkt)

    print(f"Packet {rand_seq + i} sent.")
    time.sleep(1)  # Sleep 1 second between sends

# Packet receiving thread


def receive_packets():
    global pkts_recibidos, pkts_demorados, pkts_corruptos, tiempo_receive

    def listen(pkt):
        global pkts_recibidos, pkts_demorados
        receive_time = time.time()
        tiempo_receive[pkt[TCP].seq] = receive_time
        pkts_recibidos += 1

        # Chequeo si llegó tarde
        if receive_time - tiempo_send[pkt[TCP].seq] > 3:
            pkts_demorados += 1

        if not verify_checksum(pkt):
            pkts_corruptos += 1

        print(f"Packet #{pkt[TCP].seq} received at {receive_time}")

    sniff(
        iface='lo0',
        filter_str="tcp port 9000",
        prn=listen,
        timeout=60)


print('Arrancando...')
# Creo y arranco las threads
send_thread = threading.Thread(target=enviar_paquetes)
receive_thread = threading.Thread(target=receive_packets)

send_thread.start()
receive_thread.start()

# Espero a que terminen las threads
send_thread.join()
receive_thread.join()

# Muestro stats

pkts_perdidos = pkts_enviados - pkts_recibidos

print(f"Paquetes recibidos: {pkts_recibidos}")
print(f"Paquetes demorados: {pkts_demorados}")
print(f"Paquetes corruptos: {pkts_corruptos}")
print(f"Paquetes perdidos: {pkts_perdidos}")
