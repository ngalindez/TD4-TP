import canalruidoso as f  # Correr pip install canalruidoso en la terminal
import time
import threading
import time
from funciones import verify_checksum, filter_function_server, info_packet
from scapy.all import send, sniff, IP, TCP

# Variables para almacenar stats

# Quiero ver tmb el tiempo que tarda en enviarse el paquete
# Podemos poner en un csv, para cada #seq, tiempo_viaje, corrupción(1/0), demorado(1/0)

pkts_enviados = 0
pkts_recibidos = 0
pkts_demorados = 0
pkts_corruptos = 0
tiempo_receive = {}  # mapea #SEQ <--> tiempo de recepción
tiempo_send = {}  # mapea #SEQ <--> tiempo de send


ip_ = '127.0.0.1'
client_port = 6000
server_port = 9000
init_seq = 0

# Packet sending thread


def enviar_paquetes():
    global pkts_enviados, tiempo_send
    for i in range(10):
        ip = IP(dst=ip_, src=ip_)
        tcp = TCP(sport=client_port, dport=server_port,
                  seq=init_seq + i, ack=0)
        pkt = ip/tcp

        send_time = time.time()
        tiempo_send[pkt[TCP].seq] = send_time
        pkts_enviados += 1

        f.envio_paquetes_inseguro(pkt)

        print(
            f"Packet #{init_seq + i + 1} sent at {tiempo_send[pkt[TCP].seq]}")


def receive_packets():
    global pkts_recibidos, pkts_demorados, pkts_corruptos, tiempo_receive

    def listen(pkt):
        global pkts_recibidos, pkts_demorados, pkts_corruptos

        receive_time = time.time()
        tiempo_receive[pkt[TCP].seq] = receive_time
        pkts_recibidos += 1

        # Chequeo si llegó tarde
        if receive_time - tiempo_send[pkt[TCP].seq] > 3:
            print('Paquete demorado')
            pkts_demorados += 1

        if not verify_checksum(pkt):
            print('Paquete corrupto')
            pkts_corruptos += 1

        print(f"Packet #{pkt[TCP].seq} received at {receive_time}")

    # print(f"Listening for TCP packets on port 9000 ...\n")
    pkt = sniff(iface='lo0', prn=listen, timeout=20,
                lfilter=filter_function_server)


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
print('------------------------------')
pkts_perdidos = pkts_enviados - pkts_recibidos
pkts_correctos = pkts_recibidos - pkts_corruptos - pkts_demorados

print(f"\nPaquetes enviados: {pkts_enviados}")
print(
    f"\tPaquetes perdidos: {pkts_perdidos} ({round(100 * pkts_perdidos / pkts_enviados, 2)}%)")

print(f"\nPaquetes recibidos: {pkts_recibidos}")
print(
    f"\tPaquetes recibidos correctamente: {pkts_correctos} ({round(100 * pkts_correctos / pkts_recibidos, 2)}%)")
print(
    f"\tPaquetes demorados: {pkts_demorados} ({round(100 * pkts_demorados / pkts_recibidos, 2)}%)")
print(
    f"\tPaquetes corruptos: {pkts_corruptos} ({round(100 * pkts_corruptos / pkts_recibidos, 2)}%)")
