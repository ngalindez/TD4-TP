import canalruidoso as f  # Correr pip install canalruidoso en la terminal
import threading
import time
import csv
from funciones import *
from scapy.all import send, sniff, IP, TCP

# Variables para almacenar stats

# Quiero ver tmb el tiempo que tarda en enviarse el paquete
# Podemos poner en un csv, para cada #seq, tiempo_viaje, corrupto(1/0), demorado(1/0), perdido(1/0)
# cada vez que manda, agrega una columna con time_sent, #seq, y el resto en N/A; y cuando llega completa con corrupto, demorado, o perdido si no llego


pkts_enviados = 0
pkts_recibidos = 0
pkts_demorados = 0
pkts_corruptos = 0
tiempos_rcvd = {}  # mapea #SEQ <--> tiempo de recepción
tiempos_sent = {}  # mapea #SEQ <--> tiempo de send
data = [['#SEQ', 'time_sent', 'time_received',
         'total_time', 'corrupto', 'demorado', 'perdido']]
time_inicio = 0

cant_paquetes = 100


ip_ = '127.0.0.1'
client_port = 6000
server_port = 3000
init_seq = 0

# Thread de envío de paquetes


def enviar_paquetes():
    global pkts_enviados, tiempos_sent, data, time_inicio
    time_inicio = time.time()
    for i in range(cant_paquetes):
        ip = IP(dst=ip_, src=ip_)
        tcp = TCP(sport=client_port, dport=server_port,
                  seq=init_seq + i, ack=0)
        pkt = ip/tcp

        time_sent = time.time()
        tiempos_sent[pkt[TCP].seq] = time_sent
        pkts_enviados += 1

        # perdido es 1, y si el server lo recibe, lo cambia a 0
        data.append([pkt[TCP].seq, time_sent, 0, 0, 0, 0, 1])

        f.envio_paquetes_inseguro(pkt)

        print(
            f"Paquete #{init_seq + i + 1} enviado en {round(time_sent - time_inicio, 4)}s")


def receive_packets():
    global pkts_recibidos, pkts_demorados, pkts_corruptos, tiempos_rcvd, data, time_inicio

    def listen(pkt):
        global pkts_recibidos, pkts_demorados, pkts_corruptos

        time_received = time.time()
        tiempos_rcvd[pkt[TCP].seq] = time_received
        pkts_recibidos += 1

        data[-1][2] = time_received  # columna de 'time_received'
        # total_time = time_received - time_sent
        data[-1][3] = time_received - data[-1][1]
        data[-1][6] = 0  # cambia la columna de perdido a 0

        # Chequeo si llegó tarde
        if time_received - tiempos_sent[pkt[TCP].seq] > 3:
            print('Paquete demorado')
            pkts_demorados += 1
            data[-1][5] = 1

        if not verify_checksum(pkt):
            print('Paquete corrupto')
            pkts_corruptos += 1
            data[-1][4] = 1

        print(
            f"Paquete #{pkt[TCP].seq} recibido en {round(time_received - time_inicio, 4)}s")

    sniff(iface='lo0',
          prn=listen,
          timeout=1.6*cant_paquetes,
          lfilter=lambda pkt: filter_function(pkt, server_port))
    print('Terminó de escuchar')


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


with open("TD4-TP/output_test.csv", mode="a", newline="") as file:
    writer = csv.writer(file)

    # Write rows sequentially
    for row in data[1:]:
        writer.writerow(row)
