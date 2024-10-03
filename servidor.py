from scapy.all import *
import canalruidoso as f  # Correr pip install canalruidoso en la terminal

# Mostramos todas las interfaces
print(conf.ifaces)

# Esto lo tienen que completar con el nombre de la interfaz que tenga el 127.0.0.1 si se recibe el paquete en la misma computadora que lo envio.
interface = "Software Loopback Interface 1"

listen_port = 8000  # Elegir el puerto que esta escuchando

print(f"Listening for TCP packets on port {listen_port}...")
filter_str = f"tcp port {listen_port}"

# Escuchar en ese puerto
pkt_capturado = sniff(iface=interface, filter=filter_str,
                      prn=lambda x: x.show(), count=1, timeout=60)

