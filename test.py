from scapy.all import *
from scapy.all import IP, TCP
from funciones import SocketRDT


def verify_checksum(packet):
    # extraigo el checksum del paquete que me llegó
    chksum0 = packet[TCP].chksum

    packet[TCP].chksum = None  # borro el valor viejo del paquete

    chksum1 = sum(bytes(packet[TCP]))

    return chksum0 == chksum1