import random
import time
from threading import Thread
from scapy.all import *

def envio_paquetes_inseguro(pkt):

    porcentaje_delay = 14
    porcentaje_corrupcion = 12
    porcentaje_perdida = 9
    porcentaje_normal = 65
    tiempo_atraso = 4
    time_value = 1
    
    problema = random.choices(["No", "Delay", "Corrupto", "Perdida" ],[porcentaje_normal,porcentaje_delay,porcentaje_corrupcion,porcentaje_perdida])[0]
    if problema=="Perdida":  # Situacion el paquete no se mando
        return 0
    
    if problema=="Corrupto":  # Situacion el paquete se corrompe
        pkt[TCP].chksum = 0x1234
        
    if problema == "Delay": # Situacion el paquete se atraso
        time_value += tiempo_atraso
    
    time.sleep(time_value)  # Delay de envio
    send(pkt,count=1)