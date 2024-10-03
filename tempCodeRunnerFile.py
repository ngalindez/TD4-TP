print(f"Listening for TCP packets on port {listen_port}...")
# filter_str = f"tcp port {listen_port}"

# # Escuchar en ese puerto
# pkt_capturado = sniff(iface=interface, filter=filter_str,
#                       prn=lambda x: x.show(), count=1, timeout=60)
