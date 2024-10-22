import subprocess
import time

# Run server.py
server_process = subprocess.Popen(
    ['python3', '/Users/nicogalindez/UTDT/TD4/TP/TP_TD4/TD4-TP/servidor.py'])

# Give the server time to start up (optional, adjust as needed)
time.sleep(1)

# Run client.py
client_process = subprocess.Popen(
    ['python3', '/Users/nicogalindez/UTDT/TD4/TP/TP_TD4/TD4-TP/cliente.py'])

# Wait for both processes to finish
server_process.wait()
client_process.wait()
