# attack_sim.py
import time
import random
import os

# Simulamos un log de sistema Linux estándar
LOG_FILE = "server_logs.txt"

ips = ["192.168.1.50", "10.0.0.5", "172.16.0.23", "45.33.22.11"]
users = ["admin", "root", "user", "guest"]

print(f"[*] INICIANDO SIMULACIÓN DE ATAQUE EN: {LOG_FILE}")
print("[*] Presiona Ctrl+C para detener al 'hacker'.")

# Aseguramos que el archivo existe
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w') as f: f.write("")

try:
    while True:
        # Elegimos aleatoriamente si es un login normal o un fallo
        is_attack = random.choice([True, True, False]) # 66% prob de ataque
        
        timestamp = time.strftime("%b %d %H:%M:%S")
        ip = random.choice(ips)
        user = random.choice(users)
        
        if is_attack:
            # Patrón de ataque típico en Linux (Auth Log)
            log_entry = f"{timestamp} server sshd[1234]: Failed password for {user} from {ip} port 2222 ssh2\n"
            print(f"[ATAQUE] Enviando: Failed password for {user} from {ip}")
        else:
            log_entry = f"{timestamp} server sshd[1234]: Accepted password for {user} from {ip} port 2222 ssh2\n"
            print(f"[NORMAL] Login exitoso: {user}")

        with open(LOG_FILE, "a") as f:
            f.write(log_entry)
            
        # Esperamos entre 1 y 3 segundos para darle realismo
        time.sleep(random.uniform(1, 3))

except KeyboardInterrupt:
    print("\n[*] Ataque detenido.")