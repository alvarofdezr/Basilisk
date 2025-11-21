# pysentinel/modules/log_watcher.py
import time
import re
import os
from pysentinel.utils.logger import Logger
# No importamos el notificador aquí para evitar ciclos, lo recibimos como argumento

class LogWatcher:
    # AÑADIMOS notifier=None AL CONSTRUCTOR
    def __init__(self, db_manager, log_path="server_logs.txt", notifier=None):
        self.db = db_manager 
        self.log_path = log_path
        self.notifier = notifier
        self.current_position = 0
        
        if os.path.exists(self.log_path):
            self.current_position = os.path.getsize(self.log_path)

        self.regex_bruteforce = re.compile(r"Failed password for (\w+) from ([\d\.]+)")

    def monitor_changes(self):
        if not os.path.exists(self.log_path): return

        with open(self.log_path, "r") as f:
            f.seek(self.current_position)
            lines = f.readlines()
            self.current_position = f.tell()

            for line in lines:
                self._analyze_line(line)

    def _analyze_line(self, line):
        match = self.regex_bruteforce.search(line)
        if match:
            user = match.group(1)
            ip = match.group(2)
            
            msg = f"Intrusión SSH detectada - User: {user} IP: {ip}"
            
            # 1. Log consola
            # 2. Alerta Telegram
            if self.notifier: self.notifier.send_alert(msg)
            
            # 3. GUARDAR EN HISTORIAL (NUEVO)
            self.db.log_event("AUTH", msg, "CRITICAL")