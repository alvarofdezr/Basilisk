# pysentinel/modules/log_watcher.py
import time
import re
import os
from pysentinel.utils.logger import Logger

class LogWatcher:
    def __init__(self, log_path="server_logs.txt"):
        self.log_path = log_path
        self.logger = Logger()
        self.current_position = 0
        
        # Si el archivo ya existe, vamos al final para no leer logs viejos
        if os.path.exists(self.log_path):
            self.current_position = os.path.getsize(self.log_path)

        # EXPRESIÓN REGULAR (REGEX) - Aquí está la magia
        # Busca la frase "Failed password" y captura el usuario y la IP
        self.regex_bruteforce = re.compile(r"Failed password for (\w+) from ([\d\.]+)")

    def monitor_changes(self):
        """Lee solo las nuevas líneas añadidas al archivo."""
        if not os.path.exists(self.log_path):
            return

        with open(self.log_path, "r") as f:
            # Saltamos a donde nos quedamos la última vez
            f.seek(self.current_position)
            
            lines = f.readlines()
            
            # Guardamos la nueva posición para la próxima vez
            self.current_position = f.tell()

            for line in lines:
                self._analyze_line(line)

    def _analyze_line(self, line):
        # Buscamos coincidencias con nuestra Regex
        match = self.regex_bruteforce.search(line)
        
        if match:
            user = match.group(1) # El primer paréntesis del regex
            ip = match.group(2)   # El segundo paréntesis del regex
            
            # ALERTA DE SEGURIDAD
            self.logger.warning(f"INTRUSIÓN DETECTADA: Login fallido -> User: {user} | IP: {ip}")