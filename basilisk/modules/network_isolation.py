# basilisk/modules/network_isolation.py
"""
Basilisk EDR - Network Isolation Module v7.0
Implementa 'Active Response' manipulando el Firewall de Windows.
Permite aislar un host manteniendo la línea de vida con el C2.
"""

import subprocess
import socket
from urllib.parse import urlparse
from typing import List, Optional
from basilisk.utils.logger import Logger

class NetworkIsolator:
    def __init__(self, c2_url: str):
        self.logger = Logger()
        self.c2_url = c2_url
        self.rule_prefix = "Basilisk_Isolation"

    def _get_c2_ip(self) -> str:
        """Resuelve la IP del C2 para la whitelist de forma segura."""
        if not self.c2_url:
            return ""
            
        try:
            parsed = urlparse(self.c2_url)
            hostname = parsed.hostname
            
            if not hostname:
                return ""
                
            if hostname in ["localhost", "127.0.0.1"]:
                return "127.0.0.1"
                
            return socket.gethostbyname(hostname)
            
        except Exception as e:
            self.logger.error(f"Fallo resolviendo IP C2: {e}")
            return ""

    def _run_netsh(self, args: List[str]) -> bool:
        """Ejecuta comandos netsh de forma segura."""
        try:
            cmd = ["netsh", "advfirewall", "firewall"] + args
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False

    def isolate_host(self) -> bool:
        """
        1. Bloquea todo el tráfico de salida/entrada.
        2. Permite tráfico explícito al C2.
        3. Permite DNS (UDP 53) para resolución básica.
        """
        c2_ip = self._get_c2_ip()
        
        if not c2_ip:
            self.logger.error("No se puede aislar: Imposible resolver IP del C2.")
            return False

        self.logger.warning(f"🛡️ INICIANDO PROTOCOLO DE AISLAMIENTO. C2 IP: {c2_ip}")

        self.restore_connection()

        self._run_netsh([
            "add", "rule", f"name={self.rule_prefix}_C2_OUT", 
            "dir=out", "action=allow", "protocol=TCP", 
            f"remoteip={c2_ip}"
        ])
        
        self._run_netsh([
            "add", "rule", f"name={self.rule_prefix}_DNS", 
            "dir=out", "action=allow", "protocol=UDP", "remoteport=53"
        ])

        self._run_netsh([
            "add", "rule", f"name={self.rule_prefix}_BLOCK_ALL_OUT", 
            "dir=out", "action=block"
        ])
        self._run_netsh([
            "add", "rule", f"name={self.rule_prefix}_BLOCK_ALL_IN", 
            "dir=in", "action=block"
        ])

        self.logger.success("🔒 HOST AISLADO EXITOSAMENTE.")
        return True

    def restore_connection(self) -> bool:
        """Elimina todas las reglas de aislamiento de Basilisk."""
        self.logger.info("🔓 Restaurando conectividad de red...")
        
        rules = [
            f"{self.rule_prefix}_C2_OUT",
            f"{self.rule_prefix}_DNS",
            f"{self.rule_prefix}_BLOCK_ALL_OUT",
            f"{self.rule_prefix}_BLOCK_ALL_IN"
        ]
        
        for rule in rules:
            self._run_netsh(["delete", "rule", f"name={rule}"])
            
        self.logger.success("✅ Conectividad restaurada.")
        return True