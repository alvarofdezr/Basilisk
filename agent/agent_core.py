# basilisk/agent_core.py
"""
Basilisk EDR - Agent Core v6.5
------------------------------
Controlador principal. Orquesta módulos y comunicación C2.

[FIX v6.5] Conexión total de módulos al Dashboard (C2).
"""

import sys
import time
import requests
import platform
import os
import hashlib
import urllib3
from typing import Dict, Any, Optional

# Deshabilitar advertencias de certificados auto-firmados
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AGENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(AGENT_DIR, '..'))
sys.path.insert(0, PROJECT_ROOT)

# Core Imports
from basilisk.core.config import Config
from basilisk.core.database import DatabaseManager
from basilisk.core.active_response import kill_process_by_pid
from basilisk.utils.system_monitor import get_system_metrics
from basilisk.utils.logger import Logger
from basilisk.utils.notifier import TelegramNotifier

# Module Imports
from basilisk.modules.network_monitor import NetworkMonitor
from basilisk.modules.usb_monitor import USBMonitor
from basilisk.modules.port_monitor import PortMonitor
from basilisk.modules.process_monitor import ProcessMonitor
from basilisk.modules.fim import FileIntegrityMonitor
from basilisk.modules.threat_intel import ThreatIntel
from basilisk.modules.anti_ransomware import CanarySentry
from basilisk.modules.yara_scanner import YaraScanner

# --- CONSTANTES ---
SERVER_URL = "https://localhost:8443/api/v1"
HOSTNAME = platform.node()
logger = Logger()

class C2Client:
    """Cliente HTTP/HTTPS para comunicación segura."""
    def __init__(self, config: Config):
        self.session = requests.Session()
        self.session.verify = False 
        self.agent_id = f"AGENT_{HOSTNAME}"
        self.server_url = SERVER_URL

    def send_heartbeat(self, status: str) -> Dict[str, Any]:
        metrics = get_system_metrics() 
        try:
            payload = {
                "agent_id": self.agent_id, 
                "hostname": HOSTNAME, 
                "os": platform.system(),
                "status": status, 
                "timestamp": time.time(),
                "cpu_percent": metrics["cpu"], 
                "ram_percent": metrics["ram"]
            }
            res = self.session.post(f"{self.server_url}/heartbeat", json=payload, timeout=5)
            if res.status_code == 200:
                logger.success(f"✅ Heartbeat OK")
                return res.json()
            else:
                logger.error(f"❌ Error C2: {res.status_code}")
                return {}
        except Exception:
            return {}

    def send_alert(self, msg: str, severity: str = "WARNING", alert_type: str = "GENERAL") -> None:
        """Envía alerta al Dashboard."""
        try:
            logger.info(f"📤 Enviando alerta [{alert_type}]: {msg}")
            payload = {
                "agent_id": self.agent_id,
                "type": alert_type,
                "message": msg, 
                "severity": severity
            }
            self.session.post(f"{self.server_url}/alert", json=payload)
        except Exception as e: 
            logger.error(f"Fallo enviando alerta: {e}")

    def upload_report(self, dtype: str, content: Any) -> None:
        try: 
            self.session.post(f"{self.server_url}/report/{dtype}", json={
                "agent_id": self.agent_id, "content": content
            })
        except Exception as e: 
            logger.error(f"Fallo subiendo reporte {dtype}: {e}")

class basiliskAgent:
    """
    Cerebro del Agente Basilisk v6.5.
    """
    def __init__(self):
        logger.info("🛡️ Iniciando Basilisk Agent v6.5...")
        self.config = Config()
        self.db = DatabaseManager(db_name=self.config.db_name)
        self.notifier = TelegramNotifier(self.config)
        
        # 1. Iniciamos el cliente C2 (El "Teléfono")
        self.c2 = C2Client(self.config)
        
        # 2. INICIALIZACIÓN DE MÓDULOS CON CONEXIÓN C2
        
        # YARA (Motor de Detección)
        self.yara = YaraScanner()
        
        # Network Monitor: Ahora envía bloqueos al Dashboard
        # NOTA: Asegúrate de que network_monitor.py está actualizado para aceptar c2_client
        try:
            self.net_mon = NetworkMonitor(self.db, c2_client=self.c2, notifier=self.notifier, config=self.config)
        except TypeError:
            logger.warning("NetworkMonitor no actualizado para C2. Usando modo legacy.")
            self.net_mon = NetworkMonitor(self.db, notifier=self.notifier, config=self.config)

        # USB Monitor: Igual, intentamos pasar C2
        try:
            self.usb_mon = USBMonitor(self.db, c2_client=self.c2) 
        except TypeError:
            # Fallback por si tu USBMonitor.py no tiene el argumento c2_client en __init__
            self.usb_mon = USBMonitor(self.db)

        self.port_mon = PortMonitor(self.db, self.c2)
        self.proc_mon = ProcessMonitor()
        
        # FIM: Monitor de Integridad (Corrección del error que tenías)
        # IMPORTANTE: Asegúrate de que fim.py está actualizado
        try:
            self.fim = FileIntegrityMonitor(self.db, c2_client=self.c2)
        except TypeError:
            logger.error("CRÍTICO: fim.py no está actualizado. No podrá reportar borrados.")
            self.fim = FileIntegrityMonitor(self.db)
        
        self.ti = ThreatIntel(self.config.virustotal_api_key)
        self.ransomware_mon = CanarySentry(on_detection_callback=self._handle_ransomware_alert)

    def _handle_ransomware_alert(self, msg: str) -> None:
        logger.error(f"⚠️ RANSOMWARE DETECTADO: {msg}")
        self.c2.send_alert(msg, "CRITICAL", "RANSOMWARE")
        self.notifier.send_alert(f"☣️ {msg}")

    def _safe_path_validate(self, unsafe_path: str) -> str:
        clean_path = os.path.normpath(unsafe_path)
        if ".." in clean_path: raise ValueError("Path Traversal Blocked")
        if any(c in clean_path for c in [';', '&', '|', '$', '`']): raise ValueError("Invalid Char")
        return clean_path

    def execute_command(self, cmd_data: Any) -> None:
        cmd = cmd_data.get("cmd") if isinstance(cmd_data, dict) else cmd_data
        auth = cmd_data.get("auth", "") if isinstance(cmd_data, dict) else ""
        
        logger.info(f"📥 Comando recibido: {cmd}")

        try:
            if cmd == "CREATE_BASELINE":
                if hasattr(self.config, 'admin_hash') and hashlib.sha512(auth.encode()).hexdigest() == self.config.admin_hash:
                    for folder in self.config.directories:
                        if os.path.exists(folder): self.fim.scan_directory(folder, mode="baseline")
                    self.c2.send_alert("Baseline actualizado por Admin", "INFO", "SECURITY_AUDIT")
                else:
                    self.c2.send_alert("Intento no autorizado de Baseline", "WARNING", "SECURITY_AUDIT")

            elif cmd == "REPORT_PROCESSES":
                self.c2.upload_report("processes", self.proc_mon.scan_processes())
            elif cmd == "REPORT_PORTS":
                self.c2.upload_report("ports", self.port_mon.get_full_report())

            elif cmd.startswith("SCAN_VT:"):
                path = self._safe_path_validate(cmd.split(":", 1)[1])
                if os.path.isfile(path):
                    fhash = self.proc_mon.get_process_hash(path)
                    res = self.ti.check_hash(fhash)
                    if res and res.get('malicious', 0) > 0:
                        self.c2.send_alert(f"VirusTotal: {res['malicious']} motores lo detectan ({os.path.basename(path)})", "CRITICAL", "THREAT_INTEL")
                else:
                    self.c2.send_alert(f"Archivo no encontrado: {path}", "WARNING", "ERROR")

            elif cmd.startswith("KILL:"):
                pid = int(cmd.split(":")[1])
                kill_process_by_pid(pid)
                self.c2.send_alert(f"Proceso {pid} eliminado remotamente", "WARNING", "SHELL_RESPONSE")

            elif cmd.startswith("SCAN_YARA:"):
                path = self._safe_path_validate(cmd.split(":", 1)[1])
                results = self.yara.scan_file(path)
                if results:
                    for match in results:
                        self.c2.send_alert(f"BASILISK DETECTÓ: {match['rule']} en {path}", match['severity'], "YARA_DETECTION")
                else:
                    # Opcional: Avisar que está limpio
                    pass

        except Exception as e:
            logger.error(f"Error ejecución comando: {e}")
            self.c2.send_alert(f"Error ejecución: {e}", "ERROR", "DEBUG")

    def run(self) -> None:
        """Bucle principal de ejecución del Agente."""
        logger.success(f"🚀 Basilisk Agent Activo | C2: {SERVER_URL}")
        
        # Iniciar hilos de monitorización en background
        self.ransomware_mon.start()

        # Contadores para tareas periódicas
        ticks = 0

        while True:
            try:
                # 1. Tareas de Monitorización Pasiva (Rápidas)
                self.net_mon.scan_connections() 
                self.usb_mon.check_usb_changes()
                
                # 2. Tareas Periódicas (Cada 60 segundos aprox si sleep=3)
                # 20 ticks * 3 seg = 60 seg
                if ticks % 20 == 0:
                    # --- ESCANEO DE HIGIENE RECURRENTE ---
                    logger.info("🔍 [Auto-Scan] Revisando telemetría y amenazas...")
                    procesos = self.proc_mon.scan_processes()
                    for p in procesos:
                        # Si es telemetría o malware crítico, enviamos alerta al Feed
                        if p['risk'] in ['WARNING', 'CRITICAL'] and ("TELEMETRY" in p['reason'] or "FORENSIC" in p['reason']):
                            msg = f"Amenaza activa detectada: {p['name']} ({p['reason']})"
                            # Enviamos alerta (evitamos spam masivo si ya se envió hace poco en un sistema real, pero aquí queremos verlo)
                            self.c2.send_alert(msg, p['risk'], "SECURITY_AUDIT")
                    
                    # También repasamos FIM
                    for d in self.config.directories:
                        if os.path.exists(d): self.fim.scan_directory(d, mode="monitor")
                    
                    self.port_mon.scan_ports()

                # 3. Comunicación C2 (Heartbeat)
                data = self.c2.send_heartbeat("ONLINE")
                
                # 4. Ejecución de Comandos
                if data and "command" in data and data["command"]:
                    self.execute_command(data["command"])

                ticks += 1
                time.sleep(3)

            except KeyboardInterrupt:
                logger.info("Deteniendo agente ordenadamente...")
                self.ransomware_mon.stop()
                sys.exit(0)
            except Exception as e: 
                logger.error(f"Error en bucle principal: {e}")
                time.sleep(5)

if __name__ == "__main__":
    basiliskAgent().run()