# basilisk/core/agent_core.py
"""
Basilisk EDR - Agent Core v6.6 (Fixed Command Execution)
--------------------------------------------------------
Controlador principal multihilo.
[FIX] Restaurada la lógica de REPORT_PROCESSES y REPORT_PORTS.
"""

import sys
import time
import requests
import platform
import os
import hashlib
import urllib3
import threading
import json
from typing import Dict, Any, Optional

# Deshabilitar advertencias de certificados auto-firmados
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AGENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(AGENT_DIR, '..'))
sys.path.insert(0, PROJECT_ROOT)

# --- FALLBACK UTILS ---
try:
    from basilisk.utils.system_monitor import get_system_metrics
    from basilisk.utils.logger import Logger
    from basilisk.utils.notifier import TelegramNotifier
except ImportError:
    print("⚠️  [AVISO] Utils no encontrados. Usando Fallbacks básicos.")
    def get_system_metrics(): return {"cpu": 0, "ram": 0}
    class Logger:
        def info(self, m): print(f"[INFO] {m}")
        def success(self, m): print(f"[OK] {m}")
        def warning(self, m): print(f"[WARN] {m}")
        def error(self, m): print(f"[ERR] {m}")
    class TelegramNotifier:
        def __init__(self, c): pass
        def send_alert(self, m): print(f"[TELEGRAM SIM] {m}")

# Core Imports
try:
    from basilisk.core.config import Config
    from basilisk.core.database import DatabaseManager
    from basilisk.core.active_response import kill_process_by_pid
    # Module Imports
    from basilisk.modules.network_monitor import NetworkMonitor
    from basilisk.modules.usb_monitor import USBMonitor
    from basilisk.modules.port_monitor import PortMonitor
    from basilisk.modules.process_monitor import ProcessMonitor
    from basilisk.modules.fim import FileIntegrityMonitor
    from basilisk.modules.threat_intel import ThreatIntel
    from basilisk.modules.anti_ransomware import CanarySentry
    from basilisk.modules.yara_scanner import YaraScanner
    from basilisk.modules.network_isolation import NetworkIsolator
except ImportError as e:
    print(f"❌ Error Crítico: Faltan módulos base: {e}")
    sys.exit(1)

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
            res = self.session.post(f"{self.server_url}/heartbeat", json=payload, timeout=2)
            if res.status_code == 200:
                return res.json()
            return {}
        except Exception:
            return {}

    def send_alert(self, msg: str, severity: str = "WARNING", alert_type: str = "GENERAL") -> None:
        try:
            logger.info(f"📤 Enviando alerta [{alert_type}]: {msg}")
            payload = {
                "agent_id": self.agent_id,
                "type": alert_type,
                "message": msg, 
                "severity": severity
            }
            self.session.post(f"{self.server_url}/alert", json=payload, timeout=3)
        except Exception: pass

    def upload_report(self, dtype: str, content: Any) -> None:
        """Sube reportes grandes (procesos, puertos) al C2."""
        try: 
            logger.info(f"📤 Subiendo reporte: {dtype} ({len(content)} items)")
            self.session.post(f"{self.server_url}/report/{dtype}", json={
                "agent_id": self.agent_id, "content": content
            }, timeout=5)
        except Exception as e: 
            logger.error(f"Fallo subiendo reporte {dtype}: {e}")

class BasiliskAgent:
    """
    Cerebro del Agente Basilisk v7.1
    """
    def __init__(self):
        logger.info("🛡️ Iniciando Basilisk Agent v7.1...")
        self.running = False
        self.threads = []
        
        self.config = Config()
        self.db = DatabaseManager(db_name=self.config.db_name)
        self.notifier = TelegramNotifier(self.config)
        self.c2 = C2Client(self.config)
        
        # --- CARGA DE MÓDULOS ---
        self.yara = YaraScanner()
        self.isolator = NetworkIsolator(SERVER_URL)
        self.proc_mon = ProcessMonitor()
        self.ti = ThreatIntel(getattr(self.config, 'virustotal_api_key', ''))
        
        # Módulos con manejo de compatibilidad
        try: self.net_mon = NetworkMonitor(self.db, c2_client=self.c2, notifier=self.notifier, config=self.config)
        except TypeError: self.net_mon = NetworkMonitor(self.db, notifier=self.notifier, config=self.config)

        try: self.usb_mon = USBMonitor(self.db, c2_client=self.c2) 
        except TypeError: self.usb_mon = USBMonitor(self.db)

        # PortMonitor necesita C2 para reportar
        try: self.port_mon = PortMonitor(self.db, c2_client=self.c2)
        except TypeError: self.port_mon = PortMonitor(self.db, None)

        try: self.fim = FileIntegrityMonitor(self.db, c2_client=self.c2)
        except TypeError: self.fim = FileIntegrityMonitor(self.db)
        
        self.ransomware_mon = CanarySentry(on_detection_callback=self._handle_ransomware_alert)

    def _handle_ransomware_alert(self, msg: str) -> None:
        logger.error(f"⚠️ RANSOMWARE DETECTADO: {msg}")
        self.c2.send_alert(msg, "CRITICAL", "RANSOMWARE")
        self.notifier.send_alert(f"☣️ {msg}")

    # --- [FIX] LÓGICA DE COMANDOS RESTAURADA ---
    def execute_command(self, cmd_data: Any) -> None:
        cmd = cmd_data.get("cmd") if isinstance(cmd_data, dict) else cmd_data
        cmd_str = str(cmd)
        logger.info(f"📥 Comando recibido: {cmd_str}")
        
        try:
            # 1. REPORTES (Lo que estaba fallando)
            if cmd_str == "REPORT_PROCESSES":
                data = self.proc_mon.scan_processes()
                self.c2.upload_report("processes", data)
                
            elif cmd_str == "REPORT_PORTS":
                if self.port_mon:
                    data = self.port_mon.get_full_report()
                    self.c2.upload_report("ports", data)
                else:
                    logger.warning("PortMonitor no disponible")

            # 2. RESPUESTA ACTIVA
            elif cmd_str.startswith("KILL:"):
                try:
                    pid = int(cmd_str.split(":")[1])
                    kill_process_by_pid(pid)
                    self.c2.send_alert(f"Proceso {pid} eliminado remotamente", "INFO", "RESPONSE")
                except ValueError: pass

            elif cmd_str == "ISOLATE_HOST":
                if self.isolator.isolate_host():
                    self.c2.send_alert("HOST AISLADO: Tráfico bloqueado.", "CRITICAL", "NET_DEFENSE")

            elif cmd_str == "UNISOLATE_HOST":
                self.isolator.restore_connection()
                self.c2.send_alert("Conectividad restaurada.", "INFO", "NET_ALLOW")

            elif cmd_str == "CREATE_BASELINE":
                # Escaneo de FIM bajo demanda
                target = getattr(self.config, 'directories', ["."])[0]
                self.fim.scan_directory(target, mode="baseline")
                self.c2.send_alert("Baseline FIM actualizado.", "INFO", "SECURITY_AUDIT")

            elif cmd_str.startswith("SCAN_YARA:"):
                path = cmd_str.split(":", 1)[1]
                matches = self.yara.scan_file(path)
                if matches:
                    self.c2.send_alert(f"YARA Match: {path}", "CRITICAL", "YARA_DETECTION")
                else:
                    self.c2.send_alert(f"Escaneo limpio: {path}", "INFO", "SECURITY_AUDIT")

        except Exception as e:
            logger.error(f"Error ejecutando comando {cmd_str}: {e}")
            self.c2.send_alert(f"Fallo de ejecución: {e}", "ERROR", "DEBUG")

    # --- WORKERS ---
    def _worker_process_monitor(self):
        while self.running:
            try:
                # Análisis de procesos automático (light)
                procesos = self.proc_mon.scan_processes()
                for p in procesos:
                    if p.get('risk') == 'CRITICAL':
                        # Solo enviamos alerta si es crítico para no saturar
                        self.c2.send_alert(f"Proceso Crítico: {p['name']}", "CRITICAL", "PROCESS_ALERT")
                time.sleep(20) 
            except Exception: time.sleep(5)

    def _worker_fim(self):
        targets = getattr(self.config, 'directories', ["."])
        while self.running:
            try:
                for folder in targets:
                    if os.path.exists(folder): self.fim.scan_directory(folder, mode="monitor")
                time.sleep(30)
            except Exception: time.sleep(10)

    def _worker_network(self):
        while self.running:
            try:
                if self.net_mon: self.net_mon.scan_connections()
                time.sleep(5)
            except Exception: time.sleep(5)

    def start(self):
        self.running = True
        if self.ransomware_mon: self.ransomware_mon.start()

        # Iniciar Hilos
        t_proc = threading.Thread(target=self._worker_process_monitor, name="T-Proc", daemon=True)
        t_fim = threading.Thread(target=self._worker_fim, name="T-FIM", daemon=True)
        t_net = threading.Thread(target=self._worker_network, name="T-Net", daemon=True)
        
        self.threads = [t_proc, t_fim, t_net]
        for t in self.threads: t.start()

        logger.success(f"🚀 Agente activo. ID: {self.c2.agent_id}")

        # Bucle Principal (Heartbeat + Comandos)
        try:
            while True:
                if self.usb_mon: self.usb_mon.check_usb_changes()
                
                # HEARTBEAT & COMANDOS
                response = self.c2.send_heartbeat("ONLINE")
                if response and "command" in response and response["command"]:
                    # Ejecutar comando recibido del servidor
                    self.execute_command(response["command"])
                
                time.sleep(3) # Intervalo de heartbeat

        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        if self.ransomware_mon: self.ransomware_mon.stop()
        sys.exit(0)

if __name__ == "__main__":
    BasiliskAgent().start()