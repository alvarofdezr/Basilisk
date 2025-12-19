# agent/agent_core.py
"""
Basilisk EDR - Agent Core v6.6.0
"""
import sys
import time
import requests
import platform
import os
import urllib3
import threading
import json
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor

# Deshabilitar advertencias de certificados auto-firmados (necesario para la infraestructura PKI actual)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuración de rutas
AGENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(AGENT_DIR, '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Imports de Módulos Basilisk
try:
    from basilisk.core.config import Config
    from basilisk.core.database import DatabaseManager
    from basilisk.core.active_response import kill_process_by_pid
    from basilisk.modules.network_monitor import NetworkMonitor
    from basilisk.modules.usb_monitor import USBMonitor
    from basilisk.modules.port_monitor import PortMonitor
    from basilisk.modules.process_monitor import ProcessMonitor
    from basilisk.modules.fim import FileIntegrityMonitor
    from basilisk.modules.threat_intel import ThreatIntel
    from basilisk.modules.anti_ransomware import CanarySentry
    from basilisk.modules.yara_scanner import YaraScanner
    from basilisk.modules.network_isolation import NetworkIsolator
    from basilisk.modules.audit_scanner import AuditScanner  
    from basilisk.utils.system_monitor import get_system_metrics
    from basilisk.utils.logger import Logger
    from basilisk.utils.notifier import TelegramNotifier
except ImportError as e:
    print(f"❌ CRITICAL: Missing Basilisk modules. Error: {e}")
    sys.exit(1)

# Constantes Globales
HOSTNAME = platform.node()
logger = Logger()

class C2Client:
    """Cliente HTTP/HTTPS para comunicación segura con el servidor C2."""
    def __init__(self, config: Config):
        self.session = requests.Session()
        self.session.verify = False  # Usamos certificados autofirmados
        self.agent_id = f"AGENT_{HOSTNAME}"
        self.server_url = config.c2_url

    def send_heartbeat(self, status: str) -> Dict[str, Any]:
        metrics = get_system_metrics()
        try:
            payload = {
                "agent_id": self.agent_id,
                "hostname": HOSTNAME,
                "os": platform.system(),
                "status": status,
                "timestamp": time.time(),
                "cpu_percent": metrics.get("cpu", 0.0),
                "ram_percent": metrics.get("ram", 0.0)
            }
            # Timeout corto para no bloquear el bucle principal
            res = self.session.post(f"{self.server_url}/api/v1/heartbeat", json=payload, timeout=2)
            if res.status_code == 200:
                return res.json()
            return {}
        except Exception:
            return {}

    def send_alert(self, msg: str, severity: str = "WARNING", alert_type: str = "GENERAL") -> None:
        try:
            logger.info(f"📤 Alert: {msg}")
            payload = {
                "agent_id": self.agent_id,
                "type": alert_type,
                "message": msg,
                "severity": severity
            }
            self.session.post(f"{self.server_url}/api/v1/alert", json=payload, timeout=3)
        except Exception:
            pass

    def upload_report(self, dtype: str, content: Any) -> None:
        """Sube reportes grandes (procesos, puertos) al C2."""
        try:
            logger.info(f"📤 Report upload: {dtype} ({len(content)} items)")
            self.session.post(f"{self.server_url}/api/v1/report/{dtype}", json={
                "agent_id": self.agent_id, "content": content
            }, timeout=10)
        except Exception as e:
            logger.error(f"Report upload failed ({dtype}): {e}")

class BasiliskAgent:
    """
    Núcleo del Agente Basilisk.
    Orquesta los módulos de seguridad y gestiona la comunicación asíncrona.
    """
    def __init__(self):
        VERDE = "\033[92m"
        RESET = "\033[0m"
        
        banner = r"""
        ██████╗  █████╗ ███████╗██╗██╗     ██╗███████╗██╗  ██╗
        ██╔══██╗██╔══██╗██╔════╝██║██║     ██║██╔════╝██║ ██╔╝
        ██████╔╝███████║███████╗██║██║     ██║███████╗█████╔╝ 
        ██╔══██╗██╔══██║╚════██║██║██║     ██║╚════██║██╔═██╗ 
        ██████╔╝██║  ██║███████║██║███████╗██║███████║██║  ██╗
        ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝╚══════╝╚═╝  ╚═╝
                                            Endpoint Agent v6.6
        """
        print(f"{VERDE}{banner}{RESET}")
        logger.info("🛡️ Initializing Basilisk Agent v6.6.0...")
        self.running = False
        
        # 1. Carga de Configuración y Utilidades
        self.config = Config()
        self.db = DatabaseManager(db_name=self.config.db_name)
        self.notifier = TelegramNotifier(self.config)
        self.c2 = C2Client(self.config)
        
        # 2. Inicialización de Módulos
        self.yara = YaraScanner()
        self.audit = AuditScanner()
        self.isolator = NetworkIsolator(self.config.c2_url)
        self.proc_mon = ProcessMonitor()
        self.ti = ThreatIntel(self.config.virustotal_api_key)
        
        # Módulos con dependencias cruzadas
        self.net_mon = NetworkMonitor(self.db, c2_client=self.c2, notifier=self.notifier, config=self.config)
        self.usb_mon = USBMonitor(self.db, c2_client=self.c2)
        self.port_mon = PortMonitor(self.db, c2_client=self.c2)
        self.fim = FileIntegrityMonitor(self.db)
        self.ransomware_mon = CanarySentry(on_detection_callback=self._handle_ransomware_alert)

        # 3. Pool de Ejecución Asíncrona (Para no bloquear el heartbeat)
        # Max workers = 2 para evitar saturar la CPU con comandos concurrentes
        self.command_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="AsyncWorker")

    def _handle_ransomware_alert(self, msg: str) -> None:
        """Callback de alta prioridad para detección de ransomware."""
        logger.error(f"⚠️ RANSOMWARE DETECTED: {msg}")
        self.c2.send_alert(msg, "CRITICAL", "RANSOMWARE")
        self.notifier.send_alert(f"☣️ {msg}")

    def _run_command_logic(self, cmd_str: str) -> None:
        """
        Lógica interna de ejecución de comandos.
        Se ejecuta en un hilo separado del principal.
        """
        try:
            logger.info(f"⚡ Executing async task: {cmd_str}")

            # --- REPORTING ---
            if cmd_str == "REPORT_PROCESSES":
                data = self.proc_mon.scan_processes()
                self.c2.upload_report("processes", data)
                
            elif cmd_str == "REPORT_PORTS":
                data = self.port_mon.get_full_report()
                self.c2.upload_report("ports", data)

            # --- RESPUESTA ACTIVA ---
            elif cmd_str.startswith("KILL:"):
                try:
                    pid = int(cmd_str.split(":")[1])
                    if kill_process_by_pid(pid):
                        self.c2.send_alert(f"Threat neutralized: PID {pid}", "INFO", "RESPONSE")
                    else:
                        self.c2.send_alert(f"Failed to kill PID {pid}", "ERROR", "RESPONSE")
                except ValueError:
                    pass

            elif cmd_str == "ISOLATE_HOST":
                if self.isolator.isolate_host():
                    self.c2.send_alert("HOST ISOLATED. Network lockdown active.", "CRITICAL", "NET_DEFENSE")

            elif cmd_str == "UNISOLATE_HOST":
                if self.isolator.restore_connection():
                    self.c2.send_alert("Connectivity restored.", "INFO", "NET_ALLOW")
            elif cmd_str == "RUN_AUDIT":
                report = self.audit.perform_audit()
                self.c2.upload_report("audit", report)
                self.c2.send_alert("Compliance Audit uploaded.", "INFO", "SECURITY_AUDIT")
            elif cmd_str == "REPORT_NETWORK_MAP":
                data = self.net_mon.get_network_snapshot()
                self.c2.upload_report("network_map", data)
                
            # --- FORENSE Y AUDITORÍA ---
            elif cmd_str == "CREATE_BASELINE":
                # Operación pesada (I/O intensiva)
                target = self.config.directories[0] if self.config.directories else "."
                self.fim.scan_directory(target, mode="baseline")
                self.c2.send_alert("FIM Baseline updated successfully.", "INFO", "SECURITY_AUDIT")

            elif cmd_str.startswith("SCAN_YARA:"):
                # Operación pesada (CPU intensiva)
                path_arg = cmd_str.split(":", 1)[1].strip()
                matches = self.yara.scan_file(path_arg)
                if matches:
                    self.c2.send_alert(f"YARA Match found: {path_arg}", "CRITICAL", "YARA_DETECTION")
                else:
                    self.c2.send_alert(f"Scan clean: {path_arg}", "INFO", "SECURITY_AUDIT")
            
            logger.success(f"Task completed: {cmd_str}")

        except Exception as e:
            logger.error(f"Async command error ({cmd_str}): {e}")
            self.c2.send_alert(f"Execution error: {e}", "ERROR", "DEBUG")

    def execute_command(self, cmd_data: Any) -> None:
        """
        Recibe el comando del C2 y lo delega inmediatamente al pool de hilos.
        """
        cmd = cmd_data.get("cmd") if isinstance(cmd_data, dict) else cmd_data
        cmd_str = str(cmd)
        
        # Delegar ejecución para liberar el bucle principal
        self.command_executor.submit(self._run_command_logic, cmd_str)

    # --- WORKERS (Hilos de monitoreo continuo) ---

    def _worker_process_monitor(self):
        while self.running:
            try:
                # El scan_processes ahora usa Delta Scanning (ligero)
                procesos = self.proc_mon.scan_processes()
                for p in procesos:
                    if p.get('risk') == 'CRITICAL':
                        # Solo alertar de críticos para no saturar
                        self.c2.send_alert(f"Critical Process: {p['name']}", "CRITICAL", "PROCESS_ALERT")
                time.sleep(20) 
            except Exception:
                time.sleep(5)

    def _worker_fim(self):
        targets = self.config.directories
        while self.running:
            try:
                for folder in targets:
                    if os.path.exists(folder):
                        # FIM ahora usa Smart Caching (ligero)
                        self.fim.scan_directory(folder, mode="monitor")
                time.sleep(30)
            except Exception:
                time.sleep(10)

    def _worker_network(self):
        while self.running:
            try:
                if self.net_mon:
                    # NetMon ahora usa su propio ThreadPool interno para alertas UI
                    self.net_mon.scan_connections()
                time.sleep(5)
            except Exception:
                time.sleep(5)

    def start(self):
        """Inicia el ciclo de vida del agente."""
        self.running = True
        
        # 1. Iniciar Vigilancia Anti-Ransomware
        if self.ransomware_mon:
            self.ransomware_mon.start()

        # 2. Iniciar Hilos de Monitoreo
        threads = [
            threading.Thread(target=self._worker_process_monitor, name="T-Proc", daemon=True),
            threading.Thread(target=self._worker_fim, name="T-FIM", daemon=True),
            threading.Thread(target=self._worker_network, name="T-Net", daemon=True)
        ]
        
        for t in threads:
            t.start()

        logger.success(f"🚀 Agent active. ID: {self.c2.agent_id}")

        # 3. Bucle Principal (Heartbeat + Recepción de Comandos)
        try:
            while True:
                # Tareas síncronas muy ligeras
                if self.usb_mon:
                    self.usb_mon.check_usb_changes()
                
                # Check-in con el C2
                response = self.c2.send_heartbeat("ONLINE")
                
                # Procesar órdenes
                if response and "command" in response and response["command"]:
                    self.execute_command(response["command"])
                
                time.sleep(3) # Intervalo de heartbeat

        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Detención ordenada de servicios."""
        logger.info("Stopping agent services...")
        self.running = False
        
        # Apagar pool de comandos (no espera a que terminen tareas largas si se fuerza salida)
        self.command_executor.shutdown(wait=False)
        
        if self.ransomware_mon:
            self.ransomware_mon.stop()
            
        sys.exit(0)

if __name__ == "__main__":
    BasiliskAgent().start()