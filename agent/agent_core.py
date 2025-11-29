# pysentinel/agent_core.py
"""
PySentinel Agent Core v6.2
--------------------------
Módulo principal del agente EDR. Gestiona la comunicación con el C2,
la ejecución de módulos de monitorización y la respuesta a incidentes.

HARDENING APPLIED (v6.2):
- Comunicación forzada sobre HTTPS.
- Sanitización estricta de rutas (Anti-Path Traversal).
- Validación de comandos para prevenir inyección (Anti-RCE).
"""

import sys
import time
import requests
import platform
import os
import hashlib
import urllib3
from typing import Dict, Any, Optional

# Deshabilitar advertencias de certificados auto-firmados (Solo entorno Dev/Académico)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AGENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(AGENT_DIR, '..'))
sys.path.insert(0, PROJECT_ROOT)

# Core Imports
from pysentinel.core.config import Config
from pysentinel.core.database import DatabaseManager
from pysentinel.core.active_response import kill_process_by_pid
from pysentinel.utils.system_monitor import get_system_metrics
from pysentinel.utils.logger import Logger
from pysentinel.utils.notifier import TelegramNotifier

# Module Imports
from pysentinel.modules.network_monitor import NetworkMonitor
from pysentinel.modules.usb_monitor import USBMonitor
from pysentinel.modules.port_monitor import PortMonitor
from pysentinel.modules.process_monitor import ProcessMonitor
from pysentinel.modules.fim import FileIntegrityMonitor
from pysentinel.modules.threat_intel import ThreatIntel
from pysentinel.modules.anti_ransomware import CanarySentry

# --- CONSTANTES DE CONFIGURACIÓN ---
# [SEGURIDAD CRÍTICA] Cambio a HTTPS y puerto seguro por defecto.
SERVER_URL = "https://localhost:8443/api/v1"
HOSTNAME = platform.node()

# Initialize Global Logger
logger = Logger()

class C2Client:
    """
    Cliente HTTP/HTTPS para comunicación segura con el servidor C2.
    """
    def __init__(self, config: Config):
        self.session = requests.Session()
        # En producción real, 'verify' debería apuntar al path del certificado CA (.pem)
        self.session.verify = False 
        self.agent_id = f"AGENT_{HOSTNAME}"
        self.server_url = SERVER_URL

    def send_heartbeat(self, status: str) -> Dict[str, Any]:
        system_metrics = get_system_metrics() 
        try:
            payload = {
                "agent_id": self.agent_id, 
                "hostname": HOSTNAME, 
                "os": platform.system(),
                "status": status, 
                "timestamp": time.time(),
                "cpu_percent": system_metrics["cpu"], 
                "ram_percent": system_metrics["ram"]
            }
            
            res = self.session.post(
                f"{self.server_url}/heartbeat", 
                json=payload, 
                timeout=5,
                verify=False # Importante para certificados auto-firmados
            )
            
            if res.status_code == 200:
                logger.success(f"✅ Heartbeat OK (C2 Respondió)")
                return res.json()
            else:
                # Si el servidor responde con error (ej: 422, 500), imprimirlo
                logger.error(f"❌ Error del Servidor: {res.status_code} - {res.text}")
                return {}
            
        except Exception as e:
            # Aquí veremos si es un error de SSL, conexión o timeout
            logger.error(f"❌ FALLO DE CONEXIÓN: {e}")
            return {}
        
    def send_alert(self, msg: str, severity: str = "WARNING", alert_type: str = "GENERAL") -> None:
        """Transmite alertas de seguridad críticas al C2."""
        try:
            logger.info(f"📤 Enviando alerta [{severity}]: {msg}")
            payload = {
                "agent_id": self.agent_id,
                "type": alert_type,
                "message": msg, 
                "severity": severity,
                "timestamp": time.time()
            }
            self.session.post(f"{self.server_url}/alert", json=payload)
        except Exception as e: 
            logger.error(f"Fallo al enviar alerta al C2: {e}")

    def upload_report(self, dtype: str, content: Any) -> None:
        """Sube reportes estructurados (JSON) de gran tamaño."""
        try: 
            self.session.post(f"{self.server_url}/report/{dtype}", json={
                "agent_id": self.agent_id, "content": content
            })
        except Exception as e: 
            logger.error(f"Fallo subiendo reporte {dtype}: {e}")

class PySentinelAgent:
    """
    Controlador Principal del Agente.
    Orquesta los módulos de seguridad y ejecuta la lógica de respuesta.
    """
    def __init__(self):
        logger.info("🛡️ Iniciando PySentinel Agent v6.2...")
        self.config = Config()
        self.db = DatabaseManager(db_name=self.config.db_name)
        self.notifier = TelegramNotifier(self.config)
        self.c2 = C2Client(self.config)
        
        # Inicialización de Módulos
        self.net_mon = NetworkMonitor(self.db, self.c2, self.config)
        self.usb_mon = USBMonitor(self.db, self.c2)
        self.port_mon = PortMonitor(self.db, self.c2)
        self.proc_mon = ProcessMonitor()
        self.fim = FileIntegrityMonitor(self.db)
        self.ti = ThreatIntel(self.config.virustotal_api_key)
        
        # Módulos Reactivos (Background)
        self.ransomware_mon = CanarySentry(on_detection_callback=self._handle_ransomware_alert)

    def _handle_ransomware_alert(self, msg: str) -> None:
        """Callback de alta prioridad para detección de Ransomware."""
        logger.error(f"⚠️ AMENAZA CRÍTICA DETECTADA: {msg}")
        self.c2.send_alert(msg, "CRITICAL", "RANSOMWARE")
        self.notifier.send_alert(f"☣️ {msg}")

    def _safe_path_validate(self, unsafe_path: str) -> str:
        """
        [SEGURIDAD] Valida y sanitiza rutas de archivos para evitar Path Traversal.
        Lanza ValueError si la ruta es sospechosa.
        """
        # 1. Normalizar ruta (resuelve '..')
        clean_path = os.path.normpath(unsafe_path)
        
        # 2. Verificar Path Traversal explícito
        if ".." in clean_path:
            raise ValueError(f"Intento de Path Traversal detectado: {unsafe_path}")
        
        # 3. Verificar caracteres de inyección de comandos (Defensa en profundidad)
        forbidden_chars = [';', '&', '|', '$', '`', '\n']
        if any(char in clean_path for char in forbidden_chars):
            raise ValueError("Caracteres inválidos detectados en la ruta.")

        return clean_path

    def execute_command(self, cmd_data: Any) -> None:
        """
        Parsea y ejecuta comandos recibidos del C2 de forma segura.
        """
        cmd = cmd_data
        auth = ""
        
        if isinstance(cmd_data, dict):
            cmd = cmd_data.get("cmd")
            auth = cmd_data.get("auth", "")

        logger.info(f"📥 Procesando comando: {cmd}")
        
        try:
            # --- COMANDOS ADMINISTRATIVOS ---
            if cmd == "CREATE_BASELINE":
                input_hash = hashlib.sha512(auth.encode()).hexdigest()
                # Validación de autenticación local para acciones críticas
                if hasattr(self.config, 'admin_hash') and input_hash == self.config.admin_hash:
                    logger.success("Autenticación Admin OK. Actualizando FIM Baseline...")
                    for folder in self.config.directories:
                        if os.path.exists(folder):
                            self.fim.scan_directory(folder, mode="baseline")
                    self.c2.send_alert("FIM Baseline actualizado por Administrador.", "INFO", "FIM")
                else:
                    logger.warning("Fallo de autenticación en comando crítico.")
                    self.c2.send_alert("Intento no autorizado de modificar Baseline.", "WARNING", "SECURITY")

            # --- COMANDOS OPERATIVOS ---
            elif cmd == "REPORT_PROCESSES":
                data = self.proc_mon.scan_processes()
                self.c2.upload_report("processes", data)
                
            elif cmd == "REPORT_PORTS":
                data = self.port_mon.get_full_report()
                self.c2.upload_report("ports", data)
                
            # --- COMANDOS CON ARGUMENTOS (SANITIZADOS) ---
            elif cmd.startswith("SCAN_VT:"):
                try:
                    raw_path = cmd.split(":", 1)[1]
                    # Validar ruta antes de usarla
                    path = self._safe_path_validate(raw_path)
                    
                    if not os.path.isfile(path):
                        raise ValueError("El archivo no existe.")

                    fhash = self.proc_mon.get_process_hash(path)
                    if fhash:
                        logger.info(f"Consultando VirusTotal para: {os.path.basename(path)}")
                        res = self.ti.check_hash(fhash)
                        if res:
                            mal = res.get('malicious', 0)
                            total = res.get('total', 0)
                            msg = f"VT Result [{os.path.basename(path)}]: {mal}/{total} motores detectaron malicia."
                            severity = "CRITICAL" if mal > 0 else "INFO"
                            self.c2.send_alert(msg, severity, "THREAT_INTEL")
                    else:
                        self.c2.send_alert(f"No se pudo generar hash para: {path}", "WARNING", "ERROR")
                
                except ValueError as ve:
                    logger.warning(f"Comando SCAN_VT bloqueado por seguridad: {ve}")
                    self.c2.send_alert(f"Intento de inyección/path traversal bloqueado: {ve}", "CRITICAL", "SECURITY_AUDIT")

            elif cmd.startswith("KILL:"):
                try:
                    # Validación estricta de tipo entero
                    pid_str = cmd.split(":")[1]
                    if not pid_str.isdigit():
                        raise ValueError("PID debe ser numérico")
                    
                    pid = int(pid_str)
                    success = kill_process_by_pid(pid)
                    status = "TERMINATED" if success else "FAILED"
                    self.c2.send_alert(f"KILL PID {pid} resultado: {status}", "WARNING", "RESPONSE")
                except ValueError:
                    logger.error("Formato de PID inválido recibido en comando KILL.")

        except Exception as e:
            logger.error(f"Excepción no controlada ejecutando comando: {e}")
            self.c2.send_alert(f"Error de ejecución en agente: {str(e)}", "ERROR", "DEBUG")

    def run(self) -> None:
        """Bucle principal de ejecución del Agente."""
        logger.success(f"🚀 Agente Activo en: {HOSTNAME} | C2: {SERVER_URL}")
        
        # Iniciar hilos de monitorización en background
        self.ransomware_mon.start()

        while True:
            try:
                # 1. Tareas de Monitorización Pasiva
                self.net_mon.scan_connections() 
                self.usb_mon.check_usb_changes()
                
                for d in self.config.directories:
                    if os.path.exists(d): 
                        self.fim.scan_directory(d, mode="monitor")

                self.port_mon.scan_ports()

                # 2. Comunicación C2 (Heartbeat)
                data = self.c2.send_heartbeat("ONLINE")
                
                # 3. Ejecución de Comandos
                if data and "command" in data and data["command"]:
                    self.execute_command(data["command"])

                time.sleep(3)

            except KeyboardInterrupt:
                logger.info("Deteniendo agente ordenadamente...")
                self.ransomware_mon.stop()
                sys.exit(0)
            except Exception as e: 
                logger.error(f"Error en bucle principal: {e}")
                time.sleep(5)

if __name__ == "__main__":
    PySentinelAgent().run()