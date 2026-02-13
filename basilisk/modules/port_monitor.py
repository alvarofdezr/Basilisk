# basilisk/modules/port_monitor.py
import psutil
import socket
from typing import List, Dict, Tuple, Optional
from basilisk.core.schemas import PortRiskModel
from basilisk.utils.logger import Logger

KNOWN_RISKS = {
    21: ("FTP", "CRITICAL", "Protocolo inseguro de transferencia de archivos (Texto plano)"),
    22: ("SSH", "WARNING", "Acceso remoto seguro (revisar configuración de claves)"),
    23: ("Telnet", "CRITICAL", "Acceso remoto inseguro (Texto plano, credenciales expuestas)"),
    80: ("HTTP", "INFO", "Servidor Web estándar"),
    443: ("HTTPS", "INFO", "Servidor Web Seguro (TLS)"),
    445: ("SMB", "CRITICAL", "Compartición de archivos (Vector de WannaCry/EternalBlue)"),
    135: ("RPC", "HIGH", "Ejecución remota de procedimientos (Vector de movimiento lateral)"),
    139: ("NetBIOS", "HIGH", "Protocolo heredado vulnerable"),
    3306: ("MySQL/MariaDB", "WARNING", "Base de datos expuesta"),
    3389: ("RDP", "HIGH", "Escritorio Remoto de Windows (Fuerza bruta común)"),
    5900: ("VNC", "HIGH", "Acceso remoto VNC (a menudo sin cifrar)"),
    7070: ("AnyDesk/RealServer", "WARNING", "Software de control remoto (RAT potencial)"),
    8080: ("HTTP-Alt", "INFO", "Servidor Web Alternativo"),
}


class PortMonitor:
    def __init__(self, db_manager, c2_client=None, notifier=None):
        self.db = db_manager
        self.c2 = c2_client
        self.logger = Logger()
        self.previous_ports = set()

    def get_full_report(self) -> List[Dict]:
        """Generates a detailed audit report."""
        report = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' or conn.type == socket.SOCK_DGRAM:
                    port = conn.laddr.port
                    ip = conn.laddr.ip
                    proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"

                    proc_name, pid = "Unknown", 0
                    if conn.pid:
                        try:
                            p = psutil.Process(conn.pid)
                            proc_name, pid = p.name(), conn.pid
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                    risk = "INFO"
                    desc = "Generic Port"
                    explanation: Optional[str] = None

                    if port in KNOWN_RISKS:
                        risk_data: Tuple[str, str, str] = KNOWN_RISKS[port]
                        desc = risk_data[0]
                        risk = risk_data[1]
                        explanation = risk_data[2]

                    if ip in ["0.0.0.0", "::"]:  # nosec
                        desc += " [EXPOSED]"
                        if risk == "WARNING":
                            risk = "HIGH"
                            explanation = (explanation or "") + " + Expuesto a Internet"
                    else:
                        if risk == "HIGH":
                            risk = "WARNING"

                    model = PortRiskModel(
                        port=port,
                        ip_bind=ip,
                        proto=proto,
                        service=desc,
                        process=proc_name,
                        pid=pid,
                        risk=risk,
                        explanation=explanation
                    )
                    report.append(model.dict())

            risk_map = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "INFO": 3}
            report.sort(key=lambda x: risk_map.get(x['risk'], 4))

        except Exception as e:
            self.logger.error(f"Port audit failed: {e}")

        return report
