# basilisk/modules/port_monitor.py
import psutil
import socket
from typing import Set, Tuple, List, Dict, Optional
from basilisk.core.database import DatabaseManager
from basilisk.utils.logger import Logger

# Configuración de Inteligencia de Puertos
KNOWN_RISKS = {
    21:  ("FTP", "CRITICAL", "Protocolo inseguro de transferencia de archivos"),
    22:  ("SSH", "WARNING", "Acceso remoto seguro (posible puerta trasera)"),
    23:  ("Telnet", "CRITICAL", "Acceso remoto inseguro (texto plano)"),
    80:  ("HTTP", "INFO", "Servidor Web"),
    443: ("HTTPS", "INFO", "Servidor Web Seguro"),
    445: ("SMB", "CRITICAL", "Compartición de archivos (Vector de WannaCry/EternalBlue)"),
    135: ("RPC", "HIGH", "Ejecución remota de procedimientos"),
    139: ("NetBIOS", "HIGH", "Protocolo heredado vulnerable"),
    3306: ("MySQL/MariaDB", "WARNING", "Base de datos expuesta"),
    3389: ("RDP", "HIGH", "Escritorio Remoto de Windows"),
    5900: ("VNC", "HIGH", "Acceso remoto VNC"),
    7070: ("AnyDesk/RealServer", "WARNING", "Software de control remoto (RAT potencial)"),
    8080: ("HTTP-Alt", "INFO", "Servidor Web Alternativo"),
}

class PortMonitor:
    """
    Advanced Port Monitor & Risk Analyzer.
    Detects exposed services, identifies critical ports, and correlates with process owners.
    """
    def __init__(self, db_manager: DatabaseManager, c2_client=None, notifier=None):
        self.db = db_manager
        self.c2 = c2_client  
        self.notifier = notifier
        self.logger = Logger()
        
        # Estado previo: (puerto, proto, ip_bind)
        self.previous_ports: Set[Tuple[int, str, str]] = set()
        self._initialize_baseline()

    def _initialize_baseline(self):
        """Establishes initial network posture."""
        self.previous_ports = self._get_current_ports()
        self.logger.info(f"PortMonitor: Baseline established ({len(self.previous_ports)} listening endpoints).")

    def _get_current_ports(self) -> Set[Tuple[int, str, str]]:
        """Returns unique set of (port, protocol, ip_address)."""
        listening = set()
        try:
            # kind='inet' para IPv4, se puede ampliar a 'inet6'
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' or conn.type == socket.SOCK_DGRAM:
                    port = conn.laddr.port
                    ip = conn.laddr.ip
                    proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    listening.add((port, proto, ip))
        except Exception:
            pass
        return listening

    def _analyze_risk(self, port: int, ip: str) -> Tuple[str, str]:
        """
        Determines risk level based on port reputation and exposure.
        Returns: (Severity, Description)
        """
        severity = "INFO"
        desc = "Puerto genérico"

        # 1. Análisis por Puerto Conocido
        if port in KNOWN_RISKS:
            service, base_severity, risk_desc = KNOWN_RISKS[port]
            severity = base_severity
            desc = f"{service}: {risk_desc}"
        
        # 2. Análisis de Exposición (Exposure)
        is_exposed = ip in ["0.0.0.0", "::"]
        
        if is_exposed:
            desc += " [EXPUESTO A RED]"
            # Elevar riesgo si es un puerto sensible expuesto a todo el mundo
            if severity == "WARNING": severity = "HIGH"
            if severity == "HIGH": severity = "CRITICAL"
        else:
            desc += " [Localhost/Privado]"
            # Reducir riesgo si está limitado a local (ej: DB en 127.0.0.1)
            if severity in ["CRITICAL", "HIGH"] and ip == "127.0.0.1":
                severity = "WARNING"

        return severity, desc

    def get_process_info(self, port: int) -> Tuple[str, int]:
        """Finds the process name and PID owning a port."""
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr.port == port:
                    if conn.pid:
                        return psutil.Process(conn.pid).name(), conn.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return "Unknown", 0

    def get_full_report(self) -> List[Dict]:
        """Generates a detailed audit report for the Dashboard."""
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
                        except: pass

                    severity, desc = self._analyze_risk(port, ip)

                    report.append({
                        "port": port,
                        "ip_bind": ip,
                        "proto": proto,
                        "service": desc,
                        "process": proc_name,
                        "pid": pid,
                        "risk": severity
                    })
            
            # Ordenar por riesgo (CRITICAL primero)
            risk_order = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "INFO": 3}
            report.sort(key=lambda x: risk_order.get(x["risk"], 4))
            
        except Exception as e:
            self.logger.error(f"Audit generation failed: {e}")
            
        return report

    def scan_ports(self) -> None:
        """Real-time detection loop."""
        current_state = self._get_current_ports()
        
        # Detección de APERTURA de puertos
        new_endpoints = current_state - self.previous_ports
        
        for port, proto, ip in new_endpoints:
            # Filtrar ruido de Windows (RPC dinámicos altos suelen ser inofensivos si el 135 está cerrado)
            if 49152 <= port <= 65535 and proto == "TCP" and ip == "127.0.0.1":
                continue 

            proc_name, pid = self.get_process_info(port)
            severity, description = self._analyze_risk(port, ip)
            
            msg = f"NUEVO PUERTO ABIERTO: {port}/{proto}\n" \
                    f"Process: {proc_name} (PID: {pid})\n" \
                    f"Bind: {ip}\n" \
                    f"Detalle: {description}"
            
            self.logger.warning(msg)
            self.db.log_event("NET_PORT_OPEN", msg, severity)
            
            # Solo alertar al C2 si el riesgo es relevante
            if self.c2 and severity in ["CRITICAL", "HIGH", "WARNING"]:
                self.c2.send_alert(msg, severity, "NET_EXPOSURE")

        # Detección de CIERRE de puertos
        closed_endpoints = self.previous_ports - current_state
        for port, proto, ip in closed_endpoints:
            # Loguear solo como INFO, no alertar al dashboard
            self.logger.info(f"Puerto cerrado: {port}/{proto} ({ip})")

        self.previous_ports = current_state