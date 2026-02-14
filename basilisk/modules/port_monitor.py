"""
Port Monitor Module - Network Service Enumeration and Risk Assessment

Identifies listening network services and evaluates exposure risk.
Detects dangerous protocol implementations, improperly configured bindings,
and suspicious port associations commonly leveraged in lateral movement.
"""

import psutil
import socket
from typing import List, Dict, Tuple, Optional
from basilisk.core.schemas import PortRiskModel
from basilisk.utils.logger import Logger

KNOWN_RISKS = {
    21: ("FTP", "CRITICAL", "Unencrypted file transfer protocol"),
    22: ("SSH", "WARNING", "Secure shell - verify key-based authentication"),
    23: ("Telnet", "CRITICAL", "Legacy unencrypted remote access"),
    80: ("HTTP", "INFO", "Standard web server"),
    443: ("HTTPS", "INFO", "TLS-encrypted web server"),
    445: ("SMB", "CRITICAL", "Windows file sharing - WannaCry/EternalBlue vector"),
    135: ("RPC", "HIGH", "Remote procedure call - lateral movement vector"),
    139: ("NetBIOS", "HIGH", "Legacy protocol with known vulnerabilities"),
    3306: ("MySQL/MariaDB", "WARNING", "Database service - expose to network risk"),
    3389: ("RDP", "HIGH", "Windows Remote Desktop - brute force target"),
    5900: ("VNC", "HIGH", "Remote desktop access - often unencrypted"),
    7070: ("AnyDesk/RealServer", "WARNING", "Remote access tool - RAT indicator"),
    8080: ("HTTP-Alt", "INFO", "Alternative web server port"),
}


class PortMonitor:
    """
    Network port enumeration and security assessment.
    
    Monitors listening TCP/UDP ports, identifies associated processes,
    and evaluates risk based on protocol vulnerability and network exposure.
    Flags dangerous service configurations and exposed administrative endpoints.
    """

    def __init__(self, db_manager, c2_client=None, notifier=None):
        """
        Initialize port monitor.
        
        Args:
            db_manager: Database instance for event logging
            c2_client: Command and control client for alert delivery
            notifier: Alert notification handler
        """
        self.db = db_manager
        self.c2 = c2_client
        self.logger = Logger()
        self.previous_ports = set()

    def get_full_report(self) -> List[Dict]:
        """
        Generate comprehensive port audit report.
        
        Enumerates all listening ports, identifies owning processes,
        evaluates security risk, and assesses network exposure.
        Returns results sorted by threat severity (CRITICAL → INFO).
        
        Returns:
            List[Dict]: Port inventory with risk assessment and process metadata
        """
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

                    if ip in ["0.0.0.0", "::"]:
                        desc += " [EXPOSED]"
                        if risk == "WARNING":
                            risk = "HIGH"
                            explanation = (explanation or "") + " - Exposed to network"
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
