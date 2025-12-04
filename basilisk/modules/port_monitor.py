# basilisk/modules/port_monitor.py
import psutil
import socket
from typing import Set, Tuple, List, Dict
from basilisk.core.database import DatabaseManager
from basilisk.utils.logger import Logger

class PortMonitor:
    """
    Monitors open network ports (TCP/UDP). 
    Maintains a baseline to detect newly opened ports in real-time.
    """
    def __init__(self, db_manager, c2_client=None, notifier=None):
        self.db = db_manager
        self.c2 = c2_client  
        self.notifier = notifier
        self.logger = Logger()
        self.previous_ports: Set[Tuple[int, str]] = set()
        
        self._initialize_baseline()

    def _initialize_baseline(self):
        """Captures initial state silently."""
        self.previous_ports = self._get_current_ports()
        self.logger.info(f"PortMonitor: Baseline established ({len(self.previous_ports)} ports).")

    def _get_current_ports(self) -> Set[Tuple[int, str]]:
        """Returns a set of (port, protocol) tuples."""
        open_ports = set()
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' or conn.type == socket.SOCK_DGRAM:
                    port = conn.laddr.port
                    proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    open_ports.add((port, proto))
        except Exception:
            pass
        return open_ports

    def get_service_name(self, port: int, proto: str) -> str:
        """Resolves port number to service name (e.g., 80 -> http)."""
        try:
            return socket.getservbyport(port, proto.lower())
        except:
            return "Unknown"

    def get_full_report(self) -> List[Dict]:
        """Generates a detailed audit report of all listening ports."""
        report = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' or conn.type == socket.SOCK_DGRAM:
                    port = conn.laddr.port
                    proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    pid = conn.pid
                    
                    process_name = "System/Restricted"
                    try:
                        if pid:
                            proc = psutil.Process(pid)
                            process_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied): 
                        pass

                    service_name = self.get_service_name(port, proto)

                    report.append({
                        "port": port,
                        "proto": proto,
                        "service": service_name,
                        "process": process_name,
                        "pid": pid if pid else "?"
                    })
            
            report.sort(key=lambda x: x['port'])
            
        except Exception as e:
            self.logger.error(f"Port audit failed: {e}")
            
        return report

    def scan_ports(self) -> None:
        """Real-time detection of changes in listening ports."""
        current_ports = self._get_current_ports()
        
        # Detect New Ports
        new_ports = current_ports - self.previous_ports
        for port, proto in new_ports:
            proc_name = "Unknown"
            try:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.laddr.port == port:
                        if conn.pid: 
                            proc_name = psutil.Process(conn.pid).name()
                        break
            except: pass
            
            msg = f"NEW PORT OPENED: {port} ({proto}) - Process: {proc_name}"
            self.logger.warning(msg)
            
            self.db.log_event("PORT_OPEN", msg, "WARNING")
            if self.notifier:
                self.notifier.send_alert(f"⚠️ {msg}")

        # Detect Closed Ports
        closed_ports = self.previous_ports - current_ports
        for port, proto in closed_ports:
            msg = f"Port closed: {port} ({proto})"
            self.logger.info(msg)
            self.db.log_event("PORT_CLOSE", msg, "INFO")

        self.previous_ports = current_ports