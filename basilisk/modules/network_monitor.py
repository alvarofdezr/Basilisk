import psutil
import threading
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Set, List, Dict, Any
from basilisk.utils.logger import Logger

class NetworkMonitor:
    """Monitors active network connections and generates telemetry snapshots.

    This module operates in 'Passive Mode' for stealth: it detects suspicious 
    connections and reports them to the C2 server without triggering local 
    pop-ups or interrupting the user workflow.
    """

    def __init__(self, db_manager: Any, c2_client: Any = None, notifier: Any = None, config: Any = None):
        """Initializes the network monitor with whitelisting capabilities."""
        self.db = db_manager
        self.c2 = c2_client
        self.logger = Logger()
        self.lock = threading.Lock()
        
        if config and hasattr(config, 'network_whitelist'):
            self.whitelist = [app.lower() for app in config.network_whitelist]
        else:
            self.whitelist = ["chrome.exe", "firefox.exe", "svchost.exe", "python.exe", "msedge.exe"]
            
        self.known_connections: Set[str] = set()
        self.active_alerts: Set[str] = set()
        self.thread_pool = ThreadPoolExecutor(max_workers=2)

    def get_network_snapshot(self) -> List[Dict[str, Any]]:
        """Generates a static snapshot of all current ESTABLISHED connections.

        Used by the C2 server to build the Network Map visualization.

        Returns:
            List[Dict]: A list of dictionaries containing source, destination, and process info.
        """
        snapshot = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    try:
                        if conn.raddr and conn.raddr.ip in ["127.0.0.1", "::1", "0.0.0.0"]:
                            continue

                        laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "Unknown"
                        
                        pid = conn.pid
                        proc_name = "Unknown"
                        if pid:
                            try:
                                proc_name = psutil.Process(pid).name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass

                        snapshot.append({
                            "src": laddr,
                            "dst": raddr,
                            "process": proc_name,
                            "pid": pid
                        })
                    except Exception:
                        continue
        except Exception as e:
            self.logger.error(f"Snapshot error: {e}")
        
        return snapshot

    def _report_suspicious_activity(self, pid: int, app_name: str, ip: str) -> None:
        """Silently reports a suspicious connection to the C2 server.

        Args:
            pid (int): Process ID.
            app_name (str): Name of the executable.
            ip (str): Remote IP address.
        """
        alert_id = f"{app_name}:{ip}"
        try:
            msg = f"Suspicious traffic: {app_name} (PID: {pid}) -> {ip}"

            if self.c2:
                self.c2.send_alert(msg, "WARNING", "NET_ANOMALY")
            
            self.db.log_event("NET_ANOMALY", msg, "WARNING")

        except Exception:
            pass
        finally:
            with self.lock:
                if alert_id in self.active_alerts: 
                    self.active_alerts.remove(alert_id)

    def scan_connections(self) -> None:
        """Scans for connections from non-whitelisted applications."""
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    if conn.raddr.ip in ["127.0.0.1", "::1"]: continue
                    if not conn.pid: continue
                    
                    try:
                        proc = psutil.Process(conn.pid).name().lower()
                        if proc not in self.whitelist:
                            with self.lock:
                                conn_id = f"{proc}:{conn.raddr.ip}"
                                if conn_id in self.known_connections or conn_id in self.active_alerts: 
                                    continue
                                
                                self.known_connections.add(conn_id)
                                self.active_alerts.add(conn_id)
                                
                                self.thread_pool.submit(self._report_suspicious_activity, conn.pid, proc, conn.raddr.ip)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except Exception:
            pass