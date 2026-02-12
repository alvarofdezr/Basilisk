"""
Basilisk Network Monitor v2.0 (Refactored)
Monitors active network connections using strict schemas.
"""
import psutil
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any
from basilisk.utils.logger import Logger
from basilisk.core.schemas import NetworkConnModel

class NetworkMonitor:
    def __init__(self, db_manager: Any, c2_client: Any = None, notifier: Any = None, config: Any = None):
        self.db = db_manager
        self.c2 = c2_client
        self.logger = Logger()
        self.lock = threading.Lock()
        
        self.whitelist = ["chrome.exe", "firefox.exe", "svchost.exe", "python.exe", "msedge.exe"]
        if config and hasattr(config, 'network_whitelist'):
            self.whitelist.extend([app.lower() for app in config.network_whitelist])
            
        self.known_connections: set[str] = set()
        self.active_alerts: set[str] = set()
        self.thread_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="NetMonWorker")

    def get_network_snapshot(self) -> List[Dict[str, Any]]:
        """Generates a static snapshot of ESTABLISHED connections."""
        snapshot = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    try:
                        if conn.raddr and conn.raddr.ip in ["127.0.0.1", "::1", "0.0.0.0"]:
                            continue

                        laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "Unknown"
                        
                        proc_name = "Unknown"
                        if conn.pid:
                            try:
                                proc_name = psutil.Process(conn.pid).name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass

                        model = NetworkConnModel(
                            src=laddr,
                            dst=raddr,
                            process=proc_name,
                            pid=conn.pid or 0
                        )
                        snapshot.append(model.dict())

                    except Exception:
                        continue
        except Exception as e:
            self.logger.error(f"Snapshot error: {e}")
        
        return snapshot

    def scan_connections(self) -> None:
        """Background scan for suspicious anomalies."""
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    if conn.raddr.ip in ["127.0.0.1", "::1"]: continue
                    if not conn.pid: continue
                    
                    try:
                        proc = psutil.Process(conn.pid).name().lower()
                        if proc not in self.whitelist:
                            conn_id = f"{proc}:{conn.raddr.ip}"
                            
                            with self.lock:
                                if conn_id in self.known_connections: continue
                                self.known_connections.add(conn_id)
                                
                            self.thread_pool.submit(self._alert_anomaly, conn.pid, proc, conn.raddr.ip)
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except Exception:
            pass

    def _alert_anomaly(self, pid: int, app: str, ip: str) -> None:
        msg = f"Suspicious traffic: {app} (PID: {pid}) -> {ip}"
        if self.c2: self.c2.send_alert(msg, "WARNING", "NET_ANOMALY")
        if self.db: self.db.log_event("NET_ANOMALY", msg, "WARNING")