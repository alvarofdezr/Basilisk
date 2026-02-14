"""
Network Connection Monitor - Unauthorized Communication Detection

Monitors active ESTABLISHED TCP/UDP connections across the system,
identifying applications communicating to non-whitelisted external addresses.
Provides real-time anomaly detection for command & control callbacks,
data exfiltration attempts, and lateral movement patterns.
"""
import psutil
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any
from basilisk.utils.logger import Logger
from basilisk.core.schemas import NetworkConnModel


class NetworkMonitor:
    """Monitor for active network connections and process-IP associations.
    
    Maintains baseline of known legitimate connections (browsers, system services)
    and flags suspicious outbound traffic to external addresses. Uses threading
    for scalable monitoring without blocking agent heartbeat cycles.
    
    Capabilities:
    - IPv4/IPv6 ESTABLISHED connection enumeration
    - Process-to-IP mapping for traffic attribution
    - Whitelisting for trusted applications (Chrome, Firefox, etc.)
    - Asynchronous alerting via thread pool
    """
    
    def __init__(self, db_manager: Any, c2_client: Any = None, notifier: Any = None, config: Any = None):
        """Initialize network monitor with database and optional C2 integration.
        
        Sets up connection tracking state, configures application whitelist,
        and spawns thread pool for async anomaly handling.
        
        Args:
            db_manager: DatabaseManager instance for event logging
            c2_client: Optional C2Client for sending alerts back to server
            notifier: Optional Notifier for email/webhook dispatch
            config: Optional Config object with network_whitelist extensions
        """
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
        """Generate enumeration of all ESTABLISHED network connections.
        
        Filters localhost/loopback traffic and provides complete process-IP 
        mapping for dashboard visualization. Validates process existence 
        and gracefully skips access-denied scenarios.
        
        Returns:
            List[Dict]: Array of NetworkConnModel dicts with:
                - src: Local address:port (e.g., "192.168.1.55:55823")
                - dst: Remote address:port (e.g., "8.8.8.8:443")
                - process: Executable name (e.g., "chrome.exe")
                - pid: Process ID for process inspection
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
        """Background anomaly scan for suspicious outbound connections.
        
        Iterates all ESTABLISHED connections and identifies processes
        not in the whitelist communicating to external addresses. Maintains
        known_connections set to avoid duplicate alerts per C2 heartbeat.
        
        Uses thread pool for async alert dispatching without blocking
        the main monitoring loop.
        """
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    if conn.raddr.ip in ["127.0.0.1", "::1"]:
                        continue
                    if not conn.pid:
                        continue

                    try:
                        proc = psutil.Process(conn.pid).name().lower()
                        if proc not in self.whitelist:
                            conn_id = f"{proc}:{conn.raddr.ip}"

                            with self.lock:
                                if conn_id in self.known_connections:
                                    continue
                                self.known_connections.add(conn_id)

                            self.thread_pool.submit(self._alert_anomaly, conn.pid, proc, conn.raddr.ip)

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except Exception:
            pass

    def _alert_anomaly(self, pid: int, app: str, ip: str) -> None:
        """Dispatch anomaly alert for suspicious outbound connection.
        
        Called asynchronously by thread pool. Logs event to database,
        sends C2 alert if server available, and optionally notifies ops.
        
        Args:
            pid: Process ID of communicating application
            app: Executable name of source process
            ip: Destination IP address for connection
        """
        msg = f"Suspicious traffic: {app} (PID: {pid}) -> {ip}"
        if self.c2:
            self.c2.send_alert(msg, "WARNING", "NET_ANOMALY")
        if self.db:
            self.db.log_event("NET_ANOMALY", msg, "WARNING")
