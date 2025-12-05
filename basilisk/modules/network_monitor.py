# basilisk/modules/network_monitor.py
import psutil
import ctypes
import threading
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Set, List, Dict
from basilisk.utils.logger import Logger

class NetworkMonitor:
    """
    Monitor de conexiones de red con bloqueo interactivo y snapshot de telemetría.
    """
    def __init__(self, db_manager, c2_client=None, notifier=None, config=None):
        self.db = db_manager
        self.c2 = c2_client
        self.notifier = notifier
        self.logger = Logger()
        self.lock = threading.Lock()
        
        if config and hasattr(config, 'network_whitelist'):
            self.whitelist = [app.lower() for app in config.network_whitelist]
        else:
            self.whitelist = ["chrome.exe", "firefox.exe", "svchost.exe", "python.exe"]
            
        self.known_connections: Set[str] = set()
        self.session_allowed_apps: Set[str] = set()
        self.active_alerts: Set[str] = set()
        self.thread_pool = ThreadPoolExecutor(max_workers=3)

    def get_network_snapshot(self) -> List[Dict]:
        """
        [NUEVO] Genera una foto fija de todas las conexiones actuales para el Mapa de Red.
        """
        snapshot = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    try:
                        laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "Unknown"
                        
                        # Ignorar loopback para el mapa (demasiado ruido visual)
                        if conn.raddr and conn.raddr.ip in ["127.0.0.1", "::1", "0.0.0.0"]:
                            continue

                        pid = conn.pid
                        proc_name = "Unknown"
                        if pid:
                            try:
                                proc_name = psutil.Process(pid).name()
                            except: pass

                        snapshot.append({
                            "src": laddr,
                            "dst": raddr,
                            "process": proc_name,
                            "pid": pid
                        })
                    except: continue
        except Exception as e:
            self.logger.error(f"Snapshot error: {e}")
        
        return snapshot

    def _interactive_block_routine(self, pid: int, app_name: str, ip: str) -> None:
        alert_id = f"{app_name}:{ip}"
        try:
            MB_YESNO = 0x04
            ICON_WARNING = 0x30
            MB_TOPMOST = 0x40000
            title = "Basilisk EDR - Traffic Alert"
            message = (f"Suspicious traffic detected.\n\nAPP: {app_name}\nDEST: {ip}\n\nBlock and Terminate?")
            
            result = ctypes.windll.user32.MessageBoxW(0, message, title, MB_YESNO | ICON_WARNING | MB_TOPMOST)
            
            if result == 6:  # YES -> BLOCK
                try:
                    psutil.Process(pid).kill()
                    msg = f"Network threat neutralized.\nApp: {app_name} -> {ip} terminated."
                    self.logger.warning(msg)
                    self.db.log_event("NET_DEFENSE", msg, "CRITICAL")
                    if self.c2: self.c2.send_alert(msg, "CRITICAL", "NET_DEFENSE")
                    if self.notifier: self.notifier.send_alert(msg)
                except: pass
            else:
                with self.lock:
                    self.session_allowed_apps.add(app_name)
                if self.c2: self.c2.send_alert(f"Traffic allowed: {app_name}", "INFO", "NET_ALLOW")

        except: pass
        finally:
            with self.lock:
                if alert_id in self.active_alerts: self.active_alerts.remove(alert_id)

    def scan_connections(self) -> None:
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    if conn.raddr.ip in ["127.0.0.1", "::1"]: continue
                    if not conn.pid: continue
                    
                    try:
                        proc = psutil.Process(conn.pid).name().lower()
                        if proc not in self.whitelist:
                            with self.lock:
                                if proc in self.session_allowed_apps: continue
                                conn_id = f"{proc}:{conn.raddr.ip}"
                                if conn_id in self.known_connections or conn_id in self.active_alerts: continue
                                
                                self.known_connections.add(conn_id)
                                self.active_alerts.add(conn_id)
                                self.thread_pool.submit(self._interactive_block_routine, conn.pid, proc, conn.raddr.ip)
                    except: continue
        except: pass