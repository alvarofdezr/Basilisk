# pysentinel/modules/network_monitor.py
import psutil
import ctypes
from typing import Optional, Set
from pysentinel.utils.logger import Logger

class NetworkMonitor:
    """
    Monitors active network connections and enforces whitelisting policies.
    Capable of interactive user blocking via native dialogs.
    """
    def __init__(self, db_manager, notifier=None, config=None):
        self.db = db_manager
        self.notifier = notifier
        self.logger = Logger()
        
        if config:
            self.whitelist = [app.lower() for app in config.network_whitelist]
        else:
            self.whitelist = ["chrome.exe", "firefox.exe", "svchost.exe"]
            
        self.known_connections: Set[str] = set()
        self.session_allowed_apps: Set[str] = set()

    def _ask_user_block(self, app_name: str, ip: str) -> bool:
        """
        Triggers a native Windows MessageBox to request user action.
        Returns: True (Block), False (Allow).
        """
        # Windows API Constants
        MB_YESNO = 0x04
        ICON_WARNING = 0x30
        MB_TOPMOST = 0x40000
        
        title = "PySentinel - Security Alert"
        message = (f"Suspicious connection detected.\n\n"
                   f"Application: {app_name}\n"
                   f"Destination: {ip}\n\n"
                   f"Do you want to BLOCK and TERMINATE this process?")
        
        # Blocking call to user32.dll
        result = ctypes.windll.user32.MessageBoxW(0, message, title, MB_YESNO | ICON_WARNING | MB_TOPMOST)
        
        # 6 = Yes (Block), 7 = No (Allow)
        return result == 6

    def scan_connections(self) -> None:
        """Scans current TCP connections and validates against whitelist."""
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    pid = conn.pid
                    try:
                        process = psutil.Process(pid)
                        proc_name = process.name().lower()
                        
                        remote_ip = conn.raddr.ip if conn.raddr else "Unknown"
                        
                        # Ignore loopback/local traffic
                        if remote_ip in ["127.0.0.1", "::1", "0.0.0.0"]: 
                            continue

                        # Policy Check
                        if (proc_name not in self.whitelist) and (proc_name not in self.session_allowed_apps):
                            
                            conn_id = f"{proc_name}:{remote_ip}"
                            if conn_id not in self.known_connections:
                                self.known_connections.add(conn_id)
                                
                                # Interactive User Decision
                                should_block = self._ask_user_block(proc_name, remote_ip)

                                if should_block:
                                    # Action: Block
                                    try:
                                        process.kill()
                                        
                                        msg = f"Threat neutralized by user decision.\nApp: {proc_name} -> {remote_ip} terminated."
                                        self.logger.warning(msg)
                                        
                                        self.db.log_event("NET_DEFENSE", msg, "CRITICAL")
                                        if self.notifier: 
                                            self.notifier.send_alert(msg)
                                        
                                    except Exception as e:
                                        self.logger.error(f"Failed to terminate process {pid}: {e}")

                                else:
                                    # Action: Allow (Whitelist for session)
                                    self.session_allowed_apps.add(proc_name)
                                    
                                    msg = f"Unusual traffic allowed by user.\nApp: {proc_name} -> {remote_ip}"
                                    self.logger.info(msg)
                                    self.db.log_event("NET_ALLOW", msg, "INFO")

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

        except Exception as e:
            self.logger.error(f"Network scan error: {e}")