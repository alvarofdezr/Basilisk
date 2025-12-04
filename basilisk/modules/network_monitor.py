# basilisk/modules/network_monitor.py
import psutil
import ctypes
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Set
from basilisk.utils.logger import Logger

class NetworkMonitor:
    """
    Monitor de conexiones de red con capacidades de bloqueo interactivo.
    [v6.6] Conectado al C2 Dashboard.
    [FIX SECURITY] Implementado ThreadPool para evitar DoS por exceso de popups.
    """
    def __init__(self, db_manager, c2_client=None, notifier=None, config=None):
        self.db = db_manager
        self.c2 = c2_client
        self.notifier = notifier
        self.logger = Logger()
        
        if config and hasattr(config, 'network_whitelist'):
            self.whitelist = [app.lower() for app in config.network_whitelist]
        else:
            self.whitelist = ["chrome.exe", "firefox.exe", "svchost.exe", "python.exe"]
            
        self.known_connections: Set[str] = set()
        self.session_allowed_apps: Set[str] = set()
        self.active_alerts: Set[str] = set()

        # [FIX] Pool de hilos limitado a 5 alertas simultáneas máximo
        self.thread_pool = ThreadPoolExecutor(max_workers=5)

    def _interactive_block_routine(self, pid: int, app_name: str, ip: str) -> None:
        alert_id = f"{app_name}:{ip}"
        try:
            MB_YESNO = 0x04
            ICON_WARNING = 0x30
            MB_TOPMOST = 0x40000
            
            title = "Basilisk EDR - Alerta de Tráfico"
            message = (f"⚠️ Tráfico sospechoso detectado.\n\nAPP: {app_name}\nDESTINO: {ip}\n\n¿Bloquear y Terminar Proceso?")
            
            # Esta llamada es bloqueante, por eso debe ir en el ThreadPool
            result = ctypes.windll.user32.MessageBoxW(0, message, title, MB_YESNO | ICON_WARNING | MB_TOPMOST)
            
            if result == 6:  # YES -> BLOCK
                try:
                    proc = psutil.Process(pid)
                    proc.kill()
                    
                    msg = f"⛔ Amenaza de RED neutralizada.\nApp: {app_name} -> {ip} terminada."
                    self.logger.warning(msg)
                    self.db.log_event("NET_DEFENSE", msg, "CRITICAL")
                    
                    if self.c2: self.c2.send_alert(msg, "CRITICAL", "NET_DEFENSE")
                    if self.notifier: self.notifier.send_alert(msg)
                        
                except Exception as e:
                    self.logger.error(f"Fallo al terminar proceso: {e}")
            else:
                self.session_allowed_apps.add(app_name)
                msg = f"✅ Tráfico autorizado por usuario.\nApp: {app_name} -> {ip}"
                self.logger.info(msg)
                
                if self.c2: self.c2.send_alert(msg, "INFO", "NET_ALLOW")

        except Exception as e:
            self.logger.error(f"Error UI: {e}")
        finally:
            if alert_id in self.active_alerts:
                self.active_alerts.remove(alert_id)

    def scan_connections(self) -> None:
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    try:
                        if not conn.pid: continue
                        process = psutil.Process(conn.pid)
                        proc_name = process.name().lower()
                        remote_ip = conn.raddr.ip if conn.raddr else "Unknown"
                        
                        if remote_ip in ["127.0.0.1", "::1", "0.0.0.0", "localhost"]: continue

                        if (proc_name not in self.whitelist) and (proc_name not in self.session_allowed_apps):
                            conn_id = f"{proc_name}:{remote_ip}"
                            
                            if conn_id not in self.known_connections and conn_id not in self.active_alerts:
                                self.known_connections.add(conn_id)
                                self.active_alerts.add(conn_id)
                                
                                # [FIX] Usamos el ThreadPool en lugar de crear un hilo nuevo
                                # Esto previene que 100 conexiones creen 100 hilos y colapsen la RAM
                                self.thread_pool.submit(
                                    self._interactive_block_routine, 
                                    conn.pid, 
                                    proc_name, 
                                    remote_ip
                                )
                    except: continue
        except: pass