# pysentinel/modules/network_monitor.py
import psutil
import ctypes
import threading
from typing import Optional, Set
from pysentinel.utils.logger import Logger

class NetworkMonitor:
    """
    Monitor de conexiones de red con capacidades de bloqueo interactivo.
    
    Refactor v6.4 (Fix Critical #6):
    - Implementada lógica no bloqueante (Threading) para alertas de usuario.
    - Soporte 'Safe Fail' para entornos Headless (Servidores sin UI).
    """
    def __init__(self, db_manager, notifier=None, config=None):
        self.db = db_manager
        self.notifier = notifier
        self.logger = Logger()
        
        # Carga de configuración o defaults seguros
        if config and hasattr(config, 'network_whitelist'):
            self.whitelist = [app.lower() for app in config.network_whitelist]
        else:
            self.whitelist = ["chrome.exe", "firefox.exe", "svchost.exe", "python.exe"]
            
        self.known_connections: Set[str] = set()
        self.session_allowed_apps: Set[str] = set()
        
        # Flag para evitar spam de popups para la misma amenaza
        self.active_alerts: Set[str] = set()

    def _interactive_block_routine(self, pid: int, app_name: str, ip: str) -> None:
        """
        Maneja la alerta de usuario en un hilo separado para no congelar el Agente.
        """
        alert_id = f"{app_name}:{ip}"
        
        try:
            # Windows API Constants
            MB_YESNO = 0x04
            ICON_WARNING = 0x30
            MB_TOPMOST = 0x40000
            
            title = "PySentinel EDR - Alerta de Tráfico"
            message = (f"⚠️ Tráfico sospechoso detectado.\n\n"
                       f"Aplicación: {app_name} (PID: {pid})\n"
                       f"Destino: {ip}\n\n"
                       f"¿Desea BLOQUEAR y TERMINAR este proceso inmediatamente?")
            
            # Llamada bloqueante (pero solo bloquea este hilo, no el agente)
            # Retorna: 6 = Yes (Block), 7 = No (Allow)
            result = ctypes.windll.user32.MessageBoxW(0, message, title, MB_YESNO | ICON_WARNING | MB_TOPMOST)
            
            if result == 6:  # Usuario dijo SÍ
                try:
                    proc = psutil.Process(pid)
                    proc.kill()
                    
                    msg = f"⛔ Amenaza neutralizada por usuario.\nApp: {app_name} -> {ip} terminada."
                    self.logger.warning(msg)
                    self.db.log_event("NET_DEFENSE", msg, "CRITICAL")
                    
                    if self.notifier: 
                        self.notifier.send_alert(msg)
                        
                except psutil.NoSuchProcess:
                    self.logger.info(f"El proceso {app_name} ya no existe.")
                except Exception as e:
                    self.logger.error(f"Fallo al terminar proceso {pid}: {e}")
            else:
                # Usuario dijo NO (Permitir)
                self.session_allowed_apps.add(app_name)
                msg = f"✅ Tráfico autorizado por usuario.\nApp: {app_name} -> {ip}"
                self.logger.info(msg)
                self.db.log_event("NET_ALLOW", msg, "INFO")

        except Exception as e:
            # Captura errores en servidores headless (sin monitor)
            self.logger.error(f"Error mostrando UI (posible entorno headless): {e}")
        finally:
            # Liberar el lock de alerta para esta conexión
            if alert_id in self.active_alerts:
                self.active_alerts.remove(alert_id)

    def scan_connections(self) -> None:
        """Escanea conexiones TCP activas sin bloquear el hilo principal."""
        try:
            # Usamos kind='inet' para IPv4/IPv6
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    try:
                        pid = conn.pid
                        # Optimización: Si no hay PID (ej: System Idle), saltar
                        if not pid: continue

                        process = psutil.Process(pid)
                        proc_name = process.name().lower()
                        remote_ip = conn.raddr.ip if conn.raddr else "Unknown"
                        
                        # 1. Filtros de Ruido (Loopback/Local)
                        if remote_ip in ["127.0.0.1", "::1", "0.0.0.0", "localhost"]: 
                            continue

                        # 2. Comprobación de Políticas
                        is_whitelisted = proc_name in self.whitelist
                        is_session_allowed = proc_name in self.session_allowed_apps
                        
                        if not is_whitelisted and not is_session_allowed:
                            
                            conn_id = f"{proc_name}:{remote_ip}"
                            
                            # Solo alertar si es nuevo Y no hay una alerta activa ya para esto
                            if conn_id not in self.known_connections and conn_id not in self.active_alerts:
                                
                                self.known_connections.add(conn_id)
                                self.active_alerts.add(conn_id)
                                
                                self.logger.warning(f"Interceptada conexión no autorizada: {proc_name} -> {remote_ip}")
                                
                                # FIX CRÍTICO: Lanzar UI en hilo separado
                                t = threading.Thread(
                                    target=self._interactive_block_routine,
                                    args=(pid, proc_name, remote_ip),
                                    daemon=True # Daemon threads mueren si el agente se cierra
                                )
                                t.start()

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

        except Exception as e:
            self.logger.error(f"Network scan error: {e}")