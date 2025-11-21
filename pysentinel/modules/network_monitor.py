import psutil
import time
import ctypes # <--- Necesario para ventanas nativas de Windows
from pysentinel.utils.logger import Logger

class NetworkMonitor:
    def __init__(self, db_manager, notifier=None, config=None):
        self.db = db_manager
        self.notifier = notifier
        self.logger = Logger()
        
        if config:
            # Copiamos la lista para poder modificarla en memoria sin tocar el YAML
            self.whitelist = [app.lower() for app in config.network_whitelist]
        else:
            self.whitelist = ["chrome.exe", "firefox.exe"]
            
        self.known_connections = set()
        # Cache para no preguntar 2 veces por la misma app en la misma sesión
        self.session_allowed_apps = set()

    def _ask_user_block(self, app_name, ip):
        """
        Muestra un Pop-up nativo de Windows (MessageBox).
        Devuelve: True (Si el usuario pulsa SÍ/Block), False (Si pulsa NO/Allow)
        """
        # Configuración de la ventana (API de Windows)
        MB_YESNO = 0x04
        ICON_WARNING = 0x30
        MB_TOPMOST = 0x40000 # Para que salga encima de todo
        
        title = "PySentinel - ALERTA DE SEGURIDAD"
        message = (f"Se ha detectado una conexión sospechosa.\n\n"
                   f"Aplicación: {app_name}\n"
                   f"Destino: {ip}\n\n"
                   f"¿Quieres BLOQUEAR y CERRAR este programa ahora mismo?")
        
        # Llamada al sistema (bloquea el hilo hasta que respondes)
        result = ctypes.windll.user32.MessageBoxW(0, message, title, MB_YESNO | ICON_WARNING | MB_TOPMOST)
        
        # 6 = Botón SÍ (Yes), 7 = Botón NO (No)
        return result == 6

    def scan_connections(self):
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    pid = conn.pid
                    try:
                        process = psutil.Process(pid)
                        proc_name = process.name().lower()
                        
                        remote_ip = conn.raddr.ip if conn.raddr else "Unknown"
                        remote_port = conn.raddr.port if conn.raddr else 0

                        # Filtros básicos
                        if remote_ip in ["127.0.0.1", "::1", "0.0.0.0"]: continue

                        # VERIFICACIÓN
                        # 1. Si no está en whitelist del YAML
                        # 2. Y no la hemos permitido ya en esta sesión (para no spamear ventanas)
                        if (proc_name not in self.whitelist) and (proc_name not in self.session_allowed_apps):
                            
                            conn_id = f"{proc_name}:{remote_ip}"
                            if conn_id not in self.known_connections:
                                self.known_connections.add(conn_id)
                                
                                # --- MOMENTO DE LA VERDAD: PREGUNTAR AL USUARIO ---
                                # Esto detiene el escaneo momentáneamente hasta que decides
                                should_block = self._ask_user_block(proc_name, remote_ip)

                                if should_block:
                                    # === OPCIÓN A: EL USUARIO DIJO "BLOQUEAR" ===
                                    try:
                                        process.kill() # ¡BANG!
                                        
                                        msg = f"⛔ AMENAZA NEUTRALIZADA POR USUARIO.\nApp: {proc_name} conectando a {remote_ip} ha sido eliminada."
                                        print(f"[NET] {msg}")
                                        
                                        self.db.log_event("NET_DEFENSE", msg, "CRITICAL")
                                        if self.notifier: self.notifier.send_alert(msg)
                                        
                                    except Exception as e:
                                        print(f"[ERROR] No se pudo matar el proceso: {e}")

                                else:
                                    # === OPCIÓN B: EL USUARIO DIJO "PERMITIR" ===
                                    # Añadimos a la lista temporal para que no vuelva a preguntar
                                    self.session_allowed_apps.add(proc_name)
                                    
                                    msg = f"⚠️ Tráfico inusual PERMITIDO por usuario.\nApp: {proc_name} -> {remote_ip}"
                                    print(f"[NET] {msg}")
                                    self.db.log_event("NET_ALLOW", msg, "INFO")

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

        except Exception as e:
            print(f"[ERROR NET] {e}")