# pysentinel/modules/win_event_watcher.py
import win32evtlog # Librería para hablar con Windows
import time
from pysentinel.utils.logger import Logger

class WindowsEventWatcher:
    def __init__(self, db_manager, notifier=None):
        self.db = db_manager
        self.notifier = notifier
        self.logger = Logger()
        self.server = 'localhost' # Tu propia máquina
        self.log_type = 'Security' # Queremos ver logs de SEGURIDAD
        
        # Banderas para leer logs (Leer hacia atrás, secuencial)
        self.flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    def check_security_logs(self):
        """Lee los últimos eventos de seguridad de Windows"""
        try:
            hand = win32evtlog.OpenEventLog(self.server, self.log_type)
            events = win32evtlog.ReadEventLog(hand, self.flags, 0)

            for event in events:
                # EVENTO 4625: Fallo de inicio de sesión (Fuerza bruta / Error password)
                if event.EventID == 4625:
                    # Los datos del evento vienen en una lista 'StringInserts'
                    # En el evento 4625, la posición varía según versión de Windows, 
                    # pero suele contener Usuario, Dominio, etc.
                    
                    # Analizamos la fecha para no alertar de cosas de hace un año
                    event_time = event.TimeGenerated
                    # Si el evento tiene menos de 10 segundos de antigüedad
                    if (time.time() - event_time.timestamp()) < 15:
                        self._trigger_alert(event)
            
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            print(f"[ERROR WINDOWS LOGS] {e}")

    def _trigger_alert(self, event):
        # Extraemos datos útiles (esto depende de la estructura del evento)
        # Normalmente: Index 5 es usuario, Index 19 es IP (puede variar)
        data = event.StringInserts
        if data:
            try:
                user = data[5] # Usuario intentado
                ip = data[19]  # IP de origen (si es local saldrá vacía o -)
            except:
                user = "Desconocido"
                ip = "Desconocido"

            msg = f"🛑 REAL: Intento de acceso fallido en Windows.\nUsuario: {user}\nIP/Workstation: {ip}"
            
            # Evitamos duplicados masivos (simple check de spam)
            print(f"[ALERTA REAL] {msg}")
            
            # Guardar en BD y Notificar
            self.db.log_event("WIN_SEC", msg, "CRITICAL")
            if self.notifier:
                self.notifier.send_alert(msg)