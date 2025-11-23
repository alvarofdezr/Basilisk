# pysentinel/modules/usb_monitor.py
import psutil
import time
from pysentinel.core.database import DatabaseManager

class USBMonitor:
    def __init__(self, db_manager: DatabaseManager, notifier):
        self.db = db_manager
        self.notifier = notifier
        
        # Inicialización
        self.known_devices = self._get_connected_drives()
        print(f"[*] USBMonitor INICIADO. Estado inicial: {self.known_devices}")

    def _get_connected_drives(self):
        drives = set()
        try:
            # Usamos all=True para ver absolutamente todo
            partitions = psutil.disk_partitions(all=True)
            for p in partitions:
                if p.device:
                    drives.add(p.device)
        except Exception as e:
            print(f"[ERROR CRÍTICO USB] {e}")
        return drives

    def check_usb_changes(self):
        """Compara el estado actual con el anterior"""
        current_devices = self._get_connected_drives()
        
        # --- DEBUG: ESTO NOS DIRÁ QUÉ PASA ---
        # Imprime lo que ve en cada vuelta del bucle (spam temporal)
        # print(f"[DEBUG USB] Escaneando... Veo: {current_devices}") 
        # -------------------------------------

        new_devices = current_devices - self.known_devices
        removed_devices = self.known_devices - current_devices

        # ALERTA DE CONEXIÓN
        for device in new_devices:
            # Intentamos sacar info extra
            info = ""
            try:
                usage = psutil.disk_usage(device)
                gb = round(usage.total / (1024**3), 2)
                info = f"({gb} GB)"
            except: pass

            msg = f"CONEXIÓN DETECTADA: Unidad {device} {info}"
            
            # La etiqueta clave
            print(f"[USB] ⚠️ {msg}") 
            
            self.db.log_event("USB_CONN", msg, "WARNING")
            if self.notifier:
                self.notifier.send_alert(f"💾 {msg}")

        # ALERTA DE DESCONEXIÓN
        for device in removed_devices:
            msg = f"Dispositivo retirado: Unidad {device}"
            print(f"[USB] ℹ️ {msg}")
            self.db.log_event("USB_DISCONN", msg, "INFO")

        # Actualizar estado
        if new_devices or removed_devices:
            # DEBUG
            print(f"[DEBUG USB] Cambio de estado confirmado. Antes: {self.known_devices} -> Ahora: {current_devices}")
            self.known_devices = current_devices