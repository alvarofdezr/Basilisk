import psutil
import time
from pysentinel.utils.logger import Logger

class USBMonitor:
    def __init__(self, db_manager, notifier=None):
        self.db = db_manager
        self.notifier = notifier
        self.logger = Logger()
        # Guardamos los discos que hay conectados AL INICIO (C:, D:...)
        self.existing_drives = self._get_current_drives()

    def _get_current_drives(self):
        """Devuelve una lista de las letras de disco conectadas (Ej: ['C:\\', 'D:\\'])"""
        drives = []
        try:
            partitions = psutil.disk_partitions(all=True)
            for p in partitions:
                if p.device and p.opts != 'cdrom': # Ignoramos CD-ROMs
                    drives.append(p.device)
        except:
            pass
        return drives

    def check_usb_changes(self):
        """Compara los discos actuales con los que había antes"""
        current_drives = self._get_current_drives()
        
        # Detectar NUEVOS discos (Set Difference)
        # Lo que hay en 'current' que no estaba en 'existing'
        new_drives = list(set(current_drives) - set(self.existing_drives))
        
        # Detectar discos RETIRADOS
        removed_drives = list(set(self.existing_drives) - set(current_drives))

        # Procesar Nuevos USBs
        for drive in new_drives:
            msg = f"🔌 ALERTA FÍSICA: Nuevo dispositivo USB detectado.\nUnidad: {drive}"
            print(f"[USB] {msg}")
            
            self.db.log_event("USB", msg, "WARNING")
            if self.notifier:
                self.notifier.send_alert(msg)

        # Actualizar la lista de referencia para la siguiente vuelta
        if new_drives or removed_drives:
            self.existing_drives = current_drives