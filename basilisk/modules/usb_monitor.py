# basilisk/modules/usb_monitor.py
import os
import string
import platform
from typing import Set
from basilisk.utils.logger import Logger


class USBMonitor:
    """
    Monitor de dispositivos de almacenamiento extraíbles.
    [v7.1.0] Conectado al Dashboard Basilisk (C2).
    """

    def __init__(self, db_manager, c2_client=None, notifier=None):
        self.db = db_manager
        self.c2 = c2_client
        self.notifier = notifier
        self.logger = Logger()

        # Estado inicial
        self.current_drives = self._get_active_drives()
        self.logger.info(f"USB Monitor Initialized. Active drives: {self.current_drives}")

    def _get_active_drives(self) -> Set[str]:
        """Detecta unidades conectadas (Compatible con Windows)."""
        drives = set()
        try:
            if platform.system() == "Windows":
                import win32api
                bitmask = win32api.GetLogicalDrives()
                for letter in string.ascii_uppercase:
                    if bitmask & 1:
                        drives.add(f"{letter}:\\")
                    bitmask >>= 1
            else:
                if os.path.exists('/media'):
                    drives.update([os.path.join('/media', d) for d in os.listdir('/media')])
        except Exception as e:
            self.logger.error(f"Error enumerando drives: {e}")
        return drives

    def check_usb_changes(self) -> None:
        """Compara el estado actual con el anterior para detectar cambios."""
        try:
            new_state = self._get_active_drives()

            added_drives = new_state - self.current_drives
            for drive in added_drives:
                msg = f"🔌 Dispositivo USB CONECTADO: Unidad {drive}"
                self.logger.warning(msg)

                self.db.log_event("USB_EVENT", msg, "WARNING")

                if self.c2:
                    self.c2.send_alert(msg, "WARNING", "USB_EVENT")

                if self.notifier:
                    self.notifier.send_alert(f"💾 {msg}")

            removed_drives = self.current_drives - new_state
            for drive in removed_drives:
                msg = f"❌ Dispositivo USB DESCONECTADO: Unidad {drive}"
                self.logger.info(msg)

                if self.c2:
                    self.c2.send_alert(msg, "INFO", "USB_EVENT")

            if added_drives or removed_drives:
                self.current_drives = new_state

        except Exception as e:
            self.logger.error(f"Error en monitor USB: {e}")
