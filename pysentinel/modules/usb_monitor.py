# pysentinel/modules/usb_monitor.py
import psutil
import time
from typing import Set
from pysentinel.utils.logger import Logger

class USBMonitor:
    """
    Monitors external storage devices. Detects connections/disconnections
    and reports capacity details.
    """
    def __init__(self, db_manager, notifier):
        self.db = db_manager
        self.notifier = notifier
        self.logger = Logger()
        
        self.known_devices = self._get_connected_drives()
        self.logger.info(f"USB Monitor Initialized. Active drives: {list(self.known_devices)}")

    def _get_connected_drives(self) -> Set[str]:
        """Retrieves a set of all currently mounted partitions."""
        drives = set()
        try:
            # 'all=True' ensures we catch devices even if not fully mounted standardly
            partitions = psutil.disk_partitions(all=True)
            for p in partitions:
                if p.device:
                    drives.add(p.device)
        except Exception as e:
            self.logger.error(f"Error enumerating drives: {e}")
        return drives

    def check_usb_changes(self) -> None:
        """Checks for state changes in storage devices."""
        current_devices = self._get_connected_drives()
        
        new_devices = current_devices - self.known_devices
        removed_devices = self.known_devices - current_devices

        # Handle New Connections
        for device in new_devices:
            info = ""
            try:
                u = psutil.disk_usage(device)
                gb = round(u.total / (1024**3), 2)
                info = f"({gb} GB)"
            except: 
                pass

            msg = f"USB CONNECTED: Drive {device} {info}"
            self.logger.warning(msg)
            
            if self.notifier:
                self.notifier.send_alert(msg, severity="WARNING", alert_type="USB")

        # Handle Disconnections
        for device in removed_devices:
            msg = f"USB REMOVED: Drive {device}"
            self.logger.info(msg)
            if self.notifier:
                self.notifier.send_alert(msg, severity="INFO", alert_type="USB")

        if new_devices or removed_devices:
            self.known_devices = current_devices