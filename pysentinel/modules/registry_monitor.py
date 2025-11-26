# pysentinel/modules/registry_monitor.py
import winreg
from typing import Dict, Tuple, List
from pysentinel.core.database import DatabaseManager
from pysentinel.utils.logger import Logger

class RegistryMonitor:
    """
    Monitors Windows Registry for Persistence Mechanisms.
    Scans Run keys (HKLM/HKCU) for unauthorized startup entries.
    """
    def __init__(self, db_manager: DatabaseManager, notifier):
        self.db = db_manager
        self.notifier = notifier
        self.logger = Logger()
        
        # Monitored Hives
        self.monitored_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        
        self.baseline = self._scan_all_keys()
        self.logger.info(f"RegistryMonitor: Watching {len(self.baseline)} persistence points.")

    def _get_values_from_key(self, hive, subkey) -> Dict[str, str]:
        values = {}
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key_handle:
                i = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key_handle, i)
                        full_id = f"{subkey}\\{name}"
                        values[full_id] = str(data)
                        i += 1
                    except OSError:
                        break
        except (PermissionError, FileNotFoundError):
            pass
        return values

    def _scan_all_keys(self) -> Dict[str, str]:
        snapshot = {}
        for hive, subkey in self.monitored_keys:
            snapshot.update(self._get_values_from_key(hive, subkey))
        return snapshot

    def check_registry_changes(self) -> None:
        """Compares current registry state against baseline."""
        current_snapshot = self._scan_all_keys()
        
        new_entries = set(current_snapshot.keys()) - set(self.baseline.keys())
        
        # Detect Modifications
        for key in current_snapshot:
            if key in self.baseline:
                if current_snapshot[key] != self.baseline[key]:
                    msg = f"PERSISTENCE MODIFIED: {key} -> {current_snapshot[key]}"
                    self._trigger_alert(msg, "WARNING")

        # Detect New Entries
        for key in new_entries:
            cmd = current_snapshot[key]
            msg = f"NEW STARTUP ENTRY: {key} -> {cmd}"
            self._trigger_alert(msg, "CRITICAL")

        if new_entries or (current_snapshot != self.baseline):
            self.baseline = current_snapshot

    def _trigger_alert(self, msg: str, severity: str):
        self.logger.warning(msg)
        self.db.log_event("REG_CHANGE", msg, severity)
        if self.notifier:
            self.notifier.send_alert(f"🛡️ Registry Alert: {msg}")