r"""
Windows Registry Monitor - Startup Persistence Detection

Monitors HKLM and HKCU Run/RunOnce keys for unauthorized startup entries.
Baseline comparison identifies malware attempting to establish persistence
through registry-based auto-launch mechanisms.

Targets:
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
- RunOnce variants for single-execution malware installation
"""

import sys
from typing import Dict
from basilisk.core.database import DatabaseManager
from basilisk.utils.logger import Logger

if sys.platform == "win32":
    import winreg as _winreg  # type: ignore[import]
else:
    _winreg = None  # type: ignore[assignment]


class RegistryMonitor:
    """
    Monitor Windows registry for persistence mechanism changes.
    Raises RuntimeError on non-Windows platforms.
    """

    def __init__(self, db_manager: DatabaseManager, notifier):
        if sys.platform != "win32" or _winreg is None:
            raise RuntimeError(
                "RegistryMonitor requires Windows. "
                "It cannot run on Linux/macOS."
            )
        self.db = db_manager
        self.notifier = notifier
        self.logger = Logger()
        self.monitored_keys = [
            (_winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (_winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (_winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (_winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        self.baseline = self._scan_all_keys()
        self.logger.info(
            f"RegistryMonitor: Watching {len(self.baseline)} persistence points."
        )

    def _get_values_from_key(self, hive, subkey) -> Dict[str, str]:
        values = {}
        try:
            with _winreg.OpenKey(hive, subkey, 0, _winreg.KEY_READ) as key_handle:
                i = 0
                while True:
                    try:
                        name, data, _ = _winreg.EnumValue(key_handle, i)
                        values[f"{subkey}\\{name}"] = str(data)
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
        current_snapshot = self._scan_all_keys()
        new_entries = set(current_snapshot.keys()) - set(self.baseline.keys())
        for key in current_snapshot:
            if key in self.baseline and current_snapshot[key] != self.baseline[key]:
                self._trigger_alert(
                    f"PERSISTENCE MODIFIED: {key} -> {current_snapshot[key]}", "WARNING"
                )
        for key in new_entries:
            self._trigger_alert(
                f"NEW STARTUP ENTRY: {key} -> {current_snapshot[key]}", "CRITICAL"
            )
        if new_entries or current_snapshot != self.baseline:
            self.baseline = current_snapshot

    def _trigger_alert(self, msg: str, severity: str) -> None:
        self.logger.warning(msg)
        self.db.log_event("REG_CHANGE", msg, severity)
        if self.notifier:
            self.notifier.send_alert(f"🛡️ Registry Alert: {msg}")
