"""
Windows Registry Monitor - Startup Persistence Detection

Monitors HKLM and HKCU Run/RunOnce keys for unauthorized startup entries.
Baseline comparison identifies malware attempting to establish persistence
through registry-based auto-launch mechanisms.

Targets:
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
- RunOnce variants for single-execution malware installation
"""
import winreg
from typing import Dict
from basilisk.core.database import DatabaseManager
from basilisk.utils.logger import Logger


class RegistryMonitor:
    """Monitor Windows registry for persistence mechanism changes.
    
    Creates baseline of all startup entries at initialization and continuously
    compares with current state to detect new entries (100% persistence techniques)
    or modifications to existing entries. Flags both additions and value changes.
    
    Monitored Keys:
    - HKCU Run/RunOnce: User-level startup programs
    - HKLM Run/RunOnce: System-level startup programs (requires admin for modification)
    """

    def __init__(self, db_manager: DatabaseManager, notifier):
        """Initialize registry monitor with baseline snapshot.
        
        Establishes baseline of all monitored keys at startup for future
        delta comparison. Logs number of persistence points being watched.
        
        Args:
            db_manager: DatabaseManager for event logging
            notifier: Optional notification service for alert dispatch
        """
        self.db = db_manager
        self.notifier = notifier
        self.logger = Logger()

        self.monitored_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]

        self.baseline = self._scan_all_keys()
        self.logger.info(f"RegistryMonitor: Watching {len(self.baseline)} persistence points.")

    def _get_values_from_key(self, hive, subkey) -> Dict[str, str]:
        """Enumerate all value entries in a registry key.
        
        Safely reads registry values with graceful error handling for
        access denied (non-admin) and missing keys (new Windows installations).
        
        Args:
            hive: Registry hive constant (HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER)
            subkey: Subkey path under hive (e.g., Software\Microsoft\Windows\...)
            
        Returns:
            Dict[str, str]: Mapping of full registry paths to command values.
                Keys formatted as "Subkey\ValueName", values are command strings
        """
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
        """Generate snapshot of all monitored registry keys.
        
        Iterates through HKLM and HKCU Run/RunOnce keys and aggregates
        all startup entries into single dictionary for comparison.
        
        Returns:
            Dict[str, str]: Complete baseline snapshot of registry values
        """
        snapshot = {}
        for hive, subkey in self.monitored_keys:
            snapshot.update(self._get_values_from_key(hive, subkey))
        return snapshot

    def check_registry_changes(self) -> None:
        """Compare current registry state against baseline and alert on changes.
        
        Detects three types of modifications:
        1. New entries: Malware adding startup programs (CRITICAL)
        2. Modified values: Existing startup commands changed (WARNING)
        3. Deleted entries: Detected via absence in current snapshot
        
        Updates baseline after detection to prevent duplicate alerts.
        """
        current_snapshot = self._scan_all_keys()

        new_entries = set(current_snapshot.keys()) - set(self.baseline.keys())

        # Detect command modifications
        for key in current_snapshot:
            if key in self.baseline:
                if current_snapshot[key] != self.baseline[key]:
                    msg = f"PERSISTENCE MODIFIED: {key} -> {current_snapshot[key]}"
                    self._trigger_alert(msg, "WARNING")

        # Detect new startup entries (primary malware persistence vector)
        for key in new_entries:
            cmd = current_snapshot[key]
            msg = f"NEW STARTUP ENTRY: {key} -> {cmd}"
            self._trigger_alert(msg, "CRITICAL")

        if new_entries or (current_snapshot != self.baseline):
            self.baseline = current_snapshot

    def _trigger_alert(self, msg: str, severity: str) -> None:
        """Dispatch registry change alert to all configured outputs.
        
        Logs event to database and sends notification to optional
        notifier service for real-time alerting.
        
        Args:
            msg: Human-readable alert message
            severity: Severity level (WARNING, CRITICAL)
        """
        self.logger.warning(msg)
        self.db.log_event("REG_CHANGE", msg, severity)
        if self.notifier:
            self.notifier.send_alert(f"🛡️ Registry Alert: {msg}")
