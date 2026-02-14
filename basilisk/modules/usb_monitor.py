"""
USB Device Monitor - Removable Media Enumeration and Detection

Monitors logical drive list for insertion/removal of USB storage devices,
external hard drives, and SD cards. Cross-platform (Windows/Linux) support
with appropriate enumeration APIs for each OS.

Security Implications:
- USB devices bypass data loss prevention (DLP) policies
- Insider threats can exfiltrate data via USB
- Attacker can inject malware via infected USB
"""
import os
import string
import platform
from typing import Set
from basilisk.utils.logger import Logger


class USBMonitor:
    """Monitor system for USB device insertion and removal.
    
    Maintains current state of logical drives. On each check cycle,
    compares previous state with current to identify newly connected
    or disconnected removable media.
    
    Supports:
    - Windows: Uses win32api.GetLogicalDrives() bitmask enumeration
    - Linux: Reads /media directory for mounted external storage
    """

    def __init__(self, db_manager, c2_client=None, notifier=None):
        """Initialize USB monitor with current drive state baseline.
        
        Enumerates current logical drives and stores as baseline for
        future delta comparison. Logs detected drives at startup.
        
        Args:
            db_manager: DatabaseManager for event logging
            c2_client: Optional C2Client for server-side alerts
            notifier: Optional Notifier for email/webhook dispatch
        """
        self.db = db_manager
        self.c2 = c2_client
        self.notifier = notifier
        self.logger = Logger()

        self.current_drives = self._get_active_drives()
        self.logger.info(f"USB Monitor Initialized. Active drives: {self.current_drives}")

    def _get_active_drives(self) -> Set[str]:
        """Enumerate logical drives on current system.
        
        Windows: Uses bitmask iteration over 26 drive letters
        Linux: Enumerates /media directory for mounted volumes
        
        Returns:
            Set[str]: Drive letters or mount paths (e.g., {"C:\\", "D:\\", "E:\\"})
        """
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
            self.logger.error(f"Error enumerating drives: {e}")
        return drives

    def check_usb_changes(self) -> None:
        """Compare current drive state with baseline to detect changes.
        
        Identifies newly inserted drives and removed drives by set difference.
        Logs all changes to database and dispatches alerts via C2 and
        optional notifier services.
        
        Alerts trigger on:
        - New drive added (USB inserted): WARNING severity
        - Drive removed (USB ejected): INFO severity
        """
        try:
            new_state = self._get_active_drives()

            added_drives = new_state - self.current_drives
            for drive in added_drives:
                msg = f"USB Device Connected: {drive}"
                self.logger.warning(msg)

                self.db.log_event("USB_EVENT", msg, "WARNING")

                if self.c2:
                    self.c2.send_alert(msg, "WARNING", "USB_EVENT")

                if self.notifier:
                    self.notifier.send_alert(f"💾 {msg}")

            removed_drives = self.current_drives - new_state
            for drive in removed_drives:
                msg = f"USB Device Disconnected: {drive}"
                self.logger.info(msg)

                if self.c2:
                    self.c2.send_alert(msg, "INFO", "USB_EVENT")

            if added_drives or removed_drives:
                self.current_drives = new_state

        except Exception as e:
            self.logger.error(f"Error in USB monitor: {e}")
