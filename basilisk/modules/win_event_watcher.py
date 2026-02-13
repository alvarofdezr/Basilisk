# basilisk/modules/win_event_watcher.py
import time
from basilisk.utils.logger import Logger

# Optional dependency: Only works on Windows
try:
    import win32evtlog
except ImportError:
    win32evtlog = None


class WindowsEventWatcher:
    """
    Monitors Windows Event Logs (Security Hive) for critical events.
    Target: EventID 4625 (Failed Logon / Brute Force).
    """

    def __init__(self, db_manager, notifier=None):
        self.db = db_manager
        self.notifier = notifier
        self.logger = Logger()
        self.server = 'localhost'
        self.log_type = 'Security'

        # Read flags: Sequential | Backwards (Newest first)
        if win32evtlog:
            self.flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        else:
            self.logger.warning("win32evtlog not installed. Windows Event Monitoring disabled.")

    def check_security_logs(self) -> None:
        """ polls the Security Event Log for recent failures."""
        if not win32evtlog:
            return

        try:
            hand = win32evtlog.OpenEventLog(self.server, self.log_type)
            events = win32evtlog.ReadEventLog(hand, self.flags, 0)

            for event in events:
                # Event 4625: Unknown user name or bad password
                if event.EventID == 4625:
                    event_time = event.TimeGenerated
                    # Filter: Only events from the last 15 seconds
                    if (time.time() - event_time.timestamp()) < 15:
                        self._trigger_alert(event)

            win32evtlog.CloseEventLog(hand)

        except Exception as e:
            self.logger.error(f"Windows Event Log error: {e}")

    def _trigger_alert(self, event) -> None:
        """Parses the event object and extracts User/IP."""
        data = event.StringInserts
        user = "Unknown"
        ip = "Unknown"

        if data:
            try:
                # Typical indices for Event 4625 (may vary by OS version)
                user = data[5]
                ip = data[19]
            except IndexError:
                pass

        msg = f"WINDOWS LOGON FAILURE.\nUser: {user}\nSource: {ip}"

        self.logger.warning(msg)
        self.db.log_event("WIN_SEC", msg, "CRITICAL")

        if self.notifier:
            self.notifier.send_alert(msg)
