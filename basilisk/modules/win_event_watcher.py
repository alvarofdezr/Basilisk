"""
Windows Event Log Monitor - Security Event Brute Force Detection

Monitors Windows Security event log for EventID 4625 (Failed Logon Attempts).
Identifies brute force attacks, credential spraying, and unauthorized access
attempts. Filters for recent events (last 15 seconds per heartbeat cycle)
to provide near-real-time alerting.

Requires:
- Windows platform (will gracefully disable on Linux/macOS)
- pywin32 library for win32evtlog access
"""
import time
from basilisk.utils.logger import Logger

try:
    import win32evtlog
except ImportError:
    win32evtlog = None


class WindowsEventWatcher:
    """Monitor Windows Security event log for logon failures.
    
    Targets EventID 4625 specifically for failed authentication attempts.
    Maintains local handle to event log and reads backwards (newest first)
    using sequential read mode. Gracefully disables if win32evtlog unavailable.
    
    Data Points Extracted:
    - StringInserts[5]: Username attempting login
    - StringInserts[19]: Source IP address of authentication attempt
    """

    def __init__(self, db_manager, notifier=None):
        """Initialize Windows event watcher with event log handles.
        
        Determines read flags based on win32evtlog availability. Sets up
        handlers for local Security log access.
        
        Args:
            db_manager: DatabaseManager for event logging
            notifier: Optional Notifier for alert dispatch
        """
        self.db = db_manager
        self.notifier = notifier
        self.logger = Logger()
        self.server = 'localhost'
        self.log_type = 'Security'

        if win32evtlog:
            self.flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        else:
            self.logger.warning("win32evtlog not installed. Windows Event Monitoring disabled.")

    def check_security_logs(self) -> None:
        """Poll Security event log for recent failed logon attempts.
        
        Reads event log handle in backwards sequential mode (oldest to newest).
        Filters for EventID 4625 and timestamps within last 15 seconds to avoid
        processing stale events between heartbeat cycles.
        
        Calls _trigger_alert for each recent failure, which extracts user/IP.
        """
        if not win32evtlog:
            return

        try:
            hand = win32evtlog.OpenEventLog(self.server, self.log_type)
            events = win32evtlog.ReadEventLog(hand, self.flags, 0)

            for event in events:
                if event.EventID == 4625:
                    event_time = event.TimeGenerated
                    if (time.time() - event_time.timestamp()) < 15:
                        self._trigger_alert(event)

            win32evtlog.CloseEventLog(hand)

        except Exception as e:
            self.logger.error(f"Windows Event Log error: {e}")

    def _trigger_alert(self, event) -> None:
        """Extract user and source IP from failed logon event.
        
        Parses event.StringInserts array to extract relevant fields.
        Uses hardcoded indices which may vary by Windows version/language.
        Defaults to "Unknown" if field missing or array index out of bounds.
        
        Alert formatted as multi-line message:
        "WINDOWS LOGON FAILURE.\nUser: <username>\nSource: <source_ip>"
        
        Args:
            event: Win32EventLog event object with StringInserts array
        """
        data = event.StringInserts
        user = "Unknown"
        ip = "Unknown"

        if data:
            try:
                user = data[5]
                ip = data[19]
            except IndexError:
                pass

        msg = f"WINDOWS LOGON FAILURE.\nUser: {user}\nSource: {ip}"

        self.logger.warning(msg)
        self.db.log_event("WIN_SEC", msg, "CRITICAL")

        if self.notifier:
            self.notifier.send_alert(msg)
