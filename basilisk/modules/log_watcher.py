# basilisk/modules/log_watcher.py
import re
import os
from typing import Optional
from basilisk.core.database import DatabaseManager
from basilisk.utils.logger import Logger

class LogWatcher:
    """
    Monitors plain text log files (e.g., SSH auth logs, server logs)
    using regex patterns to detect intrusion attempts.
    """
    def __init__(self, db_manager: DatabaseManager, log_path: str = "server_logs.txt", notifier=None):
        self.db = db_manager 
        self.log_path = log_path
        self.notifier = notifier
        self.logger = Logger()
        self.current_position = 0
        
        if os.path.exists(self.log_path):
            self.current_position = os.path.getsize(self.log_path)

        # Regex for SSH Brute Force (Example pattern)
        self.regex_bruteforce = re.compile(r"Failed password for (\w+) from ([\d\.]+)")

    def monitor_changes(self) -> None:
        """Reads new lines appended to the monitored log file."""
        if not os.path.exists(self.log_path): 
            return

        with open(self.log_path, "r") as f:
            f.seek(self.current_position)
            lines = f.readlines()
            self.current_position = f.tell()

            for line in lines:
                self._analyze_line(line)

    def _analyze_line(self, line: str) -> None:
        match = self.regex_bruteforce.search(line)
        if match:
            user = match.group(1)
            ip = match.group(2)
            
            msg = f"SSH Intrusion Attempt - User: {user} IP: {ip}"
            
            self.logger.warning(msg)
            self.db.log_event("AUTH_FAILURE", msg, "CRITICAL")
            
            if self.notifier: 
                self.notifier.send_alert(msg)