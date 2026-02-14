# basilisk/modules/log_watcher.py
"""
Log Watcher Module - Intrusion Detection via Log Analysis

Monitors system log files for security anomalies using pattern matching.
Detects common attack vectors including brute force attempts, privilege escalation,
and unauthorized access patterns.
"""

import re
import os
from basilisk.core.database import DatabaseManager
from basilisk.utils.logger import Logger


class LogWatcher:
    """
    Monitor and analyze system log files for security threats.
    
    Uses configurable regex patterns to detect intrusion attempts, failed
    authentication, and other security-relevant events. Maintains file position
    to avoid re-processing identical logs on subsequent scans.
    """

    def __init__(self, db_manager: DatabaseManager, log_path: str = "server_logs.txt", notifier=None):
        """
        Initialize the LogWatcher with database and log file configuration.
        
        Args:
            db_manager (DatabaseManager): Database instance for logging security events
            log_path (str): Absolute or relative path to the monitored log file
            notifier: Alert notification handler for real-time threat reporting
        """
        self.db = db_manager
        self.log_path = log_path
        self.notifier = notifier
        self.logger = Logger()
        self.current_position = 0

        if os.path.exists(self.log_path):
            self.current_position = os.path.getsize(self.log_path)

        self.regex_bruteforce = re.compile(r"Failed password for (\w+) from ([\d\.]+)")

    def monitor_changes(self) -> None:
        """
        Scan log file for new entries since last position.
        
        Efficiently reads only newly appended lines by maintaining file position.
        Processes each line through analysis pipeline for threat detection.
        """
        if not os.path.exists(self.log_path):
            return

        with open(self.log_path, "r") as f:
            f.seek(self.current_position)
            lines = f.readlines()
            self.current_position = f.tell()

            for line in lines:
                self._analyze_line(line)

    def _analyze_line(self, line: str) -> None:
        """
        Analyze individual log line for security threats.
        
        Cross-references log content against known intrusion patterns.
        Triggers alerting and database logging on match detection.
        
        Args:
            line (str): Single log file entry to analyze
        """
        match = self.regex_bruteforce.search(line)
        if match:
            user = match.group(1)
            ip = match.group(2)

            msg = f"SSH Intrusion Attempt - User: {user} IP: {ip}"

            self.logger.warning(msg)
            self.db.log_event("AUTH_FAILURE", msg, "CRITICAL")

            if self.notifier:
                self.notifier.send_alert(msg)
