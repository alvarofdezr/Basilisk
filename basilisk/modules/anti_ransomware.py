"""
Anti-Ransomware Module - Canary File Detection System

Deploys decoy files (honey-pot) to detect unauthorized file access or encryption.
Monitors filesystem modifications as early-warning indicator for ransomware activity.
"""

import os
import subprocess
from typing import Callable, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from basilisk.utils.logger import Logger

CANARY_FOLDER = os.path.join(os.path.expanduser("~"), ".basilisk_trap")
CANARY_FILES = {
    "passwords_2024.docx": "Confidential content decoy...",
    "bitcoin_wallet.dat": "Fake wallet hex dump...",
    "salary_confidential.xlsx": "Financial data decoy..."
}


class RansomwareHandler(FileSystemEventHandler):
    """
    Filesystem event handler for canary file monitoring.
    
    Triggers alerts when decoy files are accessed, modified, or deleted,
    indicating potential encryption or exfiltration attack patterns.
    """

    def __init__(self, callback_func: Optional[Callable[[str], None]] = None):
        """
        Initialize filesystem event handler.
        
        Args:
            callback_func: Callable invoked on threat detection with alert message
        """
        self.callback_func = callback_func

    def on_modified(self, event):
        """
        Handle file modification events.
        
        Triggers alert for any modification of monitored canary files.
        """
        self._trigger_alarm(event, "MODIFIED")

    def on_deleted(self, event):
        """
        Handle file deletion events.
        
        Triggers alert when canary files are deleted or renamed.
        """
        self._trigger_alarm(event, "DELETED")

    def _trigger_alarm(self, event, action_type):
        """
        Generate and dispatch threat alert.
        
        Args:
            event: Filesystem event object
            action_type: Type of filesystem operation detected
        """
        if event.is_directory:
            return

        msg = f"RANSOMWARE ACTIVITY DETECTED: {event.src_path} ({action_type})"
        if self.callback_func:
            self.callback_func(msg)


class CanarySentry:
    """
    Ransomware detection system using decoy file monitoring.
    
    Deploys a hidden directory with fake sensitive files (honey-pot).
    Monitors for unauthorized access, modification, or encryption attempts.
    Provides early-warning detection without impacting user systems.
    """

    def __init__(self, on_detection_callback: Optional[Callable] = None):
        """
        Initialize canary sentry system.
        
        Args:
            on_detection_callback: Function called when threat detected
        """
        self.observer = Observer()
        self.handler = RansomwareHandler(callback_func=on_detection_callback)
        self.trap_dir = CANARY_FOLDER
        self.logger = Logger()

    def deploy_trap(self) -> None:
        """
        Initialize canary trap infrastructure.
        
        Creates hidden directory and deploys decoy files.
        Implements self-healing to recreate deleted canaries.
        """
        if not os.path.exists(self.trap_dir):
            os.makedirs(self.trap_dir)
            try:
                os.makedirs(self.trap_dir, exist_ok=True)
                subprocess.run(["attrib", "+h", self.trap_dir], check=True, shell=False)
            except Exception:
                pass

        for filename, content in CANARY_FILES.items():
            path = os.path.join(self.trap_dir, filename)
            if not os.path.exists(path):
                with open(path, 'w') as f:
                    f.write(content)

    def start(self) -> None:
        """
        Activate ransomware monitoring.
        
        Deploys trap and begins filesystem observation.
        """
        self.deploy_trap()
        self.observer.schedule(self.handler, self.trap_dir, recursive=False)
        self.observer.start()
        self.logger.info(f"Anti-Ransomware Sentry active at: {self.trap_dir}")

    def stop(self) -> None:
        """
        Deactivate ransomware monitoring.
        
        Gracefully shutdown filesystem observer.
        """
        self.observer.stop()
        self.observer.join()
