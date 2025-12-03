# basilisk/modules/anti_ransomware.py
import os
import logging
from typing import Callable, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from basilisk.utils.logger import Logger

# Trap Configuration
CANARY_FOLDER = os.path.join(os.path.expanduser("~"), ".basilisk_trap")
CANARY_FILES = {
    "passwords_2024.docx": "Confidential content decoy...",
    "bitcoin_wallet.dat": "Fake wallet hex dump...",
    "salary_confidential.xlsx": "Financial data decoy..."
}

class RansomwareHandler(FileSystemEventHandler):
    """Handles filesystem events within the Canary directory."""
    def __init__(self, callback_func: Callable[[str], None]):
        self.callback_func = callback_func

    def on_modified(self, event):
        self._trigger_alarm(event, "MODIFIED")

    def on_deleted(self, event):
        self._trigger_alarm(event, "DELETED")

    def _trigger_alarm(self, event, action_type):
        if event.is_directory:
            return
        
        msg = f"RANSOMWARE ACTIVITY DETECTED: {event.src_path} ({action_type})"
        if self.callback_func:
            self.callback_func(msg)

class CanarySentry:
    """
    Deploys a honey-pot (Canary files) and watches for unauthorized modifications.
    Acts as an early warning system for encryption attacks.
    """
    def __init__(self, on_detection_callback: Optional[Callable] = None):
        self.observer = Observer()
        self.handler = RansomwareHandler(callback_func=on_detection_callback)
        self.trap_dir = CANARY_FOLDER
        self.logger = Logger()

    def deploy_trap(self) -> None:
        """Creates hidden directory and decoy files."""
        if not os.path.exists(self.trap_dir):
            os.makedirs(self.trap_dir)
            try:
                # Set hidden attribute on Windows
                os.system(f'attrib +h "{self.trap_dir}"') 
            except Exception:
                pass
        
        # Self-healing: Recreate files if deleted
        for filename, content in CANARY_FILES.items():
            path = os.path.join(self.trap_dir, filename)
            if not os.path.exists(path):
                with open(path, 'w') as f:
                    f.write(content)

    def start(self) -> None:
        """Starts the watchdog observer."""
        self.deploy_trap()
        self.observer.schedule(self.handler, self.trap_dir, recursive=False)
        self.observer.start()
        self.logger.info(f"Anti-Ransomware Sentry active at: {self.trap_dir}")
    
    def stop(self) -> None:
        """Stops the observer."""
        self.observer.stop()
        self.observer.join()