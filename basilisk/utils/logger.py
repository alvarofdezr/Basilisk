import logging
import sys
import os

class Logger:
    """
    Singleton Logger class.
    Configures stream handling (UTF-8) and file rotation.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
            cls._instance._initialize_logger()
        return cls._instance

    def _initialize_logger(self):
        self.logger = logging.getLogger("basilisk")
        self.logger.setLevel(logging.INFO)
        
        if self.logger.hasHandlers():
            self.logger.handlers.clear()

        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

        # Windows Console Encoding Support
        if sys.platform == "win32":
            try:
                sys.stdout.reconfigure(encoding='utf-8')
            except Exception:
                pass

        # Console Handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # File Handler
        try:
            file_handler = logging.FileHandler("basilisk_audit.log", encoding='utf-8')
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        except PermissionError:
            pass 

    def info(self, msg): self.logger.info(msg)
    def warning(self, msg): self.logger.warning(msg)
    def error(self, msg): self.logger.error(msg)
    def success(self, msg): self.logger.info(f"[SUCCESS] {msg}")