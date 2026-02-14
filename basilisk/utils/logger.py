"""
Basilisk Logging System
Thread-safe singleton logger with UTF-8 support and dual output (console + file).
"""
import logging
import sys


class Logger:
    """Singleton logger with automatic UTF-8 encoding and dual stream handling."""
    
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
            cls._instance._initialize_logger()
        return cls._instance

    def _initialize_logger(self) -> None:
        """Configure logger with console and file handlers."""
        self.logger = logging.getLogger("basilisk")
        self.logger.setLevel(logging.INFO)

        if self.logger.hasHandlers():
            self.logger.handlers.clear()

        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        if sys.platform == "win32":
            try:
                sys.stdout.reconfigure(encoding='utf-8')
            except Exception:
                pass

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        try:
            file_handler = logging.FileHandler(
                "basilisk_audit.log",
                encoding='utf-8'
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        except PermissionError:
            pass

    def info(self, msg: str) -> None:
        self.logger.info(msg)

    def warning(self, msg: str) -> None:
        self.logger.warning(msg)

    def error(self, msg: str) -> None:
        self.logger.error(msg)

    def success(self, msg: str) -> None:
        self.logger.info(f"[SUCCESS] {msg}")