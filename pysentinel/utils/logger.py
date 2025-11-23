# pysentinel/utils/logger.py
import logging
import sys

class Logger:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
            cls._instance._initialize_logger()
        return cls._instance

    def _initialize_logger(self):
        self.logger = logging.getLogger("PySentinel")
        self.logger.setLevel(logging.DEBUG)
        
        # Evitar duplicar handlers si se reinicia
        if self.logger.hasHandlers():
            self.logger.handlers.clear()

        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')

        # --- FIX 1: SOLUCIÓN PARA CONSOLA (CRITICAL FIX) ---
        # En Windows, forzamos la salida estándar a UTF-8 para soportar emojis sin crashear
        if sys.platform == "win32":
            try:
                sys.stdout.reconfigure(encoding='utf-8')
            except Exception:
                pass # Si falla por versión antigua de Python, lo ignoramos

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # --- FIX 2: SOLUCIÓN PARA ARCHIVO ---
        # Añadimos encoding='utf-8' para poder escribir emojis en el log
        file_handler = logging.FileHandler("pysentinel_audit.log", encoding='utf-8')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def error(self, msg):
        self.logger.error(msg)
        
    def success(self, msg):
        self.logger.info(f"[SUCCESS] {msg}")