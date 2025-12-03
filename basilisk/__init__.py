# basilisk/utils/logger.py
import logging
import sys
from datetime import datetime

class Logger:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
            cls._instance._initialize_logger()
        return cls._instance

    def _initialize_logger(self):
        self.logger = logging.getLogger("basilisk")
        self.logger.setLevel(logging.DEBUG)

        # Formato profesional: [FECHA] [NIVEL] Mensaje
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

        # 1. Handler para Consola (Lo que ves en pantalla)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # 2. Handler para Archivo (Histórico guardado)
        file_handler = logging.FileHandler("basilisk_audit.log")
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def error(self, msg):
        self.logger.error(msg)
        
    def success(self, msg):
        # Simulamos un nivel de éxito visual
        self.logger.info(f"[SUCCESS] {msg}")