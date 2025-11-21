# pysentinel/modules/fim.py
import os
import hashlib
from pysentinel.core.database import DatabaseManager
from pysentinel.utils.logger import Logger

class FileIntegrityMonitor:
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.logger = Logger() # Instanciamos nuestro logger profesional

    def calculate_hash(self, file_path: str) -> str:
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.logger.error(f"No se pudo leer {file_path}: {e}")
            return None

    def scan_directory(self, directory_path: str):
        self.logger.info(f"Iniciando escaneo en: {directory_path}")
        
        # Obtenemos todos los archivos que teníamos registrados de antes
        # Nota: Esto es una simplificación. En SQL real haríamos una query más compleja.
        # Para este MVP, asumimos que la BD tiene el estado "anterior".
        
        files_on_disk = set()
        
        # --- FASE 1: Escanear disco y buscar cambios/nuevos ---
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                full_path = os.path.join(root, file)
                # Normalizamos rutas para evitar problemas entre Windows/Linux
                full_path = os.path.normpath(full_path) 
                files_on_disk.add(full_path)
                
                current_hash = self.calculate_hash(full_path)
                if not current_hash: continue # Saltamos si hubo error de lectura

                stored_hash = self.db.get_file_hash(full_path)

                if stored_hash is None:
                    self.logger.success(f"NUEVO ARCHIVO DETECTADO: {full_path}")
                    self.db.update_file(full_path, current_hash)
                
                elif current_hash != stored_hash:
                    self.logger.warning(f"ALERTA DE INTEGRIDAD (MODIFICADO): {full_path}")
                    self.db.update_file(full_path, current_hash)

        # --- FASE 2: Detectar eliminados ---
        # Necesitamos saber qué archivos había en la BD que ya no están en 'files_on_disk'
        # Consultamos TODOS los archivos de la BD (en un entorno real filtraríamos por carpeta)
        self.db.cursor.execute("SELECT path FROM files")
        all_stored_paths = self.db.cursor.fetchall()
        
        for (path,) in all_stored_paths:
            # Solo verificamos archivos que pertenezcan a la carpeta que estamos escaneando
            if path.startswith(os.path.normpath(directory_path)):
                if path not in files_on_disk:
                    self.logger.warning(f"ALERTA CRÍTICA (ELIMINADO): {path}")
                    self.db.delete_file(path)

        self.logger.info("Escaneo finalizado.")