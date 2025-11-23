# pysentinel/modules/fim.py
import os
import hashlib
import time
from pysentinel.core.database import DatabaseManager
from pysentinel.utils.logger import Logger 

class FileIntegrityMonitor:
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        # Intentamos usar tu logger, si falla usamos uno simple
        try:
            self.logger = Logger()
        except:
            self.logger = None

    def _log(self, level, msg):
        """Wrapper seguro para loguear o imprimir"""
        if self.logger:
            if level == "info": self.logger.info(msg)
            elif level == "warning": self.logger.warning(msg)
            elif level == "success": self.logger.success(msg)
            elif level == "error": self.logger.error(msg)
        else:
            print(f"[{level.upper()}] {msg}")

    def calculate_hash(self, file_path: str) -> str:
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            # self._log("error", f"No se pudo leer {file_path}: {e}")
            return None

    def scan_directory(self, directory_path: str, mode="monitor", progress_callback=None):
        """
        Args:
            directory_path: Carpeta a escanear.
            mode: 'baseline' (aprender) o 'monitor' (vigilar).
            progress_callback: Función para actualizar la barra de carga en GUI.
        """
        # Normalizamos la ruta
        directory_path = os.path.normpath(directory_path)

        if mode == "baseline":
            self._log("info", f"[*] Creando LINEA BASE (Snapshot) de: {directory_path}...")
        else:
            # Solo logueamos inicio de escaneo si NO estamos en baseline (para no saturar)
            pass 

        for root, dirs, files in os.walk(directory_path):
            for file in files:
                
                # --- NUEVO: ACTUALIZAR BARRA DE CARGA ---
                if progress_callback:
                    try:
                        progress_callback()
                    except:
                        pass # Evitamos romper el escaneo si la GUI falla
                # ----------------------------------------

                full_path = os.path.join(root, file)
                full_path = os.path.normpath(full_path)
                
                # Exclusiones básicas (DBs, logs, temps)
                if file.endswith('.db') or file.endswith('.log-journal') or file.endswith('.tmp'):
                    continue

                current_hash = self.calculate_hash(full_path)
                if not current_hash: continue 
                
                current_mtime = os.path.getmtime(full_path)

                # --- LÓGICA SEGÚN MODO ---
                
                if mode == "baseline":
                    # MODO APRENDIZAJE: Guardamos todo como "verdad absoluta"
                    self.db.update_baseline(full_path, current_hash, current_mtime)
                
                elif mode == "monitor":
                    # MODO VIGILANCIA: Comparamos con la DB
                    stored_data = self.db.get_file_baseline(full_path)
                    
                    if stored_data:
                        stored_hash, stored_mtime = stored_data
                        
                        # Si el hash cambia, es una modificación crítica
                        if current_hash != stored_hash:
                            msg = f"MODIFICADO: {full_path}"
                            self._log("warning", msg)
                            self.db.log_event("FILE_MOD", msg, "CRITICAL")
                            
                    else:
                        # Si no existe en la DB, es un archivo nuevo
                        msg = f"NUEVO ARCHIVO: {full_path}"
                        self._log("success", msg)
                        self.db.log_event("FILE_NEW", msg, "WARNING")
                        
                        # Opcional: Si quieres que deje de avisar tras la primera vez, descomenta:
                        # self.db.update_baseline(full_path, current_hash, current_mtime)

        if mode == "baseline":
            self._log("info", f"Escaneo de {directory_path} finalizado.")