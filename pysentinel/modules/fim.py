# pysentinel/modules/fim.py
import os
import hashlib
import time
from pysentinel.core.database import DatabaseManager
from pysentinel.utils.logger import Logger 

# CONSTANTES DE OPTIMIZACIÓN
# Si el archivo pesa más de 50 MB, usamos escaneo inteligente
LARGE_FILE_THRESHOLD = 50 * 1024 * 1024  # 50 MB
# Tamaño del bloque a leer al principio y al final (1 MB)
SMART_CHUNK_SIZE = 1 * 1024 * 1024 

class FileIntegrityMonitor:
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
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
        """
        Calcula el hash SHA-256. 
        Si el archivo es gigante, usa Smart Hashing (Cabecera + Pie).
        """
        sha256_hash = hashlib.sha256()
        try:
            file_size = os.path.getsize(file_path)
            
            with open(file_path, "rb") as f:
                # CASO 1: Archivo Pequeño/Mediano (Lectura Completa)
                if file_size < LARGE_FILE_THRESHOLD:
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                
                # CASO 2: Archivo Gigante (Optimización Smart Hashing)
                else:
                    # 1. Leemos el primer 1MB (Header)
                    sha256_hash.update(f.read(SMART_CHUNK_SIZE))
                    
                    # 2. Saltamos al final menos 1MB
                    # seek(offset, whence): 2 significa "desde el final"
                    if file_size > SMART_CHUNK_SIZE: # Solo si cabe el salto
                        seek_pos = max(file_size - SMART_CHUNK_SIZE, 0)
                        f.seek(seek_pos)
                        # 3. Leemos el último 1MB (Footer)
                        sha256_hash.update(f.read(SMART_CHUNK_SIZE))
                    
                    # 4. Añadimos el tamaño exacto al hash para evitar colisiones
                    # (Diferenciar un archivo de 1GB de uno de 2GB con mismos headers)
                    sha256_hash.update(str(file_size).encode())

            return sha256_hash.hexdigest()
            
        except (PermissionError, OSError):
            return None
        except Exception as e:
            # self._log("error", f"Error hash: {e}")
            return None

    def scan_directory(self, directory_path: str, mode="monitor", progress_callback=None):
        """
        Args:
            directory_path: Carpeta a escanear.
            mode: 'baseline' (aprender) o 'monitor' (vigilar).
            progress_callback: Función para actualizar la barra de carga en GUI.
        """
        directory_path = os.path.normpath(directory_path)

        if mode == "baseline":
            self._log("info", f"[*] Creando LINEA BASE (Snapshot) de: {directory_path}...")

        for root, dirs, files in os.walk(directory_path):
            for file in files:
                
                # Actualizar Barra de Carga
                if progress_callback:
                    try:
                        progress_callback()
                    except: pass

                full_path = os.path.join(root, file)
                full_path = os.path.normpath(full_path)
                
                # Exclusiones básicas
                if file.endswith('.db') or file.endswith('.log-journal') or file.endswith('.tmp'):
                    continue

                current_hash = self.calculate_hash(full_path)
                if not current_hash: continue 
                
                current_mtime = os.path.getmtime(full_path)

                # --- LÓGICA SEGÚN MODO ---
                
                if mode == "baseline":
                    self.db.update_baseline(full_path, current_hash, current_mtime)
                
                elif mode == "monitor":
                    stored_data = self.db.get_file_baseline(full_path)
                    
                    if stored_data:
                        stored_hash, stored_mtime = stored_data
                        
                        if current_hash != stored_hash:
                            msg = f"MODIFICADO: {full_path}"
                            self._log("warning", msg)
                            self.db.log_event("FILE_MOD", msg, "CRITICAL")
                            
                    else:
                        msg = f"NUEVO ARCHIVO: {full_path}"
                        self._log("success", msg)
                        self.db.log_event("FILE_NEW", msg, "WARNING")
                        
                        # Auto-aprender archivos nuevos para no spamear (opcional)
                        # self.db.update_baseline(full_path, current_hash, current_mtime)

        if mode == "baseline":
            self._log("info", f"Escaneo finalizado.")