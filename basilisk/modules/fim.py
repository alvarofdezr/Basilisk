# basilisk/modules/fim.py
"""
Basilisk EDR - File Integrity Monitor (FIM)
v6.5 Stable
"""
import os
import hashlib
import sqlite3
from typing import Optional, Set
from basilisk.core.database import DatabaseManager
from basilisk.utils.logger import Logger 

# Configuration Constants
LARGE_FILE_THRESHOLD = 50 * 1024 * 1024  # 50 MB
SMART_CHUNK_SIZE = 1 * 1024 * 1024       # 1 MB

class FileIntegrityMonitor:
    """
    Monitorea cambios en el sistema de archivos usando hashing SHA-256.
    [FIX v6.5] Ahora detecta archivos eliminados comparando BBDD vs Disco.
    """
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        try:
            self.logger = Logger()
        except:
            self.logger = None

    def _log(self, level: str, msg: str) -> None:
        """Wrapper seguro para logging."""
        if self.logger:
            if level == "info": self.logger.info(msg)
            elif level == "warning": self.logger.warning(msg)
            elif level == "success": self.logger.success(msg)
            elif level == "error": self.logger.error(msg)
        else:
            print(f"[{level.upper()}] {msg}")

    def calculate_hash(self, file_path: str) -> Optional[str]:
        """
        Calcula SHA-256 usando Smart Hashing para archivos grandes.
        """
        sha256_hash = hashlib.sha256()
        try:
            # Check rápido de existencia antes de abrir
            if not os.path.exists(file_path):
                return None
                
            file_size = os.path.getsize(file_path)
            
            with open(file_path, "rb") as f:
                if file_size < LARGE_FILE_THRESHOLD:
                    # Hashing completo estándar
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                else:
                    # Smart Hashing (Optimizado): Header + Footer + Size
                    sha256_hash.update(f.read(SMART_CHUNK_SIZE))
                    
                    if file_size > SMART_CHUNK_SIZE:
                        seek_pos = max(file_size - SMART_CHUNK_SIZE, 0)
                        f.seek(seek_pos)
                        sha256_hash.update(f.read(SMART_CHUNK_SIZE))
                    
                    sha256_hash.update(str(file_size).encode())

            return sha256_hash.hexdigest()
            
        except (PermissionError, OSError):
            return None
        except Exception:
            return None

    def _get_db_files_in_dir(self, directory: str) -> Set[str]:
        """
        Recupera todos los paths monitoreados bajo un directorio específico desde la BBDD.
        """
        known_files = set()
        try:
            # Accedemos a la conexión del DatabaseManager
            conn = getattr(self.db, 'conn', None)
            
            if conn:
                cursor = conn.cursor()
                
                # [CORRECCIÓN] Usamos el nombre real de la tabla: 'files_baseline'
                query = "SELECT path FROM files_baseline WHERE path LIKE ? OR path LIKE ?"
                
                # Normalizamos para soportar barras de Windows/Linux
                search_path = os.path.normpath(directory)
                
                # Buscamos archivos que empiecen por la ruta del directorio
                cursor.execute(query, (f"{search_path}\\%", f"{search_path}/%"))
                
                rows = cursor.fetchall()
                for row in rows:
                    known_files.add(os.path.normpath(row[0]))
            else:
                self._log("error", "FIM: No se pudo acceder a la conexión BBDD para detectar borrados.")
                
        except Exception as e:
            self._log("error", f"FIM DB Query Error: {e}")
            
        return known_files

    def scan_directory(self, directory_path: str, mode: str = "monitor") -> None:
        """
        Escaneo recursivo con detección de: NUEVOS, MODIFICADOS y ELIMINADOS.
        """
        directory_path = os.path.normpath(directory_path)
        
        # Conjunto para rastrear qué archivos existen físicamente en este escaneo
        found_files_on_disk: Set[str] = set()

        if mode == "baseline":
            self._log("info", f"Generando FIM Baseline para: {directory_path}...")

        # 1. Fase de Detección (Disco -> BBDD)
        for root, _, files in os.walk(directory_path):
            for file in files:
                full_path = os.path.normpath(os.path.join(root, file))
                
                # Exclusiones de archivos volátiles
                if file.endswith(('.db', '.log-journal', '.tmp', '.pyc', '.git')):
                    continue

                found_files_on_disk.add(full_path)

                current_hash = self.calculate_hash(full_path)
                if not current_hash: continue 
                
                current_mtime = os.path.getmtime(full_path)

                if mode == "baseline":
                    self.db.update_baseline(full_path, current_hash, current_mtime)
                
                elif mode == "monitor":
                    stored_data = self.db.get_file_baseline(full_path)
                    
                    if stored_data:
                        stored_hash, _ = stored_data
                        if current_hash != stored_hash:
                            msg = f"⚠️ INTEGRIDAD COMPROMETIDA (Modificado): {full_path}"
                            self._log("warning", msg)
                            self.db.log_event("FILE_MOD", msg, "CRITICAL")     
                    else:
                        msg = f"📄 NUEVO ARCHIVO DETECTADO: {full_path}"
                        self._log("success", msg)
                        self.db.log_event("FILE_NEW", msg, "WARNING")
                        # Auto-update baseline para nuevos archivos
                        self.db.update_baseline(full_path, current_hash, current_mtime)

        # 2. Fase de Comprobación de Eliminados (BBDD -> Disco)
        if mode == "monitor":
            # Obtenemos lo que la BBDD "cree" que debería haber
            known_files_in_db = self._get_db_files_in_dir(directory_path)
            
            # Resta de conjuntos: Lo que está en BBDD pero NO en el disco
            deleted_files = known_files_in_db - found_files_on_disk
            
            for deleted_path in deleted_files:
                # Verificar una última vez que realmente no existe (evitar race conditions)
                if not os.path.exists(deleted_path):
                    msg = f"🗑️ ARCHIVO ELIMINADO (Posible borrado de huellas): {deleted_path}"
                    self._log("warning", msg)
                    self.db.log_event("FILE_DEL", msg, "CRITICAL")
                    
                    # Opcional: Eliminar de la baseline para que no siga alertando
                    # Por ahora lo dejamos para que el Admin lo investigue

        if mode == "baseline":
            self._log("info", "Baseline generation complete.")