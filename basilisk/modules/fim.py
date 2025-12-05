# basilisk/modules/fim.py
"""
Basilisk EDR - File Integrity Monitor (Smart Caching v6.6)
Utiliza metadatos (mtime/size) para evitar hashing redundante.
"""
import os
import hashlib
from typing import Optional, Set, Tuple
from basilisk.core.database import DatabaseManager
from basilisk.utils.logger import Logger 

# Configuración de rendimiento
LARGE_FILE_THRESHOLD = 50 * 1024 * 1024  # 50 MB
SMART_CHUNK_SIZE = 1 * 1024 * 1024       # 1 MB

class FileIntegrityMonitor:
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.logger = Logger()

    def _log(self, level: str, msg: str) -> None:
        if level == "info": self.logger.info(msg)
        elif level == "warning": self.logger.warning(msg)
        elif level == "success": self.logger.success(msg)
        elif level == "error": self.logger.error(msg)

    def calculate_hash(self, file_path: str) -> Optional[str]:
        """Calcula SHA-256 usando Smart Hashing para archivos grandes."""
        sha256_hash = hashlib.sha256()
        try:
            if not os.path.exists(file_path): return None
            file_size = os.path.getsize(file_path)
            
            with open(file_path, "rb") as f:
                if file_size < LARGE_FILE_THRESHOLD:
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                else:
                    # Optimización: Hash de cabecera + pie + tamaño
                    sha256_hash.update(f.read(SMART_CHUNK_SIZE))
                    if file_size > SMART_CHUNK_SIZE:
                        f.seek(max(file_size - SMART_CHUNK_SIZE, 0))
                        sha256_hash.update(f.read(SMART_CHUNK_SIZE))
                    sha256_hash.update(str(file_size).encode())

            return sha256_hash.hexdigest()
        except (PermissionError, OSError):
            return None

    def _get_db_files_in_dir(self, directory: str) -> Set[str]:
        """Recupera paths conocidos desde la BBDD."""
        known_files = set()
        try:
            # Usamos una nueva conexión para evitar problemas de hilos si el manager no lo gestiona
            # Pero como DatabaseManager tiene lock, usamos sus métodos si es posible.
            # Aquí asumimos acceso directo seguro o usamos el método público.
            # Nota: Para optimizar, mejor no exponer SQL directo aquí, pero por compatibilidad:
            with self.db.lock:
                cursor = self.db.conn.cursor()
                search_path = os.path.normpath(directory)
                query = "SELECT path FROM files_baseline WHERE path LIKE ? OR path LIKE ?"
                cursor.execute(query, (f"{search_path}\\%", f"{search_path}/%"))
                for row in cursor.fetchall():
                    known_files.add(os.path.normpath(row[0]))
        except Exception as e:
            self._log("error", f"FIM DB Error: {e}")
        return known_files

    def scan_directory(self, directory_path: str, mode: str = "monitor") -> None:
        directory_path = os.path.normpath(directory_path)
        found_files_on_disk: Set[str] = set()

        if mode == "baseline":
            self._log("info", f"Generando FIM Baseline para: {directory_path}...")

        for root, _, files in os.walk(directory_path):
            for file in files:
                full_path = os.path.normpath(os.path.join(root, file))
                if file.endswith(('.db', '.log', '.tmp', '.pyc', '.git')): continue

                found_files_on_disk.add(full_path)
                
                try:
                    current_mtime = os.path.getmtime(full_path)
                    
                    # [OPTIMIZACIÓN CLAVE] Consultar caché antes de hashear
                    stored_data = self.db.get_file_baseline(full_path)
                    
                    if stored_data:
                        stored_hash, stored_mtime = stored_data
                        
                        # Si la fecha de modificación NO ha cambiado, asumimos que el fichero es igual.
                        # Esto ahorra el 99% del trabajo en pasadas sucesivas.
                        if abs(current_mtime - stored_mtime) < 1.0:
                            continue 

                    # Si llegamos aquí, es nuevo o ha cambiado de fecha -> HASHEAR
                    current_hash = self.calculate_hash(full_path)
                    if not current_hash: continue

                    if mode == "baseline":
                        self.db.update_baseline(full_path, current_hash, current_mtime)
                    
                    elif mode == "monitor":
                        if stored_data:
                            if current_hash != stored_hash:
                                msg = f"⚠️ INTEGRIDAD COMPROMETIDA (Modificado): {full_path}"
                                self._log("warning", msg)
                                self.db.log_event("FILE_MOD", msg, "CRITICAL")
                                # Actualizamos para no alertar infinitamente
                                self.db.update_baseline(full_path, current_hash, current_mtime)
                        else:
                            msg = f"📄 NUEVO ARCHIVO: {full_path}"
                            self._log("success", msg)
                            self.db.log_event("FILE_NEW", msg, "WARNING")
                            self.db.update_baseline(full_path, current_hash, current_mtime)
                            
                except OSError: pass

        # Detección de Eliminados
        if mode == "monitor":
            known_files = self._get_db_files_in_dir(directory_path)
            deleted_files = known_files - found_files_on_disk
            for deleted_path in deleted_files:
                if not os.path.exists(deleted_path):
                    msg = f"🗑️ ARCHIVO ELIMINADO: {deleted_path}"
                    self._log("warning", msg)
                    self.db.log_event("FILE_DEL", msg, "CRITICAL")
                    # Borrar de BBDD para limpiar estado
                    with self.db.lock:
                        self.db.cursor.execute("DELETE FROM files_baseline WHERE path=?", (deleted_path,))
                        self.db.conn.commit()

        if mode == "baseline":
            self._log("info", "Baseline completada.")