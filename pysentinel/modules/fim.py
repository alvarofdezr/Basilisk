# pysentinel/modules/fim.py
import os
import hashlib
from typing import Optional
from pysentinel.core.database import DatabaseManager
from pysentinel.utils.logger import Logger 

# Configuration Constants
LARGE_FILE_THRESHOLD = 50 * 1024 * 1024  # 50 MB
SMART_CHUNK_SIZE = 1 * 1024 * 1024       # 1 MB

class FileIntegrityMonitor:
    """
    Monitors filesystem changes using SHA-256 hashing.
    Implements 'Smart Hashing' for performance optimization on large files.
    """
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        try:
            self.logger = Logger()
        except:
            self.logger = None

    def _log(self, level: str, msg: str) -> None:
        """Safe wrapper for logging."""
        if self.logger:
            if level == "info": self.logger.info(msg)
            elif level == "warning": self.logger.warning(msg)
            elif level == "success": self.logger.success(msg)
            elif level == "error": self.logger.error(msg)
        else:
            print(f"[{level.upper()}] {msg}")

    def calculate_hash(self, file_path: str) -> Optional[str]:
        """
        Computes SHA-256 hash. 
        Uses full read for small files and header/footer sampling for large files.
        """
        sha256_hash = hashlib.sha256()
        try:
            file_size = os.path.getsize(file_path)
            
            with open(file_path, "rb") as f:
                if file_size < LARGE_FILE_THRESHOLD:
                    # Standard full hashing
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                else:
                    # Optimized partial hashing (Header + Footer + Size)
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

    def scan_directory(self, directory_path: str, mode: str = "monitor") -> None:
        """
        Recursive directory scan.
        :param mode: 'baseline' (learning phase) or 'monitor' (detection phase).
        """
        directory_path = os.path.normpath(directory_path)

        if mode == "baseline":
            self._log("info", f"Generating FIM Baseline for: {directory_path}...")

        for root, _, files in os.walk(directory_path):
            for file in files:
                full_path = os.path.normpath(os.path.join(root, file))
                
                # Exclusions
                if file.endswith(('.db', '.log-journal', '.tmp')):
                    continue

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
                            msg = f"FILE INTEGRITY COMPROMISED: {full_path}"
                            self._log("warning", msg)
                            self.db.log_event("FILE_MOD", msg, "CRITICAL")     
                    else:
                        msg = f"NEW FILE DETECTED: {full_path}"
                        self._log("success", msg)
                        self.db.log_event("FILE_NEW", msg, "WARNING")

        if mode == "baseline":
            self._log("info", "Baseline generation complete.")