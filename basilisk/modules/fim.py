"""
File Integrity Monitor - Smart Hash-Based Change Detection

Monitors filesystem changes using SHA256 hashing with smart caching strategy.
Avoids redundant hashing of large files by comparing mtime/size first.
Baseline comparison detects file modifications, new files, and deletions.

Smart Hashing Strategy:
- Small files (<50MB): Full file hash
- Large files (>50MB): First 1MB + Last 1MB + filesize hash
  (Catches content modifications without full hash overhead)
"""
import os
import hashlib
from typing import Optional, Set
from basilisk.core.database import DatabaseManager
from basilisk.utils.logger import Logger

LARGE_FILE_THRESHOLD = 50 * 1024 * 1024
SMART_CHUNK_SIZE = 1 * 1024 * 1024


class FileIntegrityMonitor:
    """Monitor filesystem for unauthorized file modifications.
    
    Maintains baseline hashes of monitored directories. On each scan,
    compares current hashes against baseline to identify:
    - Modified files: Content changes detected via hash mismatch
    - New files: Not in baseline (new additions to monitored path)
    - Deleted files: In baseline but missing on disk
    
    Smart caching uses mtime/size to skip unchanged files, reducing CPU
    impact on large directories.
    """

    def __init__(self, db_manager: DatabaseManager):
        """Initialize file integrity monitor with database backend.
        
        Args:
            db_manager: DatabaseManager instance for baseline storage
        """
        self.db = db_manager
        self.logger = Logger()

    def _log(self, level: str, msg: str) -> None:
        """Route logging messages through Logger with level selector.
        
        Args:
            level: Log level (info, warning, success, error)
            msg: Message text to log
        """
        if level == "info":
            self.logger.info(msg)
        elif level == "warning":
            self.logger.warning(msg)
        elif level == "success":
            self.logger.success(msg)
        elif level == "error":
            self.logger.error(msg)

    def calculate_hash(self, file_path: str) -> Optional[str]:
        """Compute SHA256 hash using smart caching for large files.
        
        Large File Strategy:
        - Files >50MB: Hash first 1MB + last 1MB + file size
        - Catches header/footer modifications (virus injection)
        - Avoids hashing entire large archives/disk images
        
        Small files hashed completely in 4KB chunks.
        
        Args:
            file_path: Absolute path to file
            
        Returns:
            str: SHA256 hexdigest or None if file missing/access denied
        """
        sha256_hash = hashlib.sha256()
        try:
            if not os.path.exists(file_path):
                return None
            file_size = os.path.getsize(file_path)

            with open(file_path, "rb") as f:
                if file_size < LARGE_FILE_THRESHOLD:
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                else:
                    sha256_hash.update(f.read(SMART_CHUNK_SIZE))
                    if file_size > SMART_CHUNK_SIZE:
                        f.seek(max(file_size - SMART_CHUNK_SIZE, 0))
                        sha256_hash.update(f.read(SMART_CHUNK_SIZE))
                    sha256_hash.update(str(file_size).encode())

            return sha256_hash.hexdigest()
        except (PermissionError, OSError):
            return None

    def _get_db_files_in_dir(self, directory: str) -> Set[str]:
        """Retrieve all known baseline files in directory from database.
        
        Queries files_baseline table for paths matching directory using
        LIKE wildcard with both forward and backward slashes.
        
        Args:
            directory: Directory path to retrieve baseline for
            
        Returns:
            Set[str]: Normalized paths of all known files in directory
        """
        known_files: Set[str] = set()
        try:
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
        """Scan directory for file changes using baseline comparison.
        
        Two modes:
        - baseline: Create initial baseline (hash all files, store in DB)
        - monitor: Compare current hashes vs baseline, alert on changes
        
        Filters out non-essential files (.db, .log, .tmp, .pyc, .git).
        
        Detection Logic:
        - Modified: mtime changed AND hash mismatch
        - New: Path not in baseline
        - Deleted: Path in baseline but missing on disk
        
        Args:
            directory_path: Root directory to scan (recursive)
            mode: Either "baseline" (initialize) or "monitor" (detect changes)
        """
        directory_path = os.path.normpath(directory_path)
        found_files_on_disk: Set[str] = set()

        if mode == "baseline":
            self._log("info", f"Generating FIM Baseline for: {directory_path}...")

        for root, _, files in os.walk(directory_path):
            for file in files:
                full_path = os.path.normpath(os.path.join(root, file))
                if file.endswith(('.db', '.log', '.tmp', '.pyc', '.git')):
                    continue

                found_files_on_disk.add(full_path)

                try:
                    current_mtime = os.path.getmtime(full_path)
                    stored_data = self.db.get_file_baseline(full_path)

                    if stored_data:
                        stored_hash, stored_mtime = stored_data
                        if abs(current_mtime - stored_mtime) < 1.0:
                            continue

                    current_hash = self.calculate_hash(full_path)
                    if not current_hash:
                        continue

                    if mode == "baseline":
                        self.db.update_baseline(full_path, current_hash, current_mtime)

                    elif mode == "monitor":
                        if stored_data:
                            if current_hash != stored_data[0]:
                                msg = f"File Integrity Violation (Modified): {full_path}"
                                self._log("warning", msg)
                                self.db.log_event("FILE_MOD", msg, "CRITICAL")
                                self.db.update_baseline(full_path, current_hash, current_mtime)
                        else:
                            msg = f"New file detected: {full_path}"
                            self._log("success", msg)
                            self.db.log_event("FILE_NEW", msg, "WARNING")
                            self.db.update_baseline(full_path, current_hash, current_mtime)

                except OSError:
                    pass

        if mode == "monitor":
            known_files = self._get_db_files_in_dir(directory_path)
            deleted_files = known_files - found_files_on_disk

            for deleted_path in deleted_files:
                if not os.path.exists(deleted_path):
                    msg = f"File deleted from monitored path: {deleted_path}"
                    self._log("warning", msg)
                    self.db.log_event("FILE_DEL", msg, "CRITICAL")

                    with self.db.lock:
                        cursor = self.db.conn.cursor()
                        cursor.execute("DELETE FROM files_baseline WHERE path=?", (deleted_path,))
                        self.db.conn.commit()

        if mode == "baseline":
            self._log("info", "Baseline generation completed.")
