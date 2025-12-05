# basilisk/core/database.py
import sqlite3
import csv
import threading
import os
from typing import Optional, List, Tuple, Any
from datetime import datetime

class DatabaseManager:
    """
    Thread-safe SQLite manager for the agent.
    Implements explicit locking to prevent race conditions during concurrent module execution.
    """
    def __init__(self, db_name: str = "basilisk.db") -> None:
        self.db_name = db_name
        self.lock = threading.Lock()
        
        # 'check_same_thread=False' is needed because connection is shared, 
        # but self.lock ensures we serialize access manually.
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self._configure_pragmas()
        self.create_tables()

    def _configure_pragmas(self):
        """Enable Write-Ahead Logging (WAL) for better concurrency."""
        try:
            with self.lock:
                self.conn.execute('PRAGMA journal_mode=WAL;')
                self.conn.execute('PRAGMA synchronous=NORMAL;')
        except sqlite3.Error:
            pass

    def create_tables(self) -> None:
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        type TEXT,
                        message TEXT,
                        severity TEXT
                    )
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS files_baseline (
                        path TEXT PRIMARY KEY,
                        file_hash TEXT,
                        last_modified FLOAT
                    )
                ''')
                self.conn.commit()
            except sqlite3.Error as e:
                print(f"[DB ERROR] Init failed: {e}")

    def update_baseline(self, path: str, file_hash: str, last_modified: float) -> None:
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO files_baseline (path, file_hash, last_modified)
                    VALUES (?, ?, ?)
                ''', (path, file_hash, last_modified))
                self.conn.commit()
            except sqlite3.Error:
                pass

    def get_file_baseline(self, path: str) -> Optional[Tuple[str, float]]:
        # Reads can also be locked to prevent reading while writing in edge cases,
        # though WAL mode handles this better. We lock for safety.
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('SELECT file_hash, last_modified FROM files_baseline WHERE path = ?', (path,))
                return cursor.fetchone()
            except sqlite3.Error:
                return None

    def log_event(self, event_type: str, message: str, severity: str = "INFO") -> None:
        with self.lock:
            try:
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor = self.conn.cursor()
                cursor.execute('''
                    INSERT INTO events (timestamp, type, message, severity)
                    VALUES (?, ?, ?, ?)
                ''', (now, event_type, message, severity))
                self.conn.commit()
            except sqlite3.Error as e:
                print(f"[DB ERROR] Log event failed: {e}")

    def get_recent_events(self, limit: int = 50) -> List[Tuple[Any, ...]]:
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('SELECT timestamp, type, severity, message FROM events ORDER BY id DESC LIMIT ?', (limit,))
                return cursor.fetchall()
            except sqlite3.Error:
                return []

    def export_events_to_csv(self, filename: str = "security_report.csv") -> Tuple[bool, str]:
        with self.lock:
            try:
                cursor = self.conn.cursor()
                cursor.execute('SELECT timestamp, type, severity, message FROM events ORDER BY id DESC')
                rows = cursor.fetchall()
                
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["TIMESTAMP", "TYPE", "SEVERITY", "MESSAGE"])
                    writer.writerows(rows)
                return True, f"Exported to {filename}"
            except Exception as e:
                return False, str(e)

    def close(self) -> None:
        with self.lock:
            try:
                self.conn.close()
            except: pass