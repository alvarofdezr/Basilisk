# pysentinel/core/database.py
import sqlite3
import csv
from typing import Optional, List, Tuple, Any
from datetime import datetime

class DatabaseManager:
    """
    Handles local SQLite interactions for event logging and FIM baselines.
    Thread-safe connection management for the agent.
    """
    def __init__(self, db_name: str = "pysentinel.db") -> None:
        self.db_name: str = db_name 
        # check_same_thread=False is required for multi-threaded agent architecture
        self.conn: sqlite3.Connection = sqlite3.connect(db_name, check_same_thread=False)
        self.cursor: sqlite3.Cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self) -> None:
        """Initializes database schema."""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                type TEXT,
                message TEXT,
                severity TEXT
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS files_baseline (
                path TEXT PRIMARY KEY,
                file_hash TEXT,
                last_modified FLOAT
            )
        ''')
        self.conn.commit()

    def update_baseline(self, path: str, file_hash: str, last_modified: float) -> None:
        """Updates or inserts a file record in the FIM baseline."""
        # Using a fresh connection for atomic updates to avoid locks
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO files_baseline (path, file_hash, last_modified)
                VALUES (?, ?, ?)
            ''', (path, file_hash, last_modified))
            conn.commit()

    def get_file_baseline(self, path: str) -> Optional[Tuple[str, float]]:
        """Retrieves stored hash and timestamp for a specific file."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT file_hash, last_modified FROM files_baseline WHERE path = ?', (path,))
            return cursor.fetchone()

    def log_event(self, event_type: str, message: str, severity: str = "INFO") -> None:
        """Persists security events locally."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute('''
            INSERT INTO events (timestamp, type, message, severity)
            VALUES (?, ?, ?, ?)
        ''', (now, event_type, message, severity))
        self.conn.commit()

    def get_recent_events(self, limit: int = 50) -> List[Tuple[Any, ...]]:
        self.cursor.execute('SELECT timestamp, type, severity, message FROM events ORDER BY id DESC LIMIT ?', (limit,))
        return self.cursor.fetchall()

    def export_events_to_csv(self, filename: str = "security_report.csv") -> Tuple[bool, str]:
        """Exports event history to CSV format."""
        try:
            self.cursor.execute('SELECT timestamp, type, severity, message FROM events ORDER BY id DESC')
            rows = self.cursor.fetchall()
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["TIMESTAMP", "TYPE", "SEVERITY", "MESSAGE"])
                writer.writerows(rows)
            return True, f"Exported to {filename}"
        except Exception as e:
            return False, str(e)

    def close(self) -> None:
        self.conn.close()