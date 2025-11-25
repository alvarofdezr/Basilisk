# ARCHIVO: pysentinel/core/database.py
import sqlite3
import csv
from typing import Optional, List, Tuple, Any
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_name: str = "pysentinel.db") -> None:
        self.db_name: str = db_name 
        self.conn: sqlite3.Connection = sqlite3.connect(db_name, check_same_thread=False)
        self.cursor: sqlite3.Cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self) -> None:
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
        conn = sqlite3.connect(self.db_name) 
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO files_baseline (path, file_hash, last_modified)
            VALUES (?, ?, ?)
        ''', (path, file_hash, last_modified))
        conn.commit()
        conn.close()

    def get_file_baseline(self, path: str) -> Optional[Tuple[str, float]]:
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('SELECT file_hash, last_modified FROM files_baseline WHERE path = ?', (path,))
        result = cursor.fetchone()
        conn.close()
        return result 

    def log_event(self, event_type: str, message: str, severity: str = "INFO") -> None:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute('''
            INSERT INTO events (timestamp, type, message, severity)
            VALUES (?, ?, ?, ?)
        ''', (now, event_type, message, severity))
        self.conn.commit()

    def get_recent_events(self, limit: int = 50) -> List[Tuple[Any, ...]]:
        self.cursor.execute('SELECT timestamp, type, severity, message FROM events ORDER BY id DESC LIMIT ?', (limit,))
        return self.cursor.fetchall()

    def export_events_to_csv(self, filename: str = "reporte_seguridad.csv") -> Tuple[bool, str]:
        try:
            self.cursor.execute('SELECT timestamp, type, severity, message FROM events ORDER BY id DESC')
            rows = self.cursor.fetchall()
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["FECHA", "TIPO", "SEVERIDAD", "MENSAJE"])
                writer.writerows(rows)
            return True, f"Exportado correctamente a {filename}"
        except Exception as e:
            return False, str(e)

    # --- MÉTODOS PARA DASHBOARD (ESTADÍSTICAS) ---
    def get_stats_by_severity(self) -> List[Tuple[str, int]]:
        """Devuelve conteo de eventos por severidad (para gráfico de tarta)"""
        # Ejemplo: [('INFO', 50), ('WARNING', 10), ('CRITICAL', 2)]
        self.cursor.execute('SELECT severity, COUNT(*) FROM events GROUP BY severity')
        return self.cursor.fetchall()

    def get_activity_last_24h(self) -> int:
        """Cuenta eventos totales en las últimas 24h (para el Score de Salud)"""
        # Nota: En SQL simple comparamos strings de fecha, asumimos formato YYYY-MM-DD...
        # Para simplificar en este MVP, contamos los últimos 100 eventos y vemos cuántos son de hoy
        today = datetime.now().strftime("%Y-%m-%d")
        self.cursor.execute("SELECT COUNT(*) FROM events WHERE timestamp LIKE ?", (f"{today}%",))
        result = self.cursor.fetchone()
        return result[0] if result else 0

    def get_stats_by_type(self) -> List[Tuple[str, int]]:
        """Devuelve conteo por tipo de evento (USB, NET, FILE...)"""
        self.cursor.execute('SELECT type, COUNT(*) FROM events GROUP BY type ORDER BY COUNT(*) DESC LIMIT 5')
        return self.cursor.fetchall()

    def close(self) -> None:
        self.conn.close()