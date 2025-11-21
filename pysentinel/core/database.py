# pysentinel/core/database.py
import sqlite3
import csv
from typing import Optional
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_name="pysentinel.db"):
        self.conn = sqlite3.connect(db_name, check_same_thread=False) # Importante para GUI
        self.cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        # Tabla 1: Integridad de archivos (FIM)
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                path TEXT PRIMARY KEY,
                hash TEXT
            )
        ''')
        
        # Tabla 2: Historial de Eventos (NUEVA)
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                type TEXT,       -- Ej: "FIM", "AUTH"
                message TEXT,
                severity TEXT    -- Ej: "INFO", "WARNING", "CRITICAL"
            )
        ''')
        self.conn.commit()

    # --- MÉTODOS DE ARCHIVOS (Igual que antes) ---
    def get_file_hash(self, path: str) -> Optional[str]:
        self.cursor.execute('SELECT hash FROM files WHERE path = ?', (path,))
        result = self.cursor.fetchone()
        return result[0] if result else None

    def update_file(self, path: str, file_hash: str):
        self.cursor.execute('''
            INSERT INTO files (path, hash) VALUES (?, ?)
            ON CONFLICT(path) DO UPDATE SET hash=excluded.hash
        ''', (path, file_hash))
        self.conn.commit()

    def delete_file(self, path: str):
        self.cursor.execute('DELETE FROM files WHERE path = ?', (path,))
        self.conn.commit()

    # --- MÉTODOS DE EVENTOS (NUEVOS) ---
    def log_event(self, event_type, message, severity="INFO"):
        """Guarda un evento en el historial permanente"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute('''
            INSERT INTO events (timestamp, type, message, severity)
            VALUES (?, ?, ?, ?)
        ''', (now, event_type, message, severity))
        self.conn.commit()

    def get_recent_events(self, limit=50):
        """Recupera los últimos eventos para mostrarlos en la GUI"""
        self.cursor.execute('SELECT timestamp, type, severity, message FROM events ORDER BY id DESC LIMIT ?', (limit,))
        return self.cursor.fetchall()

    def export_events_to_csv(self, filename="reporte_seguridad.csv"):
        """Exporta todos los eventos a un archivo CSV para Excel"""
        try:
            self.cursor.execute('SELECT timestamp, type, severity, message FROM events ORDER BY id DESC')
            rows = self.cursor.fetchall()
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # Escribir encabezados
                writer.writerow(["FECHA", "TIPO", "SEVERIDAD", "MENSAJE"])
                # Escribir datos
                writer.writerows(rows)
            return True, f"Exportado correctamente a {filename}"
        except Exception as e:
            return False, str(e)

    def close(self):
        self.conn.close()