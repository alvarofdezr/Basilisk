# pysentinel/core/database.py
import sqlite3
import csv
from typing import Optional
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_name="pysentinel.db"):
        self.db_name = db_name # Guardamos el nombre para reconexiones si hace falta
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        # Tabla 1: Historial de Eventos (Existente)
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                type TEXT,
                message TEXT,
                severity TEXT
            )
        ''')

        # Tabla 2: LÍNEA BASE (Snapshot) - NUEVA
        # Guarda el estado "correcto" de los archivos (Ruta, Hash, Fecha Modificación)
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS files_baseline (
                path TEXT PRIMARY KEY,
                file_hash TEXT,
                last_modified FLOAT
            )
        ''')
        
        self.conn.commit()

    # --- MÉTODOS DE LÍNEA BASE (SNAPSHOT) ---
    def update_baseline(self, path: str, file_hash: str, last_modified: float):
        """Guarda o actualiza la foto inicial de un archivo"""
        # Usamos una nueva conexión para evitar problemas de hilos si se llama desde threads
        conn = sqlite3.connect(self.db_name) 
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO files_baseline (path, file_hash, last_modified)
            VALUES (?, ?, ?)
        ''', (path, file_hash, last_modified))
        conn.commit()
        conn.close()

    def get_file_baseline(self, path: str):
        """Recupera los datos guardados de la línea base"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('SELECT file_hash, last_modified FROM files_baseline WHERE path = ?', (path,))
        result = cursor.fetchone()
        conn.close()
        return result # Retorna (hash, last_modified) o None

    # --- MÉTODOS DE EVENTOS ---
    def log_event(self, event_type, message, severity="INFO"):
        """Guarda un evento en el historial permanente"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute('''
            INSERT INTO events (timestamp, type, message, severity)
            VALUES (?, ?, ?, ?)
        ''', (now, event_type, message, severity))
        self.conn.commit()

    def get_recent_events(self, limit=50):
        self.cursor.execute('SELECT timestamp, type, severity, message FROM events ORDER BY id DESC LIMIT ?', (limit,))
        return self.cursor.fetchall()

    def export_events_to_csv(self, filename="reporte_seguridad.csv"):
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

    def close(self):
        self.conn.close()