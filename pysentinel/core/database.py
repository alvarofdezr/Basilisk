# pysentinel/core/database.py
import sqlite3
from typing import Optional

class DatabaseManager:
    def __init__(self, db_name="pysentinel.db"):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        """Crea la tabla necesaria para el FIM."""
        # Guardamos la ruta y el hash SHA256
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                path TEXT PRIMARY KEY,
                hash TEXT
            )
        ''')
        self.conn.commit()

    def get_file_hash(self, path: str) -> Optional[str]:
        """Recupera el hash guardado de un archivo."""
        self.cursor.execute('SELECT hash FROM files WHERE path = ?', (path,))
        result = self.cursor.fetchone()
        return result[0] if result else None

    def update_file(self, path: str, file_hash: str):
        """Inserta o actualiza un archivo en la BD."""
        self.cursor.execute('''
            INSERT INTO files (path, hash) VALUES (?, ?)
            ON CONFLICT(path) DO UPDATE SET hash=excluded.hash
        ''', (path, file_hash))
        self.conn.commit()

    def delete_file(self, path: str):
        """Elimina un registro si el archivo ya no existe."""
        self.cursor.execute('DELETE FROM files WHERE path = ?', (path,))
        self.conn.commit()

    def close(self):
        self.conn.close()