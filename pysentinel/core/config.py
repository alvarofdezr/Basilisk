# pysentinel/core/config.py
import sys
import yaml
import os

class Config:
    def __init__(self, config_path="config.yaml"):
        self.config_path = config_path
        self.data = self._load_config()

    def _load_config(self):
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"No se encontró el archivo de configuración: {self.config_path}")
        
        with open(self.config_path, "r") as f:
            try:
                return yaml.safe_load(f)
            except yaml.YAMLError as exc:
                print(f"Error leyendo YAML: {exc}")
                return {}
    @property
    def directories(self):
        # Leemos del YAML
        dirs = self.data.get("monitoring", {}).get("directories", [])
        
        # --- INTELIGENCIA AUTOMÁTICA ---
        # Si la lista está vacía o queremos añadir rutas críticas por defecto:
        if sys.platform == "win32":
            # Añadimos la carpeta de Inicio de Windows automáticamente
            startup_path = os.path.join(os.getenv('APPDATA'), r'Microsoft\Windows\Start Menu\Programs\Startup')
            if startup_path not in dirs:
                dirs.append(startup_path)
                print(f"[AUTO] Añadida ruta crítica de Inicio: {startup_path}")
                
        return dirs
    
    @property
    def directories(self):
        return self.data.get("monitoring", {}).get("directories", [])

    @property
    def log_file(self):
        return self.data.get("monitoring", {}).get("log_file", "server_logs.txt")

    @property
    def db_name(self):
        return self.data.get("database", {}).get("name", "pysentinel.db")