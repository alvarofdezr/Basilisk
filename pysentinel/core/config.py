# pysentinel/core/config.py
import yaml
import os
import sys

class Config:
    def __init__(self, config_path="config.yaml"):
        self.config_path = config_path
        self.data = self._load_config()

    def _load_config(self):
        if not os.path.exists(self.config_path):
            # Si no existe, devolvemos diccionario vacío para evitar crashes,
            # aunque lo ideal es que el programa avise.
            print(f"[CONFIG] Advertencia: No se encontró {self.config_path}")
            return {}
        
        with open(self.config_path, "r") as f:
            try:
                return yaml.safe_load(f) or {}
            except yaml.YAMLError as exc:
                print(f"[CONFIG] Error leyendo YAML: {exc}")
                return {}

    @property
    def db_name(self):
        return self.data.get("database", {}).get("name", "pysentinel.db")

    @property
    def log_file(self):
        return self.data.get("monitoring", {}).get("log_file", "server_logs.txt")

    @property
    def directories(self):
        """Devuelve directorios a vigilar + Startup de Windows automático"""
        dirs = self.data.get("monitoring", {}).get("directories", [])
        
        # AUTO-DETECTAR CARPETA DE INICIO (Solo en Windows)
        if sys.platform == "win32":
            try:
                startup_path = os.path.join(os.getenv('APPDATA'), r'Microsoft\Windows\Start Menu\Programs\Startup')
                if os.path.exists(startup_path) and startup_path not in dirs:
                    dirs.append(startup_path)
            except:
                pass # Si falla la autodeteción, no pasa nada
                
        return dirs

    @property
    def network_whitelist(self):
        """Lista blanca de procesos de red"""
        default_list = ["chrome.exe", "firefox.exe", "msedge.exe", "svchost.exe"]
        return self.data.get("network", {}).get("whitelist", default_list)

    @property
    def active_response(self):
        """
        ESTA ES LA PROPIEDAD QUE TE FALTABA.
        Devuelve True/False sobre si activar el modo 'Kill Switch'.
        """
        return self.data.get("security", {}).get("active_response", False)