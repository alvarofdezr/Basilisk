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
            return {}
        
        try:
            with open(self.config_path, "r") as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError:
            return {}

    @property
    def db_name(self):
        return self.data.get("database", {}).get("name", "pysentinel.db")

    @property
    def log_file(self):
        return self.data.get("monitoring", {}).get("log_file", "pysentinel.log")

    @property
    def directories(self):
        """Obtiene directorios configurados y añade Start Menu si es Windows."""
        dirs = self.data.get("monitoring", {}).get("directories", [])
        
        if sys.platform == "win32":
            try:
                startup = os.path.join(os.getenv('APPDATA'), r'Microsoft\Windows\Start Menu\Programs\Startup')
                if os.path.exists(startup) and startup not in dirs:
                    dirs.append(startup)
            except Exception:
                pass
        return dirs

    @property
    def network_whitelist(self):
        default = ["chrome.exe", "firefox.exe", "msedge.exe", "svchost.exe", "python.exe"]
        return self.data.get("network", {}).get("whitelist", default)

    @property
    def active_response(self):
        return self.data.get("security", {}).get("active_response", False)

    @property
    def admin_hash(self):
        """Hash SHA-256 para operaciones administrativas."""
        return self.data.get("security", {}).get("admin_password_hash", "")

    @property
    def telegram_token(self):
        return self.data.get("notifications", {}).get("telegram_token", "")

    @property
    def telegram_chat_id(self):
        return self.data.get("notifications", {}).get("telegram_chat_id", "")