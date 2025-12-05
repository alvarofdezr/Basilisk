# basilisk/core/config.py
from typing import Any, Dict, List
import yaml
import os
import sys
from dotenv import load_dotenv

class Config:
    """
    Loads configuration from environment variables (Priority 1) and 'config.yaml' (Priority 2).
    Includes robust path detection for .env files in different execution contexts.
    """
    def __init__(self, config_path: str = "config.yaml") -> None:
        # Calcular rutas absolutas para garantizar la carga del .env
        current_dir = os.path.dirname(os.path.abspath(__file__)) 
        project_root = os.path.abspath(os.path.join(current_dir, '..', '..')) 
        env_path = os.path.join(project_root, '.env')

        # Cargar variables de entorno silenciosamente
        if os.path.exists(env_path):
            load_dotenv(dotenv_path=env_path, override=True)
        else:
            # Fallback: Intentar cargar desde el directorio de trabajo actual
            load_dotenv(override=True)

        self.config_path = config_path
        self.data = self._load_yaml()

    def _load_yaml(self) -> Dict[str, Any]:
        if not os.path.exists(self.config_path):
            return {}
        try:
            with open(self.config_path, "r") as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError:
            return {}

    @property
    def db_name(self) -> str:
        return os.getenv("BASILISK_DB_NAME", self.data.get("database", {}).get("name", "basilisk.db"))

    @property
    def directories(self) -> List[str]:
        dirs = self.data.get("monitoring", {}).get("directories", [])
        if sys.platform == "win32":
            appdata = os.getenv('APPDATA')
            if appdata:
                startup = os.path.join(appdata, r'Microsoft\Windows\Start Menu\Programs\Startup')
                if os.path.exists(startup) and startup not in dirs:
                    dirs.append(startup)
        return dirs

    @property
    def network_whitelist(self) -> List[str]:
        default = ["chrome.exe", "firefox.exe", "msedge.exe", "svchost.exe", "python.exe"]
        return self.data.get("network", {}).get("whitelist", default)

    # --- SECRETOS ---
    @property
    def admin_hash(self) -> str:
        return os.getenv("BASILISK_ADMIN_PASSWORD_HASH", "")

    @property
    def virustotal_api_key(self) -> str:
        return os.getenv("BASILISK_VIRUSTOTAL_API_KEY", "")

    @property
    def telegram_token(self) -> str:
        return os.getenv("BASILISK_TELEGRAM_TOKEN", "")

    @property
    def telegram_chat_id(self) -> str:
        return os.getenv("BASILISK_TELEGRAM_CHAT_ID", "")
    
    @property
    def c2_url(self) -> str:
        return os.getenv("BASILISK_C2_URL", "https://localhost:8443")
    
    @property
    def server_secret_key(self) -> str:
        return os.getenv("BASILISK_SERVER_SECRET_KEY", "")