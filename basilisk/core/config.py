# basilisk/core/config.py
import yaml
import os
import sys
from typing import List, Dict, Any

class Config:
    """
    Loads and validates configuration from 'config.yaml'.
    Includes default fallback values and OS-specific path adjustments.
    """
    def __init__(self, config_path: str = "config.yaml") -> None:
        self.config_path: str = config_path
        self.data: Dict[str, Any] = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        if not os.path.exists(self.config_path):
            return {}
        try:
            with open(self.config_path, "r") as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError:
            return {}

    @property
    def db_name(self) -> str:
        return str(self.data.get("database", {}).get("name", "basilisk.db"))

    @property
    def directories(self) -> List[str]:
        """Returns list of directories to monitor (FIM). Adds Startup folder on Windows."""
        dirs: List[str] = self.data.get("monitoring", {}).get("directories", [])
        if sys.platform == "win32":
            try:
                appdata = os.getenv('APPDATA')
                if appdata:
                    startup = os.path.join(appdata, r'Microsoft\Windows\Start Menu\Programs\Startup')
                    if os.path.exists(startup) and startup not in dirs:
                        dirs.append(startup)
            except Exception:
                pass
        return dirs

    @property
    def network_whitelist(self) -> List[str]:
        default = ["chrome.exe", "firefox.exe", "msedge.exe", "svchost.exe", "python.exe"]
        return self.data.get("network", {}).get("whitelist", default)

    @property
    def admin_hash(self) -> str:
        return str(self.data.get("security", {}).get("admin_password_hash", ""))

    @property
    def virustotal_api_key(self) -> str:
        return str(self.data.get("security", {}).get("virustotal_api_key", ""))

    @property
    def telegram_token(self) -> str:
        return str(self.data.get("notifications", {}).get("telegram_token", ""))

    @property
    def telegram_chat_id(self) -> str:
        return str(self.data.get("notifications", {}).get("telegram_chat_id", ""))