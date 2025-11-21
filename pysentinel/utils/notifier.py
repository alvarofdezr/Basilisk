# pysentinel/utils/notifier.py
import requests
from pysentinel.core.config import Config

class TelegramNotifier:
    def __init__(self, config: Config):
        self.enabled = config.data.get("alerts", {}).get("telegram", {}).get("enabled", False)
        self.token = config.data.get("alerts", {}).get("telegram", {}).get("token", "")
        self.chat_id = config.data.get("alerts", {}).get("telegram", {}).get("chat_id", "")
        self.base_url = f"https://api.telegram.org/bot{self.token}/sendMessage"

    def send_alert(self, message):
        """Envía el mensaje a tu móvil"""
        if not self.enabled:
            return

        try:
            payload = {
                "chat_id": self.chat_id,
                "text": f"🚨 [PySentinel ALERT] 🚨\n\n{message}",
                "parse_mode": "Markdown"
            }
            requests.post(self.base_url, data=payload, timeout=5)
        except Exception as e:
            print(f"[ERROR] Fallo enviando alerta Telegram: {e}")