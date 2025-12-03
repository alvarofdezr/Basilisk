# basilisk/utils/notifier.py
import requests
from basilisk.core.config import Config
from basilisk.utils.logger import Logger

class TelegramNotifier:
    """
    Handles push notifications via Telegram Bot API.
    """
    def __init__(self, config: Config):
        self.logger = Logger()
        self.enabled = config.data.get("alerts", {}).get("telegram", {}).get("enabled", False)
        self.token = config.data.get("alerts", {}).get("telegram", {}).get("token", "")
        self.chat_id = config.data.get("alerts", {}).get("telegram", {}).get("chat_id", "")
        self.base_url = f"https://api.telegram.org/bot{self.token}/sendMessage"

    def send_alert(self, message: str) -> None:
        """Sends a formatted message to the configured Telegram chat."""
        if not self.enabled:
            return

        try:
            payload = {
                "chat_id": self.chat_id,
                "text": f"🚨 [basilisk] 🚨\n\n{message}",
                "parse_mode": "Markdown"
            }
            # Timeout is crucial to avoid blocking the main thread
            requests.post(self.base_url, data=payload, timeout=5)
        except Exception as e:
            self.logger.error(f"Telegram notification failed: {e}")