"""
Basilisk Notification System
Telegram Bot API integration for real-time security alerts.
"""
import requests
from basilisk.core.config import Config
from basilisk.utils.logger import Logger


class TelegramNotifier:
    """Async notification delivery via Telegram Bot API with timeout protection."""

    def __init__(self, config: Config) -> None:
        self.logger = Logger()
        alerts_config = config.data.get("alerts", {}).get("telegram", {})
        
        self.enabled = alerts_config.get("enabled", False)
        self.token = alerts_config.get("token", "")
        self.chat_id = alerts_config.get("chat_id", "")
        self.base_url = f"https://api.telegram.org/bot{self.token}/sendMessage"

    def send_alert(self, message: str) -> None:
        """
        Send formatted security alert to configured Telegram chat.
        
        Args:
            message: Alert content (supports Markdown formatting)
        """
        if not self.enabled:
            return

        try:
            payload = {
                "chat_id": self.chat_id,
                "text": f"🚨 [basilisk] 🚨\n\n{message}",
                "parse_mode": "Markdown"
            }
            requests.post(self.base_url, data=payload, timeout=5)
        except Exception as e:
            self.logger.error(f"Telegram notification failed: {e}")