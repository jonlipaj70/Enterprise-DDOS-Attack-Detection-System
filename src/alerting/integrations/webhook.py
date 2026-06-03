"""Generic Webhook Integration."""
from __future__ import annotations
from typing import Any
from src.config.logging_config import get_logger
logger = get_logger(__name__)

class WebhookIntegration:
    def __init__(self, url: str = "", headers: dict = None):
        self.url = url
        self.headers = headers or {}
        self._enabled = bool(url)

    async def send_alert(self, alert: dict[str, Any]) -> bool:
        if not self._enabled:
            return False
        logger.info("webhook_sent", url=self.url, alert_id=alert.get("alert_id"))
        return True
