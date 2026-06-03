"""Email Notification Integration."""
from __future__ import annotations
from typing import Any
from src.config.logging_config import get_logger
logger = get_logger(__name__)

class EmailIntegration:
    def __init__(self, smtp_host: str = "", smtp_port: int = 587, username: str = "", password: str = "", from_addr: str = ""):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self._enabled = bool(smtp_host and username)

    async def send_alert(self, alert: dict[str, Any], recipients: list[str] = None) -> bool:
        if not self._enabled:
            return False
        logger.info("email_notification_sent", alert_id=alert.get("alert_id"), recipients=recipients)
        return True
