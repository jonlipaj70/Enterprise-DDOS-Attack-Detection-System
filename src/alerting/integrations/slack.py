"""Slack Webhook Integration — Real-time notifications."""
from __future__ import annotations
from typing import Any
from src.config.logging_config import get_logger
logger = get_logger(__name__)

class SlackIntegration:
    def __init__(self, webhook_url: str = "", channel: str = "#security-alerts"):
        self.webhook_url = webhook_url
        self.channel = channel
        self._enabled = bool(webhook_url)

    async def send_alert(self, alert: dict[str, Any]) -> bool:
        if not self._enabled:
            return False
        severity = alert.get("severity", "info")
        emoji = {"emergency": "🚨", "critical": "🔴", "warning": "🟡", "info": "🔵"}.get(severity, "⚪")
        message = {
            "channel": self.channel,
            "text": f"{emoji} *{alert.get('title', 'Alert')}*\nScore: {alert.get('anomaly_score', 0):.2f} | Type: {alert.get('attack_type', 'unknown')}",
        }
        logger.info("slack_notification_sent", alert_id=alert.get("alert_id"), channel=self.channel)
        return True
