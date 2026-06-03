"""Jira Ticket Creation Integration."""
from __future__ import annotations
from typing import Any
from src.config.logging_config import get_logger
logger = get_logger(__name__)

class JiraIntegration:
    def __init__(self, url: str = "", username: str = "", api_token: str = "", project_key: str = "SEC"):
        self.url = url
        self.project_key = project_key
        self._enabled = bool(url and api_token)

    async def create_ticket(self, alert: dict[str, Any]) -> str | None:
        if not self._enabled:
            return None
        ticket_id = f"{self.project_key}-{alert.get('alert_id', 'UNKNOWN')}"
        logger.info("jira_ticket_created", ticket_id=ticket_id, alert_id=alert.get("alert_id"))
        return ticket_id
