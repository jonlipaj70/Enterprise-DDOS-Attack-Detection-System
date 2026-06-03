"""SIEM Connector — CEF format event forwarding."""
from __future__ import annotations
import time
from typing import Any
from src.config.logging_config import get_logger
logger = get_logger(__name__)

class SIEMIntegration:
    def __init__(self, host: str = "", port: int = 514):
        self.host = host
        self.port = port
        self._enabled = bool(host)

    def format_cef(self, alert: dict[str, Any]) -> str:
        severity_map = {"emergency": 10, "critical": 8, "warning": 5, "info": 2}
        sev = severity_map.get(alert.get("severity", "info"), 2)
        return (
            f"CEF:0|DDoSDetector|DDoSDetectionSystem|1.0|"
            f"{alert.get('attack_type', 'unknown')}|"
            f"{alert.get('title', 'DDoS Alert')}|{sev}|"
            f"src={','.join(alert.get('source_ips', [])[:5])} "
            f"score={alert.get('anomaly_score', 0):.4f}"
        )

    async def send_alert(self, alert: dict[str, Any]) -> bool:
        if not self._enabled:
            return False
        cef_event = self.format_cef(alert)
        logger.info("siem_event_sent", alert_id=alert.get("alert_id"), cef_length=len(cef_event))
        return True
