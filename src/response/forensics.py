"""Forensic Evidence Collection."""
from __future__ import annotations
import time
from typing import Any

class ForensicsCollector:
    def __init__(self):
        self._evidence: list[dict] = []

    def collect(self, alert: dict[str, Any], packets: list[dict] = None) -> dict:
        evidence = {
            "alert_id": alert.get("alert_id"),
            "collected_at": time.time(),
            "attack_type": alert.get("attack_type"),
            "packet_sample_count": len(packets) if packets else 0,
            "source_ips": alert.get("source_ips", [])[:50],
            "timeline": {"detected_at": alert.get("timestamp")},
        }
        self._evidence.append(evidence)
        return evidence
