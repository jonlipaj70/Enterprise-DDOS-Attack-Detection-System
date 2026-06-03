"""
Application-Layer Attack Detection
=====================================
Detects HTTP flood, API abuse, and application-layer attacks.
"""
from __future__ import annotations
from typing import Any

class ApplicationDetector:
    """Detects application-layer DDoS attacks."""

    def detect(self, features: dict[str, Any]) -> dict[str, Any]:
        score = 0.0
        indicators = []

        tcp_ratio = features.get("tcp_ratio", 0)
        packet_rate = features.get("packet_rate", 0)
        unique_src = features.get("unique_src_ips", 0)
        avg_size = features.get("avg_packet_size", 0)

        # HTTP flood: many legitimate-looking requests from many sources
        if tcp_ratio > 0.8 and unique_src > 100 and packet_rate > 5000:
            score = min(1.0, (unique_src / 500) * (packet_rate / 20000))
            indicators.append("http_flood")

        # Small payload flood (GET flood)
        if 200 < avg_size < 800 and packet_rate > 10000:
            score = max(score, min(1.0, packet_rate / 30000))
            indicators.append("get_flood")

        return {"score": score, "indicators": indicators}
