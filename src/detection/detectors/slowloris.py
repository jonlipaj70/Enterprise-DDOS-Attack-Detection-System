"""
Slowloris Attack Detection
=============================
Detects slow-rate connection exhaustion attacks.
"""
from __future__ import annotations
from typing import Any

class SlowlorisDetector:
    """Detects slowloris and slow-read attacks."""

    def detect(self, features: dict[str, Any]) -> dict[str, Any]:
        score = 0.0
        indicators = []

        avg_size = features.get("avg_packet_size", 0)
        avg_payload = features.get("avg_payload_size", 0)
        unique_src = features.get("unique_src_ips", 0)
        packet_rate = features.get("packet_rate", 0)

        # Slowloris: many connections with tiny payloads
        if avg_payload < 50 and unique_src > 30 and avg_size < 100:
            score = min(1.0, unique_src / 100)
            indicators.append("slow_partial_requests")

        # Slow read: low rate but persistent connections
        if packet_rate < 500 and unique_src > 50 and avg_payload < 20:
            score = max(score, min(1.0, unique_src / 150))
            indicators.append("slow_read_attack")

        return {"score": score, "indicators": indicators}
