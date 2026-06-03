"""
Geolocation-Based Anomaly Detection
======================================
Detects geographic anomalies in traffic patterns.
"""
from __future__ import annotations
from typing import Any

class GeolocationDetector:
    """Detects geographic anomalies indicating potential attacks."""

    def detect(self, features: dict[str, Any]) -> dict[str, Any]:
        score = 0.0
        indicators = []

        src_entropy = features.get("src_ip_entropy", 0)
        unique_src = features.get("unique_src_ips", 0)

        # High source diversity from many geographic regions
        if src_entropy > 7.0 and unique_src > 200:
            score = min(1.0, src_entropy / 10.0)
            indicators.append("geo_distributed_attack")

        return {"score": score, "indicators": indicators}
