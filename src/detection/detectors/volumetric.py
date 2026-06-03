"""
Volumetric Flood Detection
=============================
Detects SYN flood, UDP flood, and ICMP flood attacks based on volume metrics.
"""
from __future__ import annotations
from typing import Any

class VolumetricDetector:
    """Detects volumetric DDoS attacks based on traffic volume anomalies."""

    def __init__(self, pps_threshold: float = 20000, bps_threshold: float = 10_000_000):
        self.pps_threshold = pps_threshold
        self.bps_threshold = bps_threshold

    def detect(self, features: dict[str, Any]) -> dict[str, Any]:
        packet_rate = features.get("packet_rate", 0)
        byte_rate = features.get("byte_rate", 0)
        score = 0.0
        attack_sub_type = "none"

        if packet_rate > self.pps_threshold:
            score = min(1.0, packet_rate / (self.pps_threshold * 3))
            if features.get("syn_ratio", 0) > 0.4:
                attack_sub_type = "syn_flood"
            elif features.get("udp_ratio", 0) > 0.5:
                attack_sub_type = "udp_flood"
            elif features.get("icmp_ratio", 0) > 0.3:
                attack_sub_type = "icmp_flood"
            else:
                attack_sub_type = "volumetric_generic"

        if byte_rate > self.bps_threshold:
            bps_score = min(1.0, byte_rate / (self.bps_threshold * 3))
            score = max(score, bps_score)

        return {"score": score, "sub_type": attack_sub_type, "packet_rate": packet_rate, "byte_rate": byte_rate}
