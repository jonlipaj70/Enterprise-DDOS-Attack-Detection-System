"""
Protocol-Level Attack Detection
==================================
Detects TCP state abuse, fragment attacks, and protocol anomalies.
"""
from __future__ import annotations
from typing import Any

class ProtocolDetector:
    """Detects protocol-level DDoS attacks."""

    def detect(self, features: dict[str, Any]) -> dict[str, Any]:
        score = 0.0
        indicators = []

        syn_ratio = features.get("syn_ratio", 0)
        syn_to_ack = features.get("syn_to_ack_ratio", 0)
        rst_ratio = features.get("rst_ratio", 0)
        frag_ratio = features.get("fragmentation_ratio", 0)

        if syn_to_ack > 3.0:
            score = max(score, min(1.0, syn_to_ack / 10.0))
            indicators.append("incomplete_handshakes")

        if rst_ratio > 0.3:
            score = max(score, min(1.0, rst_ratio / 0.5))
            indicators.append("high_rst_ratio")

        if frag_ratio > 0.1:
            score = max(score, min(1.0, frag_ratio / 0.3))
            indicators.append("fragment_attack")

        return {"score": score, "indicators": indicators}
