"""
Multi-Tier Alert Classifier
==============================
Classifies alerts into severity tiers based on detection metrics.
"""
from __future__ import annotations
from typing import Any

class AlertClassifier:
    """Classifies detection results into severity tiers."""

    def __init__(self):
        self._thresholds = {
            "emergency": {"score": 0.9, "packet_rate": 50000},
            "critical": {"score": 0.75, "packet_rate": 30000},
            "warning": {"score": 0.6, "packet_rate": 15000},
            "info": {"score": 0.0, "packet_rate": 0},
        }

    def classify(self, detection_result: dict[str, Any]) -> str:
        score = detection_result.get("anomaly_score", 0)
        pps = detection_result.get("details", {}).get("packet_rate", 0)

        for severity in ["emergency", "critical", "warning"]:
            t = self._thresholds[severity]
            if score >= t["score"] or pps >= t["packet_rate"]:
                return severity
        return "info"
