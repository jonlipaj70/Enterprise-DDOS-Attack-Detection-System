"""
Zero-Day Behavioral Detection
================================
Detects previously unknown attacks via behavioral deviation analysis.
"""
from __future__ import annotations
from typing import Any

class ZeroDayDetector:
    """Detects potential zero-day attacks through behavioral anomalies."""

    def __init__(self):
        self._baseline_entropy = {"src_ip": 4.0, "dst_ip": 2.5, "src_port": 8.0, "dst_port": 3.5}

    def detect(self, features: dict[str, Any]) -> dict[str, Any]:
        score = 0.0
        indicators = []
        anomalous_features = []

        # Check for unusual combinations of features
        checks = [
            ("src_ip_entropy", self._baseline_entropy["src_ip"], 2.0),
            ("dst_ip_entropy", self._baseline_entropy["dst_ip"], 2.0),
            ("src_port_entropy", self._baseline_entropy["src_port"], 3.0),
            ("dst_port_entropy", self._baseline_entropy["dst_port"], 2.0),
        ]

        deviations = 0
        for feat_name, baseline, threshold in checks:
            value = features.get(feat_name, baseline)
            if abs(value - baseline) > threshold:
                deviations += 1
                anomalous_features.append(feat_name)

        # Multiple simultaneous deviations suggest unknown attack
        if deviations >= 2:
            score = min(1.0, deviations / 4.0)
            indicators.append("multi_feature_deviation")

        # Check for unusual protocol mix
        protocols = [
            features.get("tcp_ratio", 0),
            features.get("udp_ratio", 0),
            features.get("icmp_ratio", 0),
            features.get("dns_ratio", 0),
        ]
        max_proto = max(protocols) if protocols else 0
        if max_proto > 0.85:
            score = max(score, 0.3)
            indicators.append("protocol_concentration")

        return {
            "score": score,
            "indicators": indicators,
            "anomalous_features": anomalous_features,
        }
