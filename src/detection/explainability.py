"""
Model Explainability
======================
SHAP-based feature importance and detection explainability.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


FEATURE_NAMES = [
    "packet_rate", "byte_rate",
    "tcp_ratio", "udp_ratio", "icmp_ratio", "dns_ratio",
    "syn_ratio", "syn_ack_ratio", "ack_ratio", "rst_ratio",
    "fin_ratio", "syn_to_ack_ratio",
    "src_ip_entropy", "dst_ip_entropy",
    "src_port_entropy", "dst_port_entropy",
    "avg_packet_size", "std_packet_size",
    "unique_src_ips", "unique_dst_ips",
    "unique_src_ports", "unique_dst_ports",
    "avg_ttl", "ttl_diversity",
    "avg_payload_size", "zero_payload_ratio",
    "avg_window_size", "small_window_ratio",
    "fragmentation_ratio", "large_packet_ratio",
]

FEATURE_DESCRIPTIONS = {
    "packet_rate": "Packets per second",
    "byte_rate": "Bytes per second",
    "tcp_ratio": "Proportion of TCP traffic",
    "udp_ratio": "Proportion of UDP traffic",
    "icmp_ratio": "Proportion of ICMP traffic",
    "dns_ratio": "Proportion of DNS traffic",
    "syn_ratio": "Ratio of SYN packets",
    "syn_ack_ratio": "Ratio of SYN-ACK packets",
    "ack_ratio": "Ratio of ACK packets",
    "rst_ratio": "Ratio of RST packets",
    "fin_ratio": "Ratio of FIN packets",
    "syn_to_ack_ratio": "SYN to ACK ratio (handshake completeness)",
    "src_ip_entropy": "Source IP address diversity",
    "dst_ip_entropy": "Destination IP address diversity",
    "src_port_entropy": "Source port diversity",
    "dst_port_entropy": "Destination port diversity",
    "avg_packet_size": "Average packet size in bytes",
    "std_packet_size": "Standard deviation of packet sizes",
    "unique_src_ips": "Number of unique source IPs",
    "unique_dst_ips": "Number of unique destination IPs",
    "unique_src_ports": "Number of unique source ports",
    "unique_dst_ports": "Number of unique destination ports",
    "avg_ttl": "Average Time-To-Live value",
    "ttl_diversity": "Number of distinct TTL values",
    "avg_payload_size": "Average payload size",
    "zero_payload_ratio": "Proportion of empty payloads",
    "avg_window_size": "Average TCP window size",
    "small_window_ratio": "Proportion of small TCP windows",
    "fragmentation_ratio": "Proportion of fragmented packets",
    "large_packet_ratio": "Proportion of large packets (>1400 bytes)",
}


@dataclass
class FeatureExplanation:
    """Explanation for a single feature's contribution."""
    name: str
    description: str
    value: float
    baseline_value: float
    contribution: float  # Positive = increases anomaly score
    direction: str  # "high" or "low"


class DetectionExplainer:
    """
    Provides human-readable explanations for detection decisions.

    Uses simplified SHAP-like analysis to explain which features
    contributed most to the anomaly score.
    """

    def __init__(self):
        # Baseline (normal traffic) values
        self._baselines = {
            "packet_rate": 5000, "byte_rate": 2500000,
            "tcp_ratio": 0.65, "udp_ratio": 0.20, "icmp_ratio": 0.05, "dns_ratio": 0.10,
            "syn_ratio": 0.10, "syn_ack_ratio": 0.10, "ack_ratio": 0.40, "rst_ratio": 0.05,
            "fin_ratio": 0.05, "syn_to_ack_ratio": 0.25,
            "src_ip_entropy": 4.0, "dst_ip_entropy": 2.5,
            "src_port_entropy": 8.0, "dst_port_entropy": 3.5,
            "avg_packet_size": 500, "std_packet_size": 150,
            "unique_src_ips": 50, "unique_dst_ips": 5,
            "unique_src_ports": 200, "unique_dst_ports": 15,
            "avg_ttl": 80, "ttl_diversity": 3,
            "avg_payload_size": 300, "zero_payload_ratio": 0.15,
            "avg_window_size": 40000, "small_window_ratio": 0.05,
            "fragmentation_ratio": 0.01, "large_packet_ratio": 0.10,
        }

    def explain(self, features: dict[str, Any]) -> list[FeatureExplanation]:
        """
        Generate explanations for a detection result.

        Args:
            features: Feature dictionary

        Returns:
            List of feature explanations sorted by contribution
        """
        explanations = []

        for name in FEATURE_NAMES:
            value = features.get(name, 0)
            baseline = self._baselines.get(name, 0)

            if baseline == 0:
                continue

            deviation = (value - baseline) / max(abs(baseline), 1e-10)
            contribution = abs(deviation)
            direction = "high" if value > baseline else "low"

            explanations.append(FeatureExplanation(
                name=name,
                description=FEATURE_DESCRIPTIONS.get(name, name),
                value=value,
                baseline_value=baseline,
                contribution=contribution,
                direction=direction,
            ))

        explanations.sort(key=lambda x: x.contribution, reverse=True)
        return explanations

    def generate_summary(self, features: dict[str, Any], attack_type: str) -> str:
        """Generate a human-readable detection summary."""
        explanations = self.explain(features)
        top_3 = explanations[:3]

        lines = [f"Attack Type: {attack_type.replace('_', ' ').title()}"]
        lines.append("Key Contributing Factors:")

        for exp in top_3:
            change_pct = abs(exp.value - exp.baseline_value) / max(abs(exp.baseline_value), 1e-10) * 100
            lines.append(
                f"  • {exp.description}: {exp.value:.2f} "
                f"({exp.direction}, {change_pct:.0f}% from baseline {exp.baseline_value:.2f})"
            )

        return "\n".join(lines)
