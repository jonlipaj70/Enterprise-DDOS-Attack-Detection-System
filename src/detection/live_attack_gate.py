"""
Conservative live-traffic gate for production alerting.

The ML ensemble is trained on synthetic attack profiles, so live laptop traffic
can trigger model anomalies that are not operational DDoS signals. This gate is
used only for live capture alert/display decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AttackGateDecision:
    """Decision for whether a live anomaly should be shown as a real attack."""

    allowed: bool
    reason: str
    evidence: list[str] = field(default_factory=list)


def evaluate_live_attack(features: dict[str, Any], detection: dict[str, Any]) -> AttackGateDecision:
    """
    Require concrete DDoS evidence before surfacing a live anomaly.

    This intentionally suppresses low-volume HTTPS/CDN patterns that look odd to
    the synthetic model but do not resemble a real DDoS attempt.
    """
    if not detection.get("is_anomaly", False):
        return AttackGateDecision(False, "model_not_anomalous")

    attack_type = str(detection.get("attack_type", "unknown"))
    packet_rate = _num(features, "packet_rate")
    byte_rate = _num(features, "byte_rate")
    unique_src = _num(features, "unique_src_ips")
    unique_src_ports = _num(features, "unique_src_ports")
    src_entropy = _num(features, "src_ip_entropy")
    tcp_ratio = _num(features, "tcp_ratio")
    udp_ratio = _num(features, "udp_ratio")
    icmp_ratio = _num(features, "icmp_ratio")
    dns_ratio = _num(features, "dns_ratio")
    syn_ratio = _num(features, "syn_ratio")
    syn_to_ack = _num(features, "syn_to_ack_ratio")
    ack_ratio = _num(features, "ack_ratio")
    avg_size = _num(features, "avg_packet_size")
    avg_payload = _num(features, "avg_payload_size")
    zero_payload = _num(features, "zero_payload_ratio")
    large_packet = _num(features, "large_packet_ratio")

    # Very small samples are useful for model scoring but not enough for an alert.
    if packet_rate < 50 and byte_rate < 1_000_000:
        return AttackGateDecision(False, "low_sample_volume")

    checks = [
        _syn_flood(packet_rate, unique_src, src_entropy, syn_ratio, syn_to_ack, zero_payload),
        _udp_flood(packet_rate, byte_rate, unique_src, src_entropy, udp_ratio, large_packet),
        _dns_amplification(packet_rate, byte_rate, unique_src, dns_ratio, large_packet, avg_size),
        _icmp_flood(packet_rate, unique_src, src_entropy, icmp_ratio),
        _http_flood(packet_rate, byte_rate, unique_src, src_entropy, tcp_ratio, ack_ratio),
        _slowloris(packet_rate, unique_src, unique_src_ports, tcp_ratio, avg_size, avg_payload),
    ]
    for allowed_type, evidence in checks:
        if evidence and (attack_type in {allowed_type, "unknown"} or attack_type == allowed_type):
            return AttackGateDecision(True, f"{allowed_type}_evidence", evidence)

    # Unknown high-volume events still need multi-source or very strong bandwidth evidence.
    if (packet_rate >= 8_000 or byte_rate >= 25_000_000) and (unique_src >= 25 or src_entropy >= 4.5):
        return AttackGateDecision(
            True,
            "high_volume_multisource_evidence",
            [
                f"packet_rate={packet_rate:.0f}",
                f"byte_rate={byte_rate:.0f}",
                f"unique_src_ips={unique_src:.0f}",
                f"src_ip_entropy={src_entropy:.2f}",
            ],
        )

    return AttackGateDecision(False, "no_operational_ddos_evidence")


def _syn_flood(
    packet_rate: float,
    unique_src: float,
    src_entropy: float,
    syn_ratio: float,
    syn_to_ack: float,
    zero_payload: float,
) -> tuple[str, list[str]]:
    if (
        packet_rate >= 1_000
        and syn_ratio >= 0.35
        and syn_to_ack >= 3.0
        and zero_payload >= 0.30
        and (unique_src >= 20 or src_entropy >= 4.0)
    ):
        return (
            "syn_flood",
            [
                f"packet_rate={packet_rate:.0f}",
                f"syn_ratio={syn_ratio:.2f}",
                f"syn_to_ack_ratio={syn_to_ack:.2f}",
                f"unique_src_ips={unique_src:.0f}",
            ],
        )
    return "syn_flood", []


def _udp_flood(
    packet_rate: float,
    byte_rate: float,
    unique_src: float,
    src_entropy: float,
    udp_ratio: float,
    large_packet: float,
) -> tuple[str, list[str]]:
    if (
        udp_ratio >= 0.60
        and (packet_rate >= 2_000 or byte_rate >= 10_000_000)
        and (large_packet >= 0.30 or packet_rate >= 5_000)
        and (unique_src >= 20 or src_entropy >= 4.0)
    ):
        return (
            "udp_flood",
            [
                f"packet_rate={packet_rate:.0f}",
                f"byte_rate={byte_rate:.0f}",
                f"udp_ratio={udp_ratio:.2f}",
                f"unique_src_ips={unique_src:.0f}",
            ],
        )
    return "udp_flood", []


def _dns_amplification(
    packet_rate: float,
    byte_rate: float,
    unique_src: float,
    dns_ratio: float,
    large_packet: float,
    avg_size: float,
) -> tuple[str, list[str]]:
    if (
        dns_ratio >= 0.20
        and large_packet >= 0.30
        and avg_size >= 800
        and (packet_rate >= 300 or byte_rate >= 1_000_000)
        and unique_src >= 10
    ):
        return (
            "dns_amplification",
            [
                f"dns_ratio={dns_ratio:.2f}",
                f"large_packet_ratio={large_packet:.2f}",
                f"avg_packet_size={avg_size:.0f}",
                f"unique_src_ips={unique_src:.0f}",
            ],
        )
    return "dns_amplification", []


def _icmp_flood(
    packet_rate: float,
    unique_src: float,
    src_entropy: float,
    icmp_ratio: float,
) -> tuple[str, list[str]]:
    if icmp_ratio >= 0.30 and packet_rate >= 1_000 and (unique_src >= 20 or src_entropy >= 4.0):
        return (
            "icmp_flood",
            [
                f"packet_rate={packet_rate:.0f}",
                f"icmp_ratio={icmp_ratio:.2f}",
                f"unique_src_ips={unique_src:.0f}",
            ],
        )
    return "icmp_flood", []


def _http_flood(
    packet_rate: float,
    byte_rate: float,
    unique_src: float,
    src_entropy: float,
    tcp_ratio: float,
    ack_ratio: float,
) -> tuple[str, list[str]]:
    if (
        tcp_ratio >= 0.70
        and ack_ratio >= 0.50
        and (packet_rate >= 2_000 or byte_rate >= 8_000_000)
        and unique_src >= 50
        and src_entropy >= 4.0
    ):
        return (
            "http_flood",
            [
                f"packet_rate={packet_rate:.0f}",
                f"tcp_ratio={tcp_ratio:.2f}",
                f"ack_ratio={ack_ratio:.2f}",
                f"unique_src_ips={unique_src:.0f}",
            ],
        )
    return "http_flood", []


def _slowloris(
    packet_rate: float,
    unique_src: float,
    unique_src_ports: float,
    tcp_ratio: float,
    avg_size: float,
    avg_payload: float,
) -> tuple[str, list[str]]:
    if (
        50 <= packet_rate <= 2_000
        and tcp_ratio >= 0.70
        and avg_size <= 120
        and avg_payload <= 40
        and (unique_src >= 20 or unique_src_ports >= 100)
    ):
        return (
            "slowloris",
            [
                f"packet_rate={packet_rate:.0f}",
                f"avg_packet_size={avg_size:.0f}",
                f"avg_payload_size={avg_payload:.0f}",
                f"unique_src_ports={unique_src_ports:.0f}",
            ],
        )
    return "slowloris", []


def _num(values: dict[str, Any], key: str) -> float:
    try:
        return float(values.get(key, 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0
