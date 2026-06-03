"""
Amplification Attack Detection
=================================
Detects DNS, NTP, and SSDP amplification attacks.
"""
from __future__ import annotations
from typing import Any

class AmplificationDetector:
    """Detects amplification-based DDoS attacks."""

    def detect(self, features: dict[str, Any]) -> dict[str, Any]:
        score = 0.0
        indicators = []
        sub_type = "none"

        dns_ratio = features.get("dns_ratio", 0)
        udp_ratio = features.get("udp_ratio", 0)
        avg_size = features.get("avg_packet_size", 0)
        large_pkt = features.get("large_packet_ratio", 0)
        dns_resp = features.get("dns_response_ratio", 0)

        # DNS amplification: large DNS response packets
        if dns_ratio > 0.2 and avg_size > 1000:
            score = min(1.0, (dns_ratio * avg_size) / 2000)
            sub_type = "dns_amplification"
            indicators.append("large_dns_responses")

        # NTP amplification: large UDP packets from port 123
        if udp_ratio > 0.4 and large_pkt > 0.3:
            amp_score = min(1.0, udp_ratio * large_pkt * 3)
            if amp_score > score:
                score = amp_score
                sub_type = "ntp_amplification"
                indicators.append("large_ntp_responses")

        return {"score": score, "sub_type": sub_type, "indicators": indicators}
