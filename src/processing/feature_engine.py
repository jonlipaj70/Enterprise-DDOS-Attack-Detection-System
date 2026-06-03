"""
Feature Engineering Pipeline
==============================
Extracts 20+ network traffic features from raw packet data for ML detection.
"""

from __future__ import annotations

import math
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from src.config.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class FeatureVector:
    """Computed feature vector for a time window."""

    timestamp: float
    window_start: float
    window_end: float

    # ─── Volume Features ────────────────────────────────────
    packet_count: int = 0
    byte_count: int = 0
    packet_rate: float = 0.0  # packets/sec
    byte_rate: float = 0.0   # bytes/sec

    # ─── Protocol Distribution ──────────────────────────────
    tcp_ratio: float = 0.0
    udp_ratio: float = 0.0
    icmp_ratio: float = 0.0
    dns_ratio: float = 0.0

    # ─── TCP Flag Features ──────────────────────────────────
    syn_ratio: float = 0.0
    syn_ack_ratio: float = 0.0
    ack_ratio: float = 0.0
    rst_ratio: float = 0.0
    fin_ratio: float = 0.0
    syn_to_ack_ratio: float = 0.0

    # ─── Entropy Features ───────────────────────────────────
    src_ip_entropy: float = 0.0
    dst_ip_entropy: float = 0.0
    src_port_entropy: float = 0.0
    dst_port_entropy: float = 0.0

    # ─── Packet Size Statistics ─────────────────────────────
    avg_packet_size: float = 0.0
    std_packet_size: float = 0.0
    min_packet_size: int = 0
    max_packet_size: int = 0

    # ─── Connection Features ────────────────────────────────
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    unique_src_ports: int = 0
    unique_dst_ports: int = 0
    unique_ip_pairs: int = 0

    # ─── TTL Features ───────────────────────────────────────
    avg_ttl: float = 0.0
    ttl_diversity: int = 0

    # ─── Payload Features ───────────────────────────────────
    avg_payload_size: float = 0.0
    zero_payload_ratio: float = 0.0

    # ─── Window Size Features ───────────────────────────────
    avg_window_size: float = 0.0
    small_window_ratio: float = 0.0

    # ─── Advanced Features ──────────────────────────────────
    fragmentation_ratio: float = 0.0
    dns_response_ratio: float = 0.0
    large_packet_ratio: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}

    def to_feature_array(self) -> list[float]:
        """Convert to a flat array for ML model input."""
        return [
            self.packet_rate, self.byte_rate,
            self.tcp_ratio, self.udp_ratio, self.icmp_ratio, self.dns_ratio,
            self.syn_ratio, self.syn_ack_ratio, self.ack_ratio, self.rst_ratio,
            self.fin_ratio, self.syn_to_ack_ratio,
            self.src_ip_entropy, self.dst_ip_entropy,
            self.src_port_entropy, self.dst_port_entropy,
            self.avg_packet_size, self.std_packet_size,
            float(self.unique_src_ips), float(self.unique_dst_ips),
            float(self.unique_src_ports), float(self.unique_dst_ports),
            self.avg_ttl, float(self.ttl_diversity),
            self.avg_payload_size, self.zero_payload_ratio,
            self.avg_window_size, self.small_window_ratio,
            self.fragmentation_ratio, self.large_packet_ratio,
        ]


# TCP flag constants
SYN = 0x02
ACK = 0x10
FIN = 0x01
RST = 0x04
PSH = 0x08
SYN_ACK = SYN | ACK


class FeatureEngine:
    """
    Extracts comprehensive feature vectors from raw packet batches.

    Computes 30+ features covering volume, protocol, entropy, statistical,
    and behavioral characteristics of network traffic.
    """

    def __init__(self):
        self._feature_count = 0

    def extract_features(self, packets: list[dict], window_duration: float = 1.0) -> FeatureVector:
        """
        Extract a feature vector from a batch of packet dictionaries.

        Args:
            packets: List of packet dictionaries
            window_duration: Time window in seconds

        Returns:
            FeatureVector with all computed features
        """
        if not packets:
            return FeatureVector(
                timestamp=time.time(),
                window_start=time.time(),
                window_end=time.time(),
            )

        now = time.time()
        n = len(packets)

        # Collect raw values
        src_ips = [p["src_ip"] for p in packets]
        dst_ips = [p["dst_ip"] for p in packets]
        src_ports = [p["src_port"] for p in packets]
        dst_ports = [p["dst_port"] for p in packets]
        protocols = [p["protocol"] for p in packets]
        sizes = [p["packet_size"] for p in packets]
        ttls = [p["ttl"] for p in packets]
        flags_list = [p["flags"] for p in packets]
        payloads = [p.get("payload_size", 0) for p in packets]
        windows = [p.get("window_size", 65535) for p in packets]
        fragments = [p.get("fragment_offset", 0) for p in packets]

        # Protocol counts
        proto_counts = Counter(protocols)
        tcp_count = proto_counts.get(6, 0)  # TCP
        udp_count = proto_counts.get(17, 0)  # UDP
        icmp_count = proto_counts.get(1, 0) + proto_counts.get(58, 0)  # ICMP/ICMPv6
        dns_count = sum(
            1
            for proto, src_port, dst_port in zip(protocols, src_ports, dst_ports)
            if proto == 53 or src_port == 53 or dst_port == 53
        )

        # TCP flag counts
        syn_count = sum(1 for f in flags_list if f & SYN and not (f & ACK))
        synack_count = sum(1 for f in flags_list if f == SYN_ACK)
        ack_count = sum(1 for f in flags_list if f & ACK and not (f & SYN))
        rst_count = sum(1 for f in flags_list if f & RST)
        fin_count = sum(1 for f in flags_list if f & FIN)

        # Size statistics
        total_bytes = sum(sizes)
        avg_size = total_bytes / n
        std_size = math.sqrt(sum((s - avg_size) ** 2 for s in sizes) / n) if n > 1 else 0

        # Unique counts
        unique_src = set(src_ips)
        unique_dst = set(dst_ips)
        unique_pairs = set(zip(src_ips, dst_ips))

        fv = FeatureVector(
            timestamp=now,
            window_start=now - window_duration,
            window_end=now,
            # Volume
            packet_count=n,
            byte_count=total_bytes,
            packet_rate=n / window_duration,
            byte_rate=total_bytes / window_duration,
            # Protocol distribution
            tcp_ratio=tcp_count / n,
            udp_ratio=udp_count / n,
            icmp_ratio=icmp_count / n,
            dns_ratio=dns_count / n,
            # TCP flags
            syn_ratio=syn_count / max(tcp_count, 1),
            syn_ack_ratio=synack_count / max(tcp_count, 1),
            ack_ratio=ack_count / max(tcp_count, 1),
            rst_ratio=rst_count / max(tcp_count, 1),
            fin_ratio=fin_count / max(tcp_count, 1),
            syn_to_ack_ratio=(syn_count / max(ack_count, 1)),
            # Entropy
            src_ip_entropy=self._entropy(src_ips),
            dst_ip_entropy=self._entropy(dst_ips),
            src_port_entropy=self._entropy(src_ports),
            dst_port_entropy=self._entropy(dst_ports),
            # Packet size stats
            avg_packet_size=avg_size,
            std_packet_size=std_size,
            min_packet_size=min(sizes),
            max_packet_size=max(sizes),
            # Connection features
            unique_src_ips=len(unique_src),
            unique_dst_ips=len(unique_dst),
            unique_src_ports=len(set(src_ports)),
            unique_dst_ports=len(set(dst_ports)),
            unique_ip_pairs=len(unique_pairs),
            # TTL
            avg_ttl=sum(ttls) / n,
            ttl_diversity=len(set(ttls)),
            # Payload
            avg_payload_size=sum(payloads) / n,
            zero_payload_ratio=sum(1 for p in payloads if p == 0) / n,
            # Window size
            avg_window_size=sum(windows) / n,
            small_window_ratio=sum(1 for w in windows if w < 4096) / n,
            # Advanced
            fragmentation_ratio=sum(1 for f in fragments if f > 0) / n,
            dns_response_ratio=sum(1 for p in packets if p.get("src_port") == 53) / max(dns_count, 1),
            large_packet_ratio=sum(1 for s in sizes if s > 1400) / n,
        )

        self._feature_count += 1
        return fv

    @staticmethod
    def _entropy(values: list) -> float:
        """Calculate Shannon entropy of a distribution."""
        if not values:
            return 0.0
        n = len(values)
        counts = Counter(values)
        entropy = 0.0
        for count in counts.values():
            p = count / n
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def process_batch(self, packets: list[dict]) -> list[dict]:
        """
        Process a batch for the stream processor pipeline.

        Returns a list with a single feature vector dict.
        """
        fv = self.extract_features(packets)
        return [fv.to_dict()]

    @property
    def stats(self) -> dict:
        return {"features_extracted": self._feature_count}
