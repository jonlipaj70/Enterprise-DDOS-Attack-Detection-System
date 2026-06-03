"""
Training Data Generator
=========================
Generates labeled synthetic training data from traffic profiles
for ML model training. Produces both normal and attack feature vectors
with realistic distributions.
"""

from __future__ import annotations

import math
import random
import time
from typing import Any

import numpy as np

from src.config.logging_config import get_logger

logger = get_logger(__name__)


# ─── Normal traffic feature distributions ────────────────────
# Each entry: (mean, std) for Gaussian sampling
NORMAL_PROFILES = {
    "packet_rate": (5000, 1500),
    "byte_rate": (2500000, 750000),
    "tcp_ratio": (0.65, 0.08),
    "udp_ratio": (0.20, 0.06),
    "icmp_ratio": (0.05, 0.02),
    "dns_ratio": (0.10, 0.03),
    "syn_ratio": (0.08, 0.04),
    "syn_ack_ratio": (0.08, 0.03),
    "ack_ratio": (0.40, 0.10),
    "rst_ratio": (0.05, 0.02),
    "fin_ratio": (0.05, 0.02),
    "syn_to_ack_ratio": (0.20, 0.08),
    "src_ip_entropy": (3.5, 0.8),
    "dst_ip_entropy": (2.0, 0.5),
    "src_port_entropy": (8.0, 2.0),
    "dst_port_entropy": (3.0, 1.0),
    "avg_packet_size": (500, 120),
    "std_packet_size": (150, 50),
    "unique_src_ips": (40, 12),
    "unique_dst_ips": (5, 2),
    "unique_src_ports": (180, 60),
    "unique_dst_ports": (15, 5),
    "avg_ttl": (80, 15),
    "ttl_diversity": (3, 1),
    "avg_payload_size": (300, 100),
    "zero_payload_ratio": (0.12, 0.06),
    "avg_window_size": (40000, 12000),
    "small_window_ratio": (0.04, 0.02),
    "fragmentation_ratio": (0.01, 0.005),
    "large_packet_ratio": (0.08, 0.03),
}

# ─── Attack traffic profiles ────────────────────────────────
ATTACK_PROFILES = {
    "syn_flood": {
        "packet_rate": (35000, 10000),
        "byte_rate": (2240000, 640000),  # Small packets, high rate
        "tcp_ratio": (0.95, 0.03),
        "udp_ratio": (0.03, 0.02),
        "icmp_ratio": (0.01, 0.01),
        "dns_ratio": (0.01, 0.01),
        "syn_ratio": (0.70, 0.12),
        "syn_ack_ratio": (0.02, 0.01),
        "ack_ratio": (0.05, 0.03),
        "rst_ratio": (0.08, 0.04),
        "fin_ratio": (0.02, 0.01),
        "syn_to_ack_ratio": (14.0, 5.0),
        "src_ip_entropy": (8.0, 1.5),
        "dst_ip_entropy": (1.5, 0.5),
        "src_port_entropy": (12.0, 2.0),
        "dst_port_entropy": (1.5, 0.5),
        "avg_packet_size": (64, 10),
        "std_packet_size": (8, 4),
        "unique_src_ips": (500, 200),
        "unique_dst_ips": (3, 1),
        "unique_src_ports": (800, 200),
        "unique_dst_ports": (3, 1),
        "avg_ttl": (80, 30),
        "ttl_diversity": (6, 2),
        "avg_payload_size": (0, 2),
        "zero_payload_ratio": (0.92, 0.05),
        "avg_window_size": (2048, 1000),
        "small_window_ratio": (0.85, 0.10),
        "fragmentation_ratio": (0.01, 0.005),
        "large_packet_ratio": (0.01, 0.005),
    },
    "udp_flood": {
        "packet_rate": (60000, 15000),
        "byte_rate": (84000000, 20000000),
        "tcp_ratio": (0.05, 0.03),
        "udp_ratio": (0.90, 0.05),
        "icmp_ratio": (0.03, 0.02),
        "dns_ratio": (0.02, 0.01),
        "syn_ratio": (0.02, 0.01),
        "syn_ack_ratio": (0.01, 0.005),
        "ack_ratio": (0.02, 0.01),
        "rst_ratio": (0.01, 0.005),
        "fin_ratio": (0.01, 0.005),
        "syn_to_ack_ratio": (2.0, 1.0),
        "src_ip_entropy": (7.0, 1.5),
        "dst_ip_entropy": (1.5, 0.5),
        "src_port_entropy": (10.0, 2.0),
        "dst_port_entropy": (8.0, 2.0),
        "avg_packet_size": (1400, 80),
        "std_packet_size": (50, 20),
        "unique_src_ips": (300, 100),
        "unique_dst_ips": (3, 1),
        "unique_src_ports": (600, 150),
        "unique_dst_ports": (500, 100),
        "avg_ttl": (96, 30),
        "ttl_diversity": (4, 2),
        "avg_payload_size": (1360, 60),
        "zero_payload_ratio": (0.02, 0.01),
        "avg_window_size": (32768, 8000),
        "small_window_ratio": (0.05, 0.02),
        "fragmentation_ratio": (0.02, 0.01),
        "large_packet_ratio": (0.85, 0.08),
    },
    "dns_amplification": {
        "packet_rate": (80000, 20000),
        "byte_rate": (280000000, 60000000),
        "tcp_ratio": (0.03, 0.02),
        "udp_ratio": (0.60, 0.10),
        "icmp_ratio": (0.02, 0.01),
        "dns_ratio": (0.35, 0.10),
        "syn_ratio": (0.01, 0.005),
        "syn_ack_ratio": (0.01, 0.005),
        "ack_ratio": (0.01, 0.005),
        "rst_ratio": (0.01, 0.005),
        "fin_ratio": (0.01, 0.005),
        "syn_to_ack_ratio": (1.0, 0.5),
        "src_ip_entropy": (5.0, 1.5),
        "dst_ip_entropy": (1.0, 0.3),
        "src_port_entropy": (3.0, 1.0),
        "dst_port_entropy": (6.0, 2.0),
        "avg_packet_size": (3500, 400),
        "std_packet_size": (300, 100),
        "unique_src_ips": (50, 20),
        "unique_dst_ips": (2, 1),
        "unique_src_ports": (50, 20),
        "unique_dst_ports": (400, 100),
        "avg_ttl": (100, 40),
        "ttl_diversity": (5, 2),
        "avg_payload_size": (3400, 350),
        "zero_payload_ratio": (0.01, 0.005),
        "avg_window_size": (32768, 8000),
        "small_window_ratio": (0.02, 0.01),
        "fragmentation_ratio": (0.05, 0.02),
        "large_packet_ratio": (0.90, 0.05),
    },
    "http_flood": {
        "packet_rate": (25000, 8000),
        "byte_rate": (12500000, 4000000),
        "tcp_ratio": (0.92, 0.04),
        "udp_ratio": (0.04, 0.02),
        "icmp_ratio": (0.02, 0.01),
        "dns_ratio": (0.02, 0.01),
        "syn_ratio": (0.15, 0.05),
        "syn_ack_ratio": (0.12, 0.04),
        "ack_ratio": (0.55, 0.10),
        "rst_ratio": (0.03, 0.02),
        "fin_ratio": (0.08, 0.03),
        "syn_to_ack_ratio": (1.25, 0.3),
        "src_ip_entropy": (7.5, 1.0),
        "dst_ip_entropy": (1.5, 0.5),
        "src_port_entropy": (12.0, 2.0),
        "dst_port_entropy": (2.0, 0.5),
        "avg_packet_size": (450, 150),
        "std_packet_size": (200, 80),
        "unique_src_ips": (400, 150),
        "unique_dst_ips": (3, 1),
        "unique_src_ports": (700, 200),
        "unique_dst_ports": (5, 2),
        "avg_ttl": (70, 15),
        "ttl_diversity": (4, 1.5),
        "avg_payload_size": (350, 150),
        "zero_payload_ratio": (0.05, 0.03),
        "avg_window_size": (65535, 5000),
        "small_window_ratio": (0.01, 0.005),
        "fragmentation_ratio": (0.005, 0.003),
        "large_packet_ratio": (0.05, 0.02),
    },
    "slowloris": {
        "packet_rate": (400, 150),
        "byte_rate": (20000, 8000),
        "tcp_ratio": (0.95, 0.03),
        "udp_ratio": (0.02, 0.01),
        "icmp_ratio": (0.01, 0.005),
        "dns_ratio": (0.02, 0.01),
        "syn_ratio": (0.05, 0.02),
        "syn_ack_ratio": (0.04, 0.02),
        "ack_ratio": (0.30, 0.10),
        "rst_ratio": (0.02, 0.01),
        "fin_ratio": (0.01, 0.005),
        "syn_to_ack_ratio": (1.25, 0.5),
        "src_ip_entropy": (5.5, 1.0),
        "dst_ip_entropy": (1.0, 0.3),
        "src_port_entropy": (8.0, 2.0),
        "dst_port_entropy": (1.2, 0.3),
        "avg_packet_size": (50, 10),
        "std_packet_size": (10, 5),
        "unique_src_ips": (80, 30),
        "unique_dst_ips": (2, 1),
        "unique_src_ports": (200, 80),
        "unique_dst_ports": (2, 1),
        "avg_ttl": (64, 5),
        "ttl_diversity": (2, 1),
        "avg_payload_size": (10, 5),
        "zero_payload_ratio": (0.15, 0.05),
        "avg_window_size": (65535, 3000),
        "small_window_ratio": (0.01, 0.005),
        "fragmentation_ratio": (0.005, 0.003),
        "large_packet_ratio": (0.01, 0.005),
    },
    "icmp_flood": {
        "packet_rate": (40000, 12000),
        "byte_rate": (40000000, 12000000),
        "tcp_ratio": (0.05, 0.03),
        "udp_ratio": (0.05, 0.03),
        "icmp_ratio": (0.85, 0.08),
        "dns_ratio": (0.02, 0.01),
        "syn_ratio": (0.01, 0.005),
        "syn_ack_ratio": (0.01, 0.005),
        "ack_ratio": (0.02, 0.01),
        "rst_ratio": (0.01, 0.005),
        "fin_ratio": (0.01, 0.005),
        "syn_to_ack_ratio": (1.0, 0.5),
        "src_ip_entropy": (7.0, 1.5),
        "dst_ip_entropy": (1.0, 0.3),
        "src_port_entropy": (0.5, 0.3),
        "dst_port_entropy": (0.5, 0.3),
        "avg_packet_size": (800, 400),
        "std_packet_size": (400, 200),
        "unique_src_ips": (300, 100),
        "unique_dst_ips": (3, 1),
        "unique_src_ports": (1, 0),
        "unique_dst_ports": (1, 0),
        "avg_ttl": (100, 50),
        "ttl_diversity": (5, 2),
        "avg_payload_size": (700, 350),
        "zero_payload_ratio": (0.02, 0.01),
        "avg_window_size": (0, 0),
        "small_window_ratio": (0.0, 0.0),
        "fragmentation_ratio": (0.03, 0.01),
        "large_packet_ratio": (0.40, 0.15),
    },
}

FEATURE_ORDER = [
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


def _sample_profile(profile: dict[str, tuple[float, float]]) -> list[float]:
    """Sample a single feature vector from a profile."""
    result = []
    for feat in FEATURE_ORDER:
        mean, std = profile.get(feat, NORMAL_PROFILES.get(feat, (0, 0)))
        value = random.gauss(mean, std)
        # Clip ratios to [0, 1]
        if "ratio" in feat and feat != "syn_to_ack_ratio":
            value = max(0.0, min(1.0, value))
        elif feat in ("packet_rate", "byte_rate", "avg_packet_size",
                       "std_packet_size", "unique_src_ips", "unique_dst_ips",
                       "unique_src_ports", "unique_dst_ports", "avg_ttl",
                       "ttl_diversity", "avg_payload_size", "avg_window_size"):
            value = max(0.0, value)
        result.append(value)
    return result


def generate_training_data(
    n_normal: int = 5000,
    n_attack_per_type: int = 800,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Generate labeled training data.

    Returns:
        X: Feature matrix (n_samples, 30)
        y: Binary labels (0=normal, 1=attack)
        y_type: Attack type indices (0=normal, 1..6=attack types)
    """
    random.seed(seed)
    np.random.seed(seed)

    X_list = []
    y_list = []
    y_type_list = []

    # Generate normal traffic with time-of-day variations
    for i in range(n_normal):
        # Simulate business hours variation
        hour_factor = 0.5 + 0.5 * math.sin((i / n_normal) * 2 * math.pi)
        sample = _sample_profile(NORMAL_PROFILES)
        # Scale volume features by hour factor
        sample[0] *= (0.3 + 0.7 * hour_factor)  # packet_rate
        sample[1] *= (0.3 + 0.7 * hour_factor)  # byte_rate
        X_list.append(sample)
        y_list.append(0)
        y_type_list.append(0)

    # Generate attack traffic
    attack_names = list(ATTACK_PROFILES.keys())
    for idx, (attack_name, profile) in enumerate(ATTACK_PROFILES.items(), 1):
        for _ in range(n_attack_per_type):
            # Mix attack with some normal traffic (realistic blending)
            blend_factor = random.uniform(0.3, 1.0)
            attack_sample = _sample_profile(profile)
            normal_sample = _sample_profile(NORMAL_PROFILES)

            blended = []
            for a, n in zip(attack_sample, normal_sample):
                blended.append(blend_factor * a + (1 - blend_factor) * n)

            X_list.append(blended)
            y_list.append(1)
            y_type_list.append(idx)

    X = np.array(X_list, dtype=np.float64)
    y = np.array(y_list, dtype=np.int32)
    y_type = np.array(y_type_list, dtype=np.int32)

    # Shuffle
    indices = np.random.permutation(len(X))
    X = X[indices]
    y = y[indices]
    y_type = y_type[indices]

    logger.info(
        "training_data_generated",
        n_normal=n_normal,
        n_attack=n_attack_per_type * len(ATTACK_PROFILES),
        total=len(X),
        n_features=X.shape[1],
        attack_types=attack_names,
    )

    return X, y, y_type


def get_attack_type_name(idx: int) -> str:
    """Map attack type index to name."""
    names = ["normal"] + list(ATTACK_PROFILES.keys())
    return names[idx] if idx < len(names) else "unknown"
