"""Tests for conservative live alert gating."""

from src.detection.live_attack_gate import evaluate_live_attack


def test_suppresses_normal_https_cdn_traffic():
    features = {
        "packet_rate": 585,
        "byte_rate": 840896,
        "tcp_ratio": 1.0,
        "udp_ratio": 0.0,
        "icmp_ratio": 0.0,
        "dns_ratio": 0.0,
        "syn_ratio": 0.0,
        "syn_to_ack_ratio": 0.0,
        "ack_ratio": 1.0,
        "src_ip_entropy": 1.1,
        "unique_src_ips": 3,
        "unique_src_ports": 7,
        "avg_packet_size": 1437,
        "avg_payload_size": 1382,
        "zero_payload_ratio": 0.37,
        "large_packet_ratio": 0.60,
    }
    detection = {"is_anomaly": True, "attack_type": "slowloris", "anomaly_score": 1.0}

    decision = evaluate_live_attack(features, detection)

    assert decision.allowed is False
    assert decision.reason == "no_operational_ddos_evidence"


def test_allows_realistic_syn_flood():
    features = {
        "packet_rate": 50000,
        "byte_rate": 3200000,
        "tcp_ratio": 0.95,
        "syn_ratio": 0.85,
        "syn_to_ack_ratio": 17.0,
        "zero_payload_ratio": 0.95,
        "src_ip_entropy": 9.5,
        "unique_src_ips": 4500,
    }
    detection = {"is_anomaly": True, "attack_type": "syn_flood", "anomaly_score": 0.9}

    decision = evaluate_live_attack(features, detection)

    assert decision.allowed is True
    assert decision.reason == "syn_flood_evidence"


def test_allows_realistic_dns_amplification():
    features = {
        "packet_rate": 800,
        "byte_rate": 3_000_000,
        "dns_ratio": 0.55,
        "large_packet_ratio": 0.90,
        "avg_packet_size": 3500,
        "unique_src_ips": 50,
    }
    detection = {
        "is_anomaly": True,
        "attack_type": "dns_amplification",
        "anomaly_score": 0.9,
    }

    decision = evaluate_live_attack(features, detection)

    assert decision.allowed is True
    assert decision.reason == "dns_amplification_evidence"


def test_suppresses_low_volume_slowloris_false_positive():
    features = {
        "packet_rate": 1,
        "byte_rate": 55,
        "tcp_ratio": 1.0,
        "avg_packet_size": 55,
        "avg_payload_size": 10,
        "unique_src_ips": 1,
        "unique_src_ports": 1,
    }
    detection = {"is_anomaly": True, "attack_type": "slowloris", "anomaly_score": 1.0}

    decision = evaluate_live_attack(features, detection)

    assert decision.allowed is False
    assert decision.reason == "low_sample_volume"
