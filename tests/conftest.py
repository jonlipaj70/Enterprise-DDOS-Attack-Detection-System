"""Shared test fixtures and configuration."""
import pytest
import time

@pytest.fixture
def sample_packets():
    """Generate sample packet data for testing."""
    return [
        {
            "timestamp": time.time(),
            "src_ip": "10.0.1.50",
            "dst_ip": "10.0.1.100",
            "src_port": 45678,
            "dst_port": 80,
            "protocol": 6,
            "packet_size": 512,
            "ttl": 64,
            "flags": 0x10,  # ACK
            "payload_size": 472,
            "fragment_offset": 0,
            "sequence_number": 12345,
            "ack_number": 67890,
            "window_size": 65535,
            "checksum": 0,
        }
        for _ in range(100)
    ]


@pytest.fixture
def attack_packets():
    """Generate SYN flood attack packet data."""
    import random
    return [
        {
            "timestamp": time.time(),
            "src_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "dst_ip": "10.0.1.100",
            "src_port": random.randint(1024, 65535),
            "dst_port": 80,
            "protocol": 6,
            "packet_size": 64,
            "ttl": random.choice([32, 64, 128]),
            "flags": 0x02,  # SYN
            "payload_size": 0,
            "fragment_offset": 0,
            "sequence_number": random.randint(0, 2**32-1),
            "ack_number": 0,
            "window_size": 1024,
            "checksum": 0,
        }
        for _ in range(1000)
    ]


@pytest.fixture
def sample_features():
    """Sample feature dictionary representing normal traffic."""
    return {
        "timestamp": time.time(),
        "window_start": time.time() - 1,
        "window_end": time.time(),
        "packet_count": 5000,
        "byte_count": 2500000,
        "packet_rate": 5000.0,
        "byte_rate": 2500000.0,
        "tcp_ratio": 0.65,
        "udp_ratio": 0.20,
        "icmp_ratio": 0.05,
        "dns_ratio": 0.10,
        "syn_ratio": 0.10,
        "syn_ack_ratio": 0.10,
        "ack_ratio": 0.40,
        "rst_ratio": 0.05,
        "fin_ratio": 0.05,
        "syn_to_ack_ratio": 0.25,
        "src_ip_entropy": 4.0,
        "dst_ip_entropy": 2.5,
        "src_port_entropy": 8.0,
        "dst_port_entropy": 3.5,
        "avg_packet_size": 500,
        "std_packet_size": 150,
        "min_packet_size": 64,
        "max_packet_size": 1460,
        "unique_src_ips": 50,
        "unique_dst_ips": 5,
        "unique_src_ports": 200,
        "unique_dst_ports": 15,
        "unique_ip_pairs": 75,
        "avg_ttl": 80,
        "ttl_diversity": 3,
        "avg_payload_size": 300,
        "zero_payload_ratio": 0.15,
        "avg_window_size": 40000,
        "small_window_ratio": 0.05,
        "fragmentation_ratio": 0.01,
        "dns_response_ratio": 0.5,
        "large_packet_ratio": 0.10,
    }


@pytest.fixture
def attack_features():
    """Sample feature dictionary representing a SYN flood attack."""
    return {
        "timestamp": time.time(),
        "window_start": time.time() - 1,
        "window_end": time.time(),
        "packet_count": 50000,
        "byte_count": 3200000,
        "packet_rate": 50000.0,
        "byte_rate": 3200000.0,
        "tcp_ratio": 0.95,
        "udp_ratio": 0.03,
        "icmp_ratio": 0.01,
        "dns_ratio": 0.01,
        "syn_ratio": 0.85,
        "syn_ack_ratio": 0.02,
        "ack_ratio": 0.05,
        "rst_ratio": 0.03,
        "fin_ratio": 0.01,
        "syn_to_ack_ratio": 17.0,
        "src_ip_entropy": 9.5,
        "dst_ip_entropy": 1.0,
        "src_port_entropy": 12.0,
        "dst_port_entropy": 1.5,
        "avg_packet_size": 64,
        "std_packet_size": 10,
        "min_packet_size": 54,
        "max_packet_size": 74,
        "unique_src_ips": 4500,
        "unique_dst_ips": 3,
        "unique_src_ports": 10000,
        "unique_dst_ports": 3,
        "unique_ip_pairs": 4500,
        "avg_ttl": 90,
        "ttl_diversity": 5,
        "avg_payload_size": 0,
        "zero_payload_ratio": 0.95,
        "avg_window_size": 2048,
        "small_window_ratio": 0.8,
        "fragmentation_ratio": 0.0,
        "dns_response_ratio": 0.0,
        "large_packet_ratio": 0.0,
    }
