"""
Realistic Traffic Simulator
=============================
Generates normal and attack traffic patterns for testing and demonstration.
Supports: SYN flood, UDP flood, HTTP flood, DNS amplification, Slowloris,
ICMP flood, NTP amplification, and mixed multi-vector attacks.
"""

from __future__ import annotations

import asyncio
import math
import random
import time
from dataclasses import dataclass
from enum import Enum
from typing import AsyncIterator, Optional

from src.ingestion.packet_capture import (
    ACK,
    FIN,
    PSH,
    RST,
    SYN,
    SYN_ACK,
    Protocol,
    RawPacket,
)
from src.config.logging_config import get_logger

logger = get_logger(__name__)


class AttackType(str, Enum):
    """DDoS attack types."""
    NONE = "none"
    SYN_FLOOD = "syn_flood"
    UDP_FLOOD = "udp_flood"
    HTTP_FLOOD = "http_flood"
    DNS_AMPLIFICATION = "dns_amplification"
    SLOWLORIS = "slowloris"
    ICMP_FLOOD = "icmp_flood"
    NTP_AMPLIFICATION = "ntp_amplification"
    MULTI_VECTOR = "multi_vector"


@dataclass
class TrafficProfile:
    """Describes a traffic generation profile."""
    name: str
    normal_pps: int  # Normal packets per second
    attack_pps: int  # Attack packets per second during attack
    attack_type: AttackType
    attack_duration: float  # Duration in seconds
    ramp_up_time: float  # Time to reach full attack rate
    attack_sources: int  # Number of attacking IPs


# Predefined attack profiles
ATTACK_PROFILES = {
    AttackType.SYN_FLOOD: TrafficProfile(
        name="SYN Flood",
        normal_pps=5000,
        attack_pps=50000,
        attack_type=AttackType.SYN_FLOOD,
        attack_duration=120,
        ramp_up_time=10,
        attack_sources=5000,
    ),
    AttackType.UDP_FLOOD: TrafficProfile(
        name="UDP Flood",
        normal_pps=5000,
        attack_pps=80000,
        attack_type=AttackType.UDP_FLOOD,
        attack_duration=90,
        ramp_up_time=5,
        attack_sources=3000,
    ),
    AttackType.HTTP_FLOOD: TrafficProfile(
        name="HTTP Flood",
        normal_pps=5000,
        attack_pps=30000,
        attack_type=AttackType.HTTP_FLOOD,
        attack_duration=180,
        ramp_up_time=30,
        attack_sources=10000,
    ),
    AttackType.DNS_AMPLIFICATION: TrafficProfile(
        name="DNS Amplification",
        normal_pps=5000,
        attack_pps=100000,
        attack_type=AttackType.DNS_AMPLIFICATION,
        attack_duration=60,
        ramp_up_time=3,
        attack_sources=500,
    ),
    AttackType.SLOWLORIS: TrafficProfile(
        name="Slowloris",
        normal_pps=5000,
        attack_pps=500,
        attack_type=AttackType.SLOWLORIS,
        attack_duration=300,
        ramp_up_time=60,
        attack_sources=200,
    ),
}


class TrafficSimulator:
    """
    Generates realistic network traffic with configurable attack patterns.

    Simulates both normal business traffic and various DDoS attack vectors.
    """

    def __init__(self, seed: Optional[int] = None):
        if seed is not None:
            random.seed(seed)

        self._attack_ips: list[str] = []
        self._botnet_ips: list[str] = []
        self._target_servers = [
            "10.0.1.100", "10.0.1.101", "10.0.1.102",
            "10.0.2.100", "10.0.2.101",
        ]
        self._internal_ips = [f"10.0.{i}.{j}" for i in range(1, 5) for j in range(1, 50)]

        # Geographic IP pools for attack sources
        self._geo_pools = {
            "asia": [(f"103.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}") for _ in range(200)],
            "europe": [(f"185.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}") for _ in range(200)],
            "americas": [(f"45.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}") for _ in range(200)],
            "russia": [(f"91.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}") for _ in range(100)],
            "china": [(f"116.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}") for _ in range(100)],
        }

        self._current_attack: Optional[AttackType] = None
        self._attack_start: float = 0
        self._attack_intensity: float = 0.0

    def generate_normal_packet(self) -> RawPacket:
        """Generate a single normal traffic packet with realistic patterns."""
        # Time-based traffic variation (sinusoidal pattern for business hours)
        hour = (time.time() / 3600) % 24
        time_factor = 0.5 + 0.5 * math.sin((hour - 6) * math.pi / 12)

        protocol = random.choices(
            [Protocol.TCP, Protocol.UDP, Protocol.ICMP, Protocol.DNS],
            weights=[0.65, 0.20, 0.05, 0.10],
            k=1,
        )[0]

        src_ip = random.choice(self._internal_ips)
        dst_ip = random.choice(self._target_servers)

        if random.random() < 0.4:
            src_ip, dst_ip = dst_ip, src_ip

        if protocol == Protocol.TCP:
            dst_port = random.choices(
                [80, 443, 8080, 3306, 5432, 6379, 22, 8443],
                weights=[0.25, 0.30, 0.10, 0.08, 0.07, 0.05, 0.05, 0.10],
                k=1,
            )[0]
            src_port = random.randint(1024, 65535)
            flags = random.choices(
                [SYN, SYN_ACK, ACK, PSH | ACK, FIN | ACK, RST],
                weights=[0.08, 0.08, 0.40, 0.34, 0.05, 0.05],
                k=1,
            )[0]
            packet_size = int(random.gauss(512, 200))
            packet_size = max(64, min(1460, packet_size))
        elif protocol == Protocol.UDP:
            dst_port = random.choices([53, 123, 161, 514], weights=[0.4, 0.2, 0.2, 0.2], k=1)[0]
            src_port = random.randint(1024, 65535)
            flags = 0
            packet_size = random.randint(64, 512)
        elif protocol == Protocol.DNS:
            dst_port = 53
            src_port = random.randint(1024, 65535)
            flags = 0
            packet_size = random.randint(40, 300)
        else:
            dst_port = 0
            src_port = 0
            flags = 0
            packet_size = 84

        return RawPacket(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=int(protocol),
            packet_size=packet_size,
            ttl=random.choices([64, 128, 255], weights=[0.5, 0.3, 0.2], k=1)[0],
            flags=flags,
            payload_size=max(0, packet_size - 40),
            sequence_number=random.randint(0, 2**32 - 1),
            ack_number=random.randint(0, 2**32 - 1) if flags & ACK else 0,
            window_size=random.choice([8192, 16384, 32768, 65535]),
        )

    def generate_attack_packet(self, attack_type: AttackType) -> RawPacket:
        """Generate an attack packet based on the specified attack type."""
        generators = {
            AttackType.SYN_FLOOD: self._gen_syn_flood,
            AttackType.UDP_FLOOD: self._gen_udp_flood,
            AttackType.HTTP_FLOOD: self._gen_http_flood,
            AttackType.DNS_AMPLIFICATION: self._gen_dns_amplification,
            AttackType.SLOWLORIS: self._gen_slowloris,
            AttackType.ICMP_FLOOD: self._gen_icmp_flood,
            AttackType.NTP_AMPLIFICATION: self._gen_ntp_amplification,
        }

        generator = generators.get(attack_type, self._gen_syn_flood)
        return generator()

    def _gen_syn_flood(self) -> RawPacket:
        """SYN flood: high-rate SYN packets from spoofed IPs."""
        src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        return RawPacket(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=random.choice(self._target_servers),
            src_port=random.randint(1024, 65535),
            dst_port=random.choice([80, 443, 8080]),
            protocol=int(Protocol.TCP),
            packet_size=64,
            ttl=random.choice([32, 64, 128]),
            flags=SYN,
            payload_size=0,
            window_size=random.choice([1024, 2048, 4096]),
        )

    def _gen_udp_flood(self) -> RawPacket:
        """UDP flood: high-rate large UDP packets."""
        src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        return RawPacket(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=random.choice(self._target_servers),
            src_port=random.randint(1024, 65535),
            dst_port=random.randint(1, 65535),
            protocol=int(Protocol.UDP),
            packet_size=random.choice([1400, 1460, 1500]),
            ttl=random.choice([64, 128]),
            flags=0,
            payload_size=random.choice([1360, 1420, 1460]),
        )

    def _gen_http_flood(self) -> RawPacket:
        """HTTP flood: many seemingly legitimate HTTP requests."""
        pool = random.choice(list(self._geo_pools.values()))
        src_ip = random.choice(pool)
        return RawPacket(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=random.choice(self._target_servers),
            src_port=random.randint(1024, 65535),
            dst_port=random.choice([80, 443]),
            protocol=int(Protocol.TCP),
            packet_size=random.randint(200, 800),
            ttl=random.choices([64, 128], weights=[0.6, 0.4], k=1)[0],
            flags=PSH | ACK,
            payload_size=random.randint(100, 700),
            window_size=65535,
        )

    def _gen_dns_amplification(self) -> RawPacket:
        """DNS amplification: large DNS responses with spoofed source."""
        return RawPacket(
            timestamp=time.time(),
            src_ip=f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            dst_ip=random.choice(self._target_servers),
            src_port=53,
            dst_port=random.randint(1024, 65535),
            protocol=int(Protocol.UDP),
            packet_size=random.choice([3000, 4000, 4096]),
            ttl=random.choice([64, 128, 255]),
            flags=0,
            payload_size=random.choice([2960, 3960, 4056]),
        )

    def _gen_ntp_amplification(self) -> RawPacket:
        """NTP amplification: large NTP monlist responses."""
        return RawPacket(
            timestamp=time.time(),
            src_ip=f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            dst_ip=random.choice(self._target_servers),
            src_port=123,
            dst_port=random.randint(1024, 65535),
            protocol=int(Protocol.UDP),
            packet_size=random.choice([468, 482, 556]),
            ttl=random.choice([64, 128]),
            flags=0,
            payload_size=random.choice([440, 450, 520]),
        )

    def _gen_slowloris(self) -> RawPacket:
        """Slowloris: slow, partial HTTP requests that keep connections open."""
        pool = random.choice(list(self._geo_pools.values()))
        src_ip = random.choice(pool)
        return RawPacket(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=random.choice(self._target_servers),
            src_port=random.randint(1024, 65535),
            dst_port=80,
            protocol=int(Protocol.TCP),
            packet_size=random.randint(40, 60),
            ttl=64,
            flags=PSH | ACK,
            payload_size=random.randint(1, 20),
            window_size=65535,
        )

    def _gen_icmp_flood(self) -> RawPacket:
        """ICMP flood: high-rate ICMP echo requests."""
        src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        return RawPacket(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=random.choice(self._target_servers),
            src_port=0,
            dst_port=0,
            protocol=int(Protocol.ICMP),
            packet_size=random.choice([64, 1024, 1500]),
            ttl=random.choice([64, 128, 255]),
            flags=0,
            payload_size=random.choice([24, 984, 1460]),
        )

    async def generate_traffic(
        self,
        normal_pps: int = 5000,
        batch_size: int = 100,
        attack_schedule: Optional[list[dict]] = None,
    ) -> AsyncIterator[tuple[list[RawPacket], Optional[AttackType]]]:
        """
        Generate continuous traffic with optional attack injections.

        Args:
            normal_pps: Normal traffic rate
            batch_size: Packets per batch
            attack_schedule: List of attack events [{time, type, duration, intensity}]

        Yields:
            Tuple of (packet_batch, current_attack_type)
        """
        start_time = time.time()
        interval = batch_size / normal_pps

        # Default attack schedule for demo
        if attack_schedule is None:
            attack_schedule = [
                {"time": 30, "type": AttackType.SYN_FLOOD, "duration": 45, "intensity": 0.7},
                {"time": 120, "type": AttackType.DNS_AMPLIFICATION, "duration": 30, "intensity": 0.9},
                {"time": 200, "type": AttackType.HTTP_FLOOD, "duration": 60, "intensity": 0.5},
                {"time": 320, "type": AttackType.SLOWLORIS, "duration": 90, "intensity": 0.4},
                {"time": 450, "type": AttackType.UDP_FLOOD, "duration": 40, "intensity": 0.8},
            ]

        while True:
            elapsed = time.time() - start_time
            batch = []
            current_attack = None
            intensity = 0.0

            # Check for active attack
            for event in attack_schedule:
                if event["time"] <= elapsed < event["time"] + event["duration"]:
                    current_attack = event["type"]
                    # Calculate ramp-up intensity
                    attack_elapsed = elapsed - event["time"]
                    ramp_factor = min(1.0, attack_elapsed / 10.0)
                    intensity = event["intensity"] * ramp_factor
                    break

            # Generate batch
            for _ in range(batch_size):
                if current_attack and random.random() < intensity:
                    if current_attack == AttackType.MULTI_VECTOR:
                        attack = random.choice([
                            AttackType.SYN_FLOOD, AttackType.UDP_FLOOD, AttackType.HTTP_FLOOD
                        ])
                        batch.append(self.generate_attack_packet(attack))
                    else:
                        batch.append(self.generate_attack_packet(current_attack))
                else:
                    batch.append(self.generate_normal_packet())

            yield batch, current_attack
            await asyncio.sleep(interval)

    def get_attack_sources(self, count: int = 100) -> list[str]:
        """Generate a list of attack source IPs."""
        ips = []
        for pool in self._geo_pools.values():
            ips.extend(pool[:count // len(self._geo_pools)])
        return ips[:count]
