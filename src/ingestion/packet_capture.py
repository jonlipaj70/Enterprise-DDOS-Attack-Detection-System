"""
Network Packet Capture Agent
==============================
Simulated packet capture with realistic network data generation.
In production, this would interface with libpcap/AF_PACKET for raw capture.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import AsyncIterator, Optional

from src.config.logging_config import get_logger

logger = get_logger(__name__)


class Protocol(IntEnum):
    """Network protocols."""
    TCP = 6
    UDP = 17
    ICMP = 1
    DNS = 53
    HTTP = 80
    HTTPS = 443
    NTP = 123
    SSDP = 1900


@dataclass
class RawPacket:
    """Represents a captured network packet."""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    packet_size: int
    ttl: int
    flags: int  # TCP flags bitmask
    payload_size: int
    fragment_offset: int = 0
    sequence_number: int = 0
    ack_number: int = 0
    window_size: int = 65535
    checksum: int = 0

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_size": self.packet_size,
            "ttl": self.ttl,
            "flags": self.flags,
            "payload_size": self.payload_size,
            "fragment_offset": self.fragment_offset,
            "sequence_number": self.sequence_number,
            "ack_number": self.ack_number,
            "window_size": self.window_size,
            "checksum": self.checksum,
        }


# TCP Flag constants
SYN = 0x02
ACK = 0x10
FIN = 0x01
RST = 0x04
PSH = 0x08
URG = 0x20
SYN_ACK = SYN | ACK


class PacketCaptureAgent:
    """
    Network packet capture agent.

    In simulation mode, generates realistic traffic patterns.
    In production mode, would use raw sockets or libpcap.
    """

    def __init__(
        self,
        interface: str = "eth0",
        capture_filter: str = "",
        batch_size: int = 100,
        simulation_mode: bool = True,
    ):
        self.interface = interface
        self.capture_filter = capture_filter
        self.batch_size = batch_size
        self.simulation_mode = simulation_mode
        self._running = False
        self._packet_count = 0
        self._start_time = 0.0

        # Internal network ranges for simulation
        self._internal_ips = [f"10.0.{i}.{j}" for i in range(1, 5) for j in range(1, 20)]
        self._servers = [
            "10.0.1.100", "10.0.1.101", "10.0.1.102",
            "10.0.2.100", "10.0.2.101",
        ]

    async def start(self) -> None:
        """Start the packet capture agent."""
        self._running = True
        self._start_time = time.time()
        logger.info(
            "packet_capture_started",
            interface=self.interface,
            simulation_mode=self.simulation_mode,
        )

    async def stop(self) -> None:
        """Stop the packet capture agent."""
        self._running = False
        elapsed = time.time() - self._start_time if self._start_time else 0
        logger.info(
            "packet_capture_stopped",
            packets_captured=self._packet_count,
            elapsed_seconds=round(elapsed, 2),
            avg_pps=round(self._packet_count / max(elapsed, 1), 2),
        )

    async def capture_packets(self, rate_pps: int = 1000) -> AsyncIterator[list[RawPacket]]:
        """
        Yield batches of captured packets.

        Args:
            rate_pps: Target packets per second for simulation
        """
        interval = self.batch_size / rate_pps

        while self._running:
            batch = []
            for _ in range(self.batch_size):
                packet = self._generate_normal_packet()
                batch.append(packet)
                self._packet_count += 1

            yield batch
            await asyncio.sleep(interval)

    def _generate_normal_packet(self) -> RawPacket:
        """Generate a realistic normal traffic packet."""
        protocol = random.choices(
            [Protocol.TCP, Protocol.UDP, Protocol.ICMP, Protocol.DNS],
            weights=[0.65, 0.20, 0.05, 0.10],
            k=1,
        )[0]

        src_ip = random.choice(self._internal_ips)
        dst_ip = random.choice(self._servers)

        # Occasionally swap src/dst for return traffic
        if random.random() < 0.4:
            src_ip, dst_ip = dst_ip, src_ip

        if protocol == Protocol.TCP:
            dst_port = random.choices(
                [80, 443, 8080, 3306, 5432, 6379, 22],
                weights=[0.30, 0.35, 0.10, 0.08, 0.07, 0.05, 0.05],
                k=1,
            )[0]
            src_port = random.randint(1024, 65535)
            flags = random.choices(
                [SYN, SYN_ACK, ACK, PSH | ACK, FIN | ACK, RST],
                weights=[0.10, 0.10, 0.40, 0.30, 0.05, 0.05],
                k=1,
            )[0]
            packet_size = random.choices(
                [64, 128, 256, 512, 1024, 1460],
                weights=[0.15, 0.10, 0.15, 0.20, 0.25, 0.15],
                k=1,
            )[0]
        elif protocol == Protocol.UDP:
            dst_port = random.choices(
                [53, 123, 161, 514, 5060],
                weights=[0.40, 0.15, 0.15, 0.15, 0.15],
                k=1,
            )[0]
            src_port = random.randint(1024, 65535)
            flags = 0
            packet_size = random.randint(64, 512)
        elif protocol == Protocol.DNS:
            dst_port = 53
            src_port = random.randint(1024, 65535)
            flags = 0
            packet_size = random.randint(40, 512)
        else:  # ICMP
            dst_port = 0
            src_port = 0
            flags = 0
            packet_size = random.choices([64, 84, 128], weights=[0.5, 0.3, 0.2], k=1)[0]

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
            payload_size=max(0, packet_size - 40),  # Subtract header
            sequence_number=random.randint(0, 2**32 - 1),
            ack_number=random.randint(0, 2**32 - 1) if flags & ACK else 0,
            window_size=random.choice([8192, 16384, 32768, 65535]),
        )

    @property
    def stats(self) -> dict:
        """Get capture statistics."""
        elapsed = time.time() - self._start_time if self._start_time else 0
        return {
            "packets_captured": self._packet_count,
            "elapsed_seconds": round(elapsed, 2),
            "avg_pps": round(self._packet_count / max(elapsed, 1), 2),
            "running": self._running,
        }
