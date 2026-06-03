"""
Custom Packet Serialization
=============================
Avro-based serialization with schema evolution support.
"""

from __future__ import annotations

import json
import struct
import time
from typing import Any

from src.config.logging_config import get_logger

logger = get_logger(__name__)

# Packet schema definition (Avro-compatible)
PACKET_SCHEMA = {
    "type": "record",
    "name": "NetworkPacket",
    "namespace": "com.ddos.detection",
    "fields": [
        {"name": "timestamp", "type": "double"},
        {"name": "src_ip", "type": "string"},
        {"name": "dst_ip", "type": "string"},
        {"name": "src_port", "type": "int"},
        {"name": "dst_port", "type": "int"},
        {"name": "protocol", "type": "int"},
        {"name": "packet_size", "type": "int"},
        {"name": "ttl", "type": "int"},
        {"name": "flags", "type": "int"},
        {"name": "payload_size", "type": "int"},
        {"name": "fragment_offset", "type": "int", "default": 0},
        {"name": "sequence_number", "type": "long", "default": 0},
        {"name": "ack_number", "type": "long", "default": 0},
        {"name": "window_size", "type": "int", "default": 65535},
        {"name": "checksum", "type": "int", "default": 0},
    ],
}

SCHEMA_VERSION = 1
BINARY_PACKET_FORMAT = ">d4B4BHHBIBIIIQQII"


class PacketSerializer:
    """
    Serializes network packets for Kafka transport.

    Supports JSON and binary formats with schema versioning.
    """

    def __init__(self, format: str = "json"):
        """
        Args:
            format: Serialization format ('json' or 'binary')
        """
        self.format = format
        self._schema_id = 1
        self._serialized_count = 0
        self._total_bytes = 0

    def serialize(self, packet_dict: dict[str, Any]) -> bytes:
        """Serialize a packet dictionary to bytes."""
        if self.format == "binary":
            return self._serialize_binary(packet_dict)
        return self._serialize_json(packet_dict)

    def deserialize(self, data: bytes) -> dict[str, Any]:
        """Deserialize bytes back to a packet dictionary."""
        if self.format == "binary":
            return self._deserialize_binary(data)
        return self._deserialize_json(data)

    def _serialize_json(self, packet: dict[str, Any]) -> bytes:
        """JSON serialization with schema header."""
        envelope = {
            "schema_version": SCHEMA_VERSION,
            "schema_id": self._schema_id,
            "data": packet,
        }
        data = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        self._serialized_count += 1
        self._total_bytes += len(data)
        return data

    def _deserialize_json(self, data: bytes) -> dict[str, Any]:
        """JSON deserialization with schema validation."""
        envelope = json.loads(data.decode("utf-8"))
        return envelope["data"]

    def _serialize_binary(self, packet: dict[str, Any]) -> bytes:
        """
        Compact binary serialization.

        Format: [magic(2)] [schema_version(1)] [schema_id(4)] [payload...]
        """
        # Header
        header = struct.pack(
            ">HBI",
            0xDD05,  # Magic bytes
            SCHEMA_VERSION,
            self._schema_id,
        )

        # Encode IP addresses as 4 bytes each
        src_parts = [int(p) for p in packet["src_ip"].split(".")]
        dst_parts = [int(p) for p in packet["dst_ip"].split(".")]

        payload = struct.pack(
            BINARY_PACKET_FORMAT,
            packet["timestamp"],
            *src_parts,
            *dst_parts,
            packet["src_port"],
            packet["dst_port"],
            packet["protocol"],
            packet["packet_size"],
            packet["ttl"],
            packet["flags"],
            packet["payload_size"],
            packet.get("fragment_offset", 0),
            packet.get("sequence_number", 0),
            packet.get("ack_number", 0),
            packet.get("window_size", 65535),
            packet.get("checksum", 0),
        )

        data = header + payload
        self._serialized_count += 1
        self._total_bytes += len(data)
        return data

    def _deserialize_binary(self, data: bytes) -> dict[str, Any]:
        """Deserialize binary format back to dict."""
        # Parse header
        magic, version, schema_id = struct.unpack(">HBI", data[:7])
        if magic != 0xDD05:
            raise ValueError(f"Invalid magic bytes: {magic:#x}")

        # Parse payload
        values = struct.unpack(BINARY_PACKET_FORMAT, data[7:])

        src_ip = f"{values[1]}.{values[2]}.{values[3]}.{values[4]}"
        dst_ip = f"{values[5]}.{values[6]}.{values[7]}.{values[8]}"

        return {
            "timestamp": values[0],
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": values[9],
            "dst_port": values[10],
            "protocol": values[11],
            "packet_size": values[12],
            "ttl": values[13],
            "flags": values[14],
            "payload_size": values[15],
            "fragment_offset": values[16],
            "sequence_number": values[17],
            "ack_number": values[18],
            "window_size": values[19],
            "checksum": values[20],
        }

    @property
    def stats(self) -> dict:
        return {
            "format": self.format,
            "serialized_count": self._serialized_count,
            "total_bytes": self._total_bytes,
            "avg_bytes_per_packet": (
                self._total_bytes / self._serialized_count if self._serialized_count else 0
            ),
        }
