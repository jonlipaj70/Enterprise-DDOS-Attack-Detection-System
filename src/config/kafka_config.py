"""
Kafka Cluster Configuration
============================
Three-broker cluster configuration with optimized producer/consumer settings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class KafkaProducerConfig:
    """Optimized Kafka producer configuration."""

    bootstrap_servers: list[str] = field(
        default_factory=lambda: ["localhost:9092", "localhost:9093", "localhost:9094"]
    )
    acks: str = "all"
    retries: int = 3
    batch_size: int = 16384  # 16KB
    linger_ms: int = 5  # Wait up to 5ms for batching
    buffer_memory: int = 33554432  # 32MB
    compression_type: str = "snappy"
    max_in_flight_requests: int = 5
    enable_idempotence: bool = True
    max_request_size: int = 1048576  # 1MB

    def to_dict(self) -> dict[str, Any]:
        return {
            "bootstrap.servers": ",".join(self.bootstrap_servers),
            "acks": self.acks,
            "retries": self.retries,
            "batch.size": self.batch_size,
            "linger.ms": self.linger_ms,
            "buffer.memory": self.buffer_memory,
            "compression.type": self.compression_type,
            "max.in.flight.requests.per.connection": self.max_in_flight_requests,
            "enable.idempotence": self.enable_idempotence,
            "max.request.size": self.max_request_size,
        }


@dataclass
class KafkaConsumerConfig:
    """Optimized Kafka consumer configuration."""

    bootstrap_servers: list[str] = field(
        default_factory=lambda: ["localhost:9092", "localhost:9093", "localhost:9094"]
    )
    group_id: str = "ddos-detector"
    auto_offset_reset: str = "latest"
    enable_auto_commit: bool = False
    max_poll_records: int = 500
    max_poll_interval_ms: int = 300000
    session_timeout_ms: int = 30000
    heartbeat_interval_ms: int = 10000
    fetch_min_bytes: int = 1
    fetch_max_wait_ms: int = 500

    def to_dict(self) -> dict[str, Any]:
        return {
            "bootstrap.servers": ",".join(self.bootstrap_servers),
            "group.id": self.group_id,
            "auto.offset.reset": self.auto_offset_reset,
            "enable.auto.commit": self.enable_auto_commit,
            "max.poll.records": self.max_poll_records,
            "max.poll.interval.ms": self.max_poll_interval_ms,
            "session.timeout.ms": self.session_timeout_ms,
            "heartbeat.interval.ms": self.heartbeat_interval_ms,
            "fetch.min.bytes": self.fetch_min_bytes,
            "fetch.max.wait.ms": self.fetch_max_wait_ms,
        }


@dataclass
class KafkaTopicConfig:
    """Topic configuration with replication and partitioning."""

    name: str
    num_partitions: int = 12
    replication_factor: int = 3
    retention_ms: int = 86400000  # 24 hours
    cleanup_policy: str = "delete"
    min_insync_replicas: int = 2
    segment_bytes: int = 1073741824  # 1GB

    def to_dict(self) -> dict[str, Any]:
        return {
            "num.partitions": self.num_partitions,
            "replication.factor": self.replication_factor,
            "retention.ms": self.retention_ms,
            "cleanup.policy": self.cleanup_policy,
            "min.insync.replicas": self.min_insync_replicas,
            "segment.bytes": self.segment_bytes,
        }


# ─── Default Topic Definitions ──────────────────────────────

RAW_PACKETS_TOPIC = KafkaTopicConfig(
    name="raw-packets",
    num_partitions=12,
    retention_ms=3600000,  # 1 hour
)

PROCESSED_FEATURES_TOPIC = KafkaTopicConfig(
    name="processed-features",
    num_partitions=12,
    retention_ms=86400000,  # 24 hours
)

ALERTS_TOPIC = KafkaTopicConfig(
    name="detection-alerts",
    num_partitions=6,
    retention_ms=604800000,  # 7 days
)
