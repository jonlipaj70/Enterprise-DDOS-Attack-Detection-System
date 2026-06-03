"""
Optimized Kafka Producer
=========================
High-throughput Kafka producer with batching, compression, and delivery guarantees.
Simulated implementation for demonstration — swappable with confluent-kafka.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from src.config.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class ProducerMetrics:
    """Producer performance metrics."""

    messages_sent: int = 0
    bytes_sent: int = 0
    batches_sent: int = 0
    errors: int = 0
    avg_latency_ms: float = 0.0
    _latencies: deque = field(default_factory=lambda: deque(maxlen=1000))

    def record_latency(self, latency_ms: float) -> None:
        self._latencies.append(latency_ms)
        self.avg_latency_ms = sum(self._latencies) / len(self._latencies)

    def to_dict(self) -> dict:
        return {
            "messages_sent": self.messages_sent,
            "bytes_sent": self.bytes_sent,
            "batches_sent": self.batches_sent,
            "errors": self.errors,
            "avg_latency_ms": round(self.avg_latency_ms, 2),
        }


class KafkaProducerSimulator:
    """
    Simulated Kafka producer with production-grade behavior.

    Implements batching, compression simulation, and delivery callbacks.
    In production, replace with confluent_kafka.Producer.
    """

    def __init__(
        self,
        bootstrap_servers: list[str] | None = None,
        batch_size: int = 16384,
        linger_ms: int = 5,
        compression_type: str = "snappy",
        acks: str = "all",
        max_retries: int = 3,
    ):
        self.bootstrap_servers = bootstrap_servers or ["localhost:9092"]
        self.batch_size = batch_size
        self.linger_ms = linger_ms
        self.compression_type = compression_type
        self.acks = acks
        self.max_retries = max_retries

        self._buffer: deque[dict[str, Any]] = deque()
        self._running = False
        self._flush_task: Optional[asyncio.Task] = None
        self.metrics = ProducerMetrics()
        self._callbacks: list[Callable] = []

    async def start(self) -> None:
        """Start the producer and background flush task."""
        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())
        logger.info(
            "kafka_producer_started",
            servers=self.bootstrap_servers,
            batch_size=self.batch_size,
            compression=self.compression_type,
        )

    async def stop(self) -> None:
        """Stop the producer, flushing remaining messages."""
        self._running = False
        if self._buffer:
            await self._flush_batch()
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        logger.info("kafka_producer_stopped", metrics=self.metrics.to_dict())

    async def send(self, topic: str, key: str | None, value: dict) -> None:
        """
        Send a message to a Kafka topic.

        Args:
            topic: Target topic name
            key: Message key for partitioning
            value: Message payload
        """
        message = {
            "topic": topic,
            "key": key,
            "value": value,
            "timestamp": time.time(),
        }
        self._buffer.append(message)

        # Flush if batch is full
        if len(self._buffer) >= self.batch_size:
            await self._flush_batch()

    async def send_batch(self, topic: str, messages: list[dict]) -> None:
        """Send a batch of messages efficiently."""
        for msg in messages:
            await self.send(topic, msg.get("key"), msg)

    async def _flush_loop(self) -> None:
        """Background task to flush buffered messages periodically."""
        while self._running:
            await asyncio.sleep(self.linger_ms / 1000.0)
            if self._buffer:
                await self._flush_batch()

    async def _flush_batch(self) -> None:
        """Flush the current message buffer."""
        if not self._buffer:
            return

        batch = []
        while self._buffer and len(batch) < self.batch_size:
            batch.append(self._buffer.popleft())

        start_time = time.time()

        try:
            # Simulate serialization and network send
            serialized_size = sum(len(json.dumps(msg["value"])) for msg in batch)

            # Simulate compression (snappy ~50% compression)
            compressed_size = int(serialized_size * 0.5) if self.compression_type else serialized_size

            # Simulate network latency (1-5ms)
            await asyncio.sleep(0.002)

            latency_ms = (time.time() - start_time) * 1000
            self.metrics.messages_sent += len(batch)
            self.metrics.bytes_sent += compressed_size
            self.metrics.batches_sent += 1
            self.metrics.record_latency(latency_ms)

            for callback in self._callbacks:
                callback(len(batch), compressed_size, latency_ms)

        except Exception as e:
            self.metrics.errors += 1
            logger.error("kafka_produce_error", error=str(e), batch_size=len(batch))

    def on_delivery(self, callback: Callable) -> None:
        """Register a delivery callback."""
        self._callbacks.append(callback)

    @property
    def stats(self) -> dict:
        return self.metrics.to_dict()
