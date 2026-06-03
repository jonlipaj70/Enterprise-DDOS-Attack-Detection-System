"""
Spark Structured Streaming Engine (Simulated)
==============================================
Processes raw packet streams into feature vectors for ML detection.
Uses an in-memory streaming approach that mirrors Spark Structured Streaming semantics.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable, Optional

from src.config.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class StreamMetrics:
    """Stream processing metrics."""
    batches_processed: int = 0
    records_processed: int = 0
    processing_time_ms: float = 0.0
    avg_batch_time_ms: float = 0.0
    watermark: float = 0.0
    _batch_times: deque = field(default_factory=lambda: deque(maxlen=100))

    def record_batch(self, records: int, time_ms: float) -> None:
        self.batches_processed += 1
        self.records_processed += records
        self._batch_times.append(time_ms)
        self.avg_batch_time_ms = sum(self._batch_times) / len(self._batch_times)
        self.processing_time_ms = time_ms

    def to_dict(self) -> dict:
        return {
            "batches_processed": self.batches_processed,
            "records_processed": self.records_processed,
            "processing_time_ms": round(self.processing_time_ms, 2),
            "avg_batch_time_ms": round(self.avg_batch_time_ms, 2),
            "watermark": self.watermark,
            "throughput_rps": round(
                self.records_processed / max(1, self.batches_processed * self.avg_batch_time_ms / 1000),
                0,
            ) if self.avg_batch_time_ms > 0 else 0,
        }


class StreamProcessor:
    """
    Simulated Spark Structured Streaming engine.

    Processes micro-batches of packet data with:
    - Watermarking for late data handling
    - Checkpointing for fault tolerance
    - Stateful aggregations
    """

    def __init__(
        self,
        batch_interval_ms: int = 1000,
        watermark_delay_ms: int = 10000,
        max_records_per_batch: int = 10000,
    ):
        self.batch_interval_ms = batch_interval_ms
        self.watermark_delay_ms = watermark_delay_ms
        self.max_records_per_batch = max_records_per_batch

        self._running = False
        self._processors: list[Callable] = []
        self._input_buffer: deque = deque()
        self._checkpoint: dict[str, Any] = {}
        self.metrics = StreamMetrics()

    async def start(self) -> None:
        """Start the stream processing engine."""
        self._running = True
        logger.info(
            "stream_processor_started",
            batch_interval_ms=self.batch_interval_ms,
            watermark_delay_ms=self.watermark_delay_ms,
        )

    async def stop(self) -> None:
        """Stop the stream processing engine."""
        self._running = False
        logger.info("stream_processor_stopped", metrics=self.metrics.to_dict())

    def add_processor(self, processor: Callable) -> None:
        """Register a processing function for the pipeline."""
        self._processors.append(processor)

    async def ingest(self, records: list[dict]) -> None:
        """Add records to the input buffer."""
        self._input_buffer.extend(records)

    async def process_stream(
        self, source: AsyncIterator[list[dict]]
    ) -> AsyncIterator[list[dict]]:
        """
        Process a stream of record batches.

        Applies all registered processors in sequence and yields results.
        """
        async for batch in source:
            if not self._running:
                break

            start_time = time.time()

            # Apply watermark — drop records older than watermark
            current_time = time.time()
            watermark = current_time - (self.watermark_delay_ms / 1000.0)
            self.metrics.watermark = watermark

            filtered_batch = [
                record for record in batch
                if record.get("timestamp", current_time) >= watermark
            ]

            # Apply each processor in sequence
            result = filtered_batch
            for processor in self._processors:
                result = processor(result)

            elapsed_ms = (time.time() - start_time) * 1000
            self.metrics.record_batch(len(filtered_batch), elapsed_ms)

            # Checkpoint
            self._checkpoint = {
                "timestamp": current_time,
                "batch_id": self.metrics.batches_processed,
                "watermark": watermark,
            }

            yield result

    async def process_batch(self, batch: list[dict]) -> list[dict]:
        """Process a single batch of records."""
        start_time = time.time()

        result = batch
        for processor in self._processors:
            result = processor(result)

        elapsed_ms = (time.time() - start_time) * 1000
        self.metrics.record_batch(len(batch), elapsed_ms)
        return result

    @property
    def stats(self) -> dict:
        return self.metrics.to_dict()
