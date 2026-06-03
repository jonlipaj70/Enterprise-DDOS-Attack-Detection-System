"""
Spark Streaming Configuration
==============================
Spark Structured Streaming configuration for real-time packet processing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SparkStreamingConfig:
    """Spark Structured Streaming configuration."""

    master: str = "local[*]"
    app_name: str = "ddos-stream-processor"
    batch_interval_seconds: int = 1
    checkpoint_dir: str = "/tmp/spark-checkpoints"

    # Memory settings
    driver_memory: str = "4g"
    executor_memory: str = "4g"
    executor_cores: int = 4

    # Streaming settings
    max_offsets_per_trigger: int = 50000
    watermark_delay: str = "10 seconds"
    output_mode: str = "update"

    # Shuffle settings
    shuffle_partitions: int = 12
    adaptive_enabled: bool = True

    # Serialization
    serializer: str = "org.apache.spark.serializer.KryoSerializer"

    def to_spark_conf(self) -> dict[str, Any]:
        return {
            "spark.master": self.master,
            "spark.app.name": self.app_name,
            "spark.driver.memory": self.driver_memory,
            "spark.executor.memory": self.executor_memory,
            "spark.executor.cores": self.executor_cores,
            "spark.sql.shuffle.partitions": self.shuffle_partitions,
            "spark.sql.adaptive.enabled": self.adaptive_enabled,
            "spark.serializer": self.serializer,
            "spark.streaming.backpressure.enabled": True,
            "spark.streaming.kafka.maxRatePerPartition": 10000,
        }


@dataclass
class WindowConfig:
    """Window aggregation configuration."""

    short_window: str = "1 second"
    medium_window: str = "5 seconds"
    long_window: str = "60 seconds"
    slide_interval: str = "1 second"
    watermark_delay: str = "10 seconds"


# ─── Default Configurations ─────────────────────────────────

DEFAULT_SPARK_CONFIG = SparkStreamingConfig()
DEFAULT_WINDOW_CONFIG = WindowConfig()
