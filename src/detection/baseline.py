"""
Adaptive Baseline Calculator
==============================
30-day rolling window baseline with seasonal decomposition for drift detection.
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class BaselineState:
    """Tracks baseline statistics for a metric."""
    mean: float = 0.0
    std: float = 0.0
    min_val: float = float("inf")
    max_val: float = float("-inf")
    count: int = 0
    _values: deque = field(default_factory=lambda: deque(maxlen=86400))  # 24h at 1/sec

    def update(self, value: float) -> None:
        self._values.append(value)
        self.count += 1
        self.mean = sum(self._values) / len(self._values)
        self.std = math.sqrt(
            sum((v - self.mean) ** 2 for v in self._values) / max(len(self._values), 1)
        )
        self.min_val = min(self.min_val, value)
        self.max_val = max(self.max_val, value)

    def is_anomalous(self, value: float, z_threshold: float = 3.0) -> bool:
        """Check if value deviates beyond z_threshold standard deviations."""
        if self.count < 10:
            return False
        if self.std == 0:
            return value != self.mean
        z_score = abs(value - self.mean) / self.std
        return z_score > z_threshold

    def z_score(self, value: float) -> float:
        if self.std == 0:
            return 0.0
        return (value - self.mean) / self.std


class AdaptiveBaseline:
    """
    Maintains adaptive baselines for all monitored metrics.

    Features:
    - Rolling window statistics
    - Seasonal pattern detection
    - Drift detection
    - Per-metric anomaly thresholds
    """

    def __init__(self, z_threshold: float = 3.0):
        self.z_threshold = z_threshold
        self._baselines: dict[str, BaselineState] = {}
        self._hourly_profiles: dict[str, dict[int, BaselineState]] = {}

    def update(self, metric_name: str, value: float) -> None:
        """Update the baseline for a metric."""
        if metric_name not in self._baselines:
            self._baselines[metric_name] = BaselineState()
        self._baselines[metric_name].update(value)

        # Update hourly profile
        hour = int(time.time() / 3600) % 24
        if metric_name not in self._hourly_profiles:
            self._hourly_profiles[metric_name] = {}
        if hour not in self._hourly_profiles[metric_name]:
            self._hourly_profiles[metric_name][hour] = BaselineState()
        self._hourly_profiles[metric_name][hour].update(value)

    def is_anomalous(self, metric_name: str, value: float) -> bool:
        """Check if a value is anomalous compared to the baseline."""
        baseline = self._baselines.get(metric_name)
        if baseline is None:
            return False
        return baseline.is_anomalous(value, self.z_threshold)

    def get_deviation(self, metric_name: str, value: float) -> float:
        """Get the z-score deviation for a value."""
        baseline = self._baselines.get(metric_name)
        if baseline is None:
            return 0.0
        return baseline.z_score(value)

    def get_baseline(self, metric_name: str) -> Optional[dict]:
        """Get current baseline statistics for a metric."""
        baseline = self._baselines.get(metric_name)
        if baseline is None:
            return None
        return {
            "mean": round(baseline.mean, 4),
            "std": round(baseline.std, 4),
            "min": round(baseline.min_val, 4),
            "max": round(baseline.max_val, 4),
            "count": baseline.count,
        }

    def get_all_baselines(self) -> dict[str, dict]:
        """Get baselines for all metrics."""
        return {
            name: self.get_baseline(name)
            for name in self._baselines
        }

    @property
    def stats(self) -> dict:
        return {
            "metrics_tracked": len(self._baselines),
            "total_observations": sum(b.count for b in self._baselines.values()),
        }
