"""Prometheus Metrics Exporter."""
from __future__ import annotations
from typing import Any

class MetricsExporter:
    """Exports system metrics in Prometheus format."""

    def __init__(self):
        self._metrics = {}

    def record(self, name: str, value: float, labels: dict = None) -> None:
        key = f"{name}_{hash(str(labels)) if labels else ''}"
        self._metrics[key] = {"name": name, "value": value, "labels": labels or {}}

    def export_prometheus(self) -> str:
        lines = []
        for entry in self._metrics.values():
            label_str = ",".join(f'{k}="{v}"' for k, v in entry["labels"].items())
            metric_name = entry["name"].replace(".", "_")
            if label_str:
                lines.append(f"{metric_name}{{{label_str}}} {entry['value']}")
            else:
                lines.append(f"{metric_name} {entry['value']}")
        return "\n".join(lines)
