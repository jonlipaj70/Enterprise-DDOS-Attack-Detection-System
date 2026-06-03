"""Distributed Tracing (Jaeger)."""
from __future__ import annotations
import time, uuid
from typing import Any, Optional

class Tracer:
    def __init__(self, service_name: str = "ddos-detector"):
        self.service_name = service_name
        self._spans: list[dict] = []

    def start_span(self, operation: str, parent_id: Optional[str] = None) -> dict:
        span = {"trace_id": str(uuid.uuid4())[:16], "span_id": str(uuid.uuid4())[:8], "operation": operation, "parent_id": parent_id, "start_time": time.time(), "end_time": None, "tags": {}}
        self._spans.append(span)
        return span

    def finish_span(self, span: dict) -> None:
        span["end_time"] = time.time()
