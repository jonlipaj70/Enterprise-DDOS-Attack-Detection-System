"""
Model Registry
================
Model versioning, A/B testing support, and model lifecycle management.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ModelStatus(str, Enum):
    STAGING = "staging"
    PRODUCTION = "production"
    ARCHIVED = "archived"


@dataclass
class ModelVersion:
    """A registered model version."""
    model_id: str
    name: str
    version: int
    status: ModelStatus
    metrics: dict[str, float] = field(default_factory=dict)
    parameters: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    promoted_at: Optional[float] = None


class ModelRegistry:
    """
    Model registry for versioning and lifecycle management.

    Supports:
    - Model version registration
    - Promotion (staging → production)
    - A/B testing between versions
    - Performance metric tracking
    """

    def __init__(self):
        self._models: dict[str, list[ModelVersion]] = {}
        self._production_models: dict[str, ModelVersion] = {}

    def register(
        self,
        name: str,
        metrics: dict[str, float],
        parameters: dict[str, Any] | None = None,
    ) -> ModelVersion:
        """Register a new model version."""
        if name not in self._models:
            self._models[name] = []

        version = len(self._models[name]) + 1
        model_id = f"{name}_v{version}"

        mv = ModelVersion(
            model_id=model_id,
            name=name,
            version=version,
            status=ModelStatus.STAGING,
            metrics=metrics,
            parameters=parameters or {},
        )

        self._models[name].append(mv)
        return mv

    def promote(self, name: str, version: int) -> ModelVersion:
        """Promote a model version to production."""
        versions = self._models.get(name, [])
        for mv in versions:
            if mv.version == version:
                # Archive current production model
                if name in self._production_models:
                    self._production_models[name].status = ModelStatus.ARCHIVED

                mv.status = ModelStatus.PRODUCTION
                mv.promoted_at = time.time()
                self._production_models[name] = mv
                return mv

        raise ValueError(f"Model {name} version {version} not found")

    def get_production(self, name: str) -> Optional[ModelVersion]:
        """Get the current production model."""
        return self._production_models.get(name)

    def get_all_versions(self, name: str) -> list[dict]:
        """Get all versions of a model."""
        return [
            {
                "model_id": mv.model_id,
                "version": mv.version,
                "status": mv.status.value,
                "metrics": mv.metrics,
                "created_at": mv.created_at,
            }
            for mv in self._models.get(name, [])
        ]

    @property
    def stats(self) -> dict:
        return {
            "registered_models": len(self._models),
            "total_versions": sum(len(v) for v in self._models.values()),
            "production_models": len(self._production_models),
        }
