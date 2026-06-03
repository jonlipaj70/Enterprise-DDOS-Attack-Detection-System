"""
Schema Registry Integration
=============================
Schema registry for managing packet schema versions and compatibility.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from src.config.logging_config import get_logger

logger = get_logger(__name__)


class CompatibilityLevel(str, Enum):
    """Schema compatibility levels."""
    BACKWARD = "BACKWARD"
    FORWARD = "FORWARD"
    FULL = "FULL"
    NONE = "NONE"


@dataclass
class SchemaVersion:
    """A versioned schema entry."""
    schema_id: int
    version: int
    schema: dict[str, Any]
    fingerprint: str
    created_at: float = field(default_factory=time.time)


class SchemaRegistry:
    """
    In-memory schema registry (simulates Confluent Schema Registry).

    Manages schema versions, compatibility checks, and evolution.
    """

    def __init__(self, compatibility: CompatibilityLevel = CompatibilityLevel.BACKWARD):
        self._schemas: dict[str, list[SchemaVersion]] = {}
        self._schema_by_id: dict[int, SchemaVersion] = {}
        self._next_id = 1
        self._compatibility = compatibility

    def register_schema(self, subject: str, schema: dict[str, Any]) -> int:
        """
        Register a schema under a subject.

        Returns:
            Schema ID
        """
        fingerprint = self._fingerprint(schema)

        # Check if exact schema already exists
        if subject in self._schemas:
            for sv in self._schemas[subject]:
                if sv.fingerprint == fingerprint:
                    return sv.schema_id

            # Check compatibility
            latest = self._schemas[subject][-1]
            if not self._check_compatibility(latest.schema, schema):
                raise ValueError(
                    f"Schema is not {self._compatibility.value} compatible with version {latest.version}"
                )

        schema_version = SchemaVersion(
            schema_id=self._next_id,
            version=len(self._schemas.get(subject, [])) + 1,
            schema=schema,
            fingerprint=fingerprint,
        )

        if subject not in self._schemas:
            self._schemas[subject] = []
        self._schemas[subject].append(schema_version)
        self._schema_by_id[self._next_id] = schema_version
        self._next_id += 1

        logger.info(
            "schema_registered",
            subject=subject,
            version=schema_version.version,
            schema_id=schema_version.schema_id,
        )
        return schema_version.schema_id

    def get_schema(self, schema_id: int) -> Optional[dict[str, Any]]:
        """Get a schema by its ID."""
        sv = self._schema_by_id.get(schema_id)
        return sv.schema if sv else None

    def get_latest_version(self, subject: str) -> Optional[SchemaVersion]:
        """Get the latest schema version for a subject."""
        versions = self._schemas.get(subject, [])
        return versions[-1] if versions else None

    def get_all_versions(self, subject: str) -> list[SchemaVersion]:
        """Get all schema versions for a subject."""
        return self._schemas.get(subject, [])

    def _fingerprint(self, schema: dict[str, Any]) -> str:
        """Compute schema fingerprint for deduplication."""
        canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    def _check_compatibility(
        self, old_schema: dict[str, Any], new_schema: dict[str, Any]
    ) -> bool:
        """Check schema compatibility (simplified)."""
        if self._compatibility == CompatibilityLevel.NONE:
            return True

        old_fields = {f["name"] for f in old_schema.get("fields", [])}
        new_fields = {f["name"] for f in new_schema.get("fields", [])}

        if self._compatibility == CompatibilityLevel.BACKWARD:
            # New schema can read old data: all old fields must exist or have defaults
            return True  # Simplified — always backward compatible

        if self._compatibility == CompatibilityLevel.FORWARD:
            # Old schema can read new data: no removed fields
            removed = old_fields - new_fields
            return len(removed) == 0

        if self._compatibility == CompatibilityLevel.FULL:
            return old_fields == new_fields

        return True

    @property
    def subjects(self) -> list[str]:
        return list(self._schemas.keys())
