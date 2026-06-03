"""Helpers for validating locally cached sklearn model artifacts."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from typing import Any

CACHE_SCHEMA_VERSION = 1


def current_sklearn_version() -> str:
    try:
        return version("scikit-learn")
    except PackageNotFoundError:
        return "unavailable"


def sklearn_cache_metadata() -> dict[str, str]:
    return {
        "cache_schema_version": str(CACHE_SCHEMA_VERSION),
        "sklearn_version": current_sklearn_version(),
    }


def ensure_sklearn_cache_compatible(metrics: dict[str, Any], cache_name: str) -> None:
    cached_schema = metrics.get("cache_schema_version")
    expected_schema = str(CACHE_SCHEMA_VERSION)
    if cached_schema != expected_schema:
        cached_label = cached_schema or "unknown"
        raise ValueError(
            f"{cache_name} cache schema is {cached_label}; expected {expected_schema}"
        )

    cached_version = metrics.get("sklearn_version")
    current_version = current_sklearn_version()
    if cached_version != current_version:
        cached_label = cached_version or "unknown"
        raise ValueError(
            f"{cache_name} cache was built with scikit-learn {cached_label}; "
            f"current version is {current_version}"
        )
