import pytest

from src.detection.cache_metadata import (
    ensure_sklearn_cache_compatible,
    sklearn_cache_metadata,
)


def test_current_sklearn_cache_metadata_is_accepted():
    ensure_sklearn_cache_compatible(sklearn_cache_metadata(), "test_model")


def test_missing_cache_schema_is_rejected():
    with pytest.raises(ValueError, match="cache schema"):
        ensure_sklearn_cache_compatible({"sklearn_version": "1.8.0"}, "test_model")
