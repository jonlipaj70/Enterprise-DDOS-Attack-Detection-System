"""Unit tests for Adaptive Baseline."""
import pytest
from src.detection.baseline import AdaptiveBaseline

class TestAdaptiveBaseline:
    def test_update_and_query(self):
        baseline = AdaptiveBaseline()
        for i in range(100):
            baseline.update("packet_rate", 5000 + i)
        info = baseline.get_baseline("packet_rate")
        assert info is not None
        assert info["count"] == 100

    def test_anomaly_detection(self):
        baseline = AdaptiveBaseline(z_threshold=3.0)
        for _ in range(100):
            baseline.update("pps", 5000)
        assert baseline.is_anomalous("pps", 5000) is False
        assert baseline.is_anomalous("pps", 50000) is True
