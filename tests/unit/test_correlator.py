"""Unit tests for Alert Correlator."""
import pytest
import time
from src.alerting.correlator import AlertCorrelator

class TestAlertCorrelator:
    def test_time_correlation(self):
        correlator = AlertCorrelator(time_window=60)
        alert1 = {"alert_id": "a1", "timestamp": time.time(), "attack_type": "syn_flood"}
        alert2 = {"alert_id": "a2", "timestamp": time.time() + 5, "attack_type": "syn_flood"}
        correlator.correlate(alert1)
        correlated = correlator.correlate(alert2)
        assert "a1" in correlated

    def test_no_correlation_different_types(self):
        correlator = AlertCorrelator(time_window=60)
        alert1 = {"alert_id": "a1", "timestamp": time.time(), "attack_type": "syn_flood"}
        alert2 = {"alert_id": "a2", "timestamp": time.time() + 5, "attack_type": "udp_flood"}
        correlator.correlate(alert1)
        correlated = correlator.correlate(alert2)
        assert len(correlated) == 0
