"""Unit tests for the Alert Engine."""
import pytest
from src.alerting.alert_engine import AlertEngine, AlertSeverity, AlertStatus


class TestAlertEngine:
    def setup_method(self):
        self.engine = AlertEngine(dedup_window_seconds=1)

    def test_create_alert_from_anomaly(self):
        result = {
            "is_anomaly": True,
            "anomaly_score": 0.85,
            "confidence": 0.9,
            "attack_type": "syn_flood",
            "severity": "critical",
            "details": {"packet_rate": 50000},
        }
        alert = self.engine.create_alert(result)
        assert alert is not None
        assert alert.severity == AlertSeverity.CRITICAL
        assert alert.attack_type == "syn_flood"
        assert "SYN Flood" in alert.title

    def test_no_alert_for_normal(self):
        result = {"is_anomaly": False, "anomaly_score": 0.1}
        alert = self.engine.create_alert(result)
        assert alert is None

    def test_deduplication(self):
        result = {
            "is_anomaly": True,
            "anomaly_score": 0.8,
            "attack_type": "syn_flood",
            "severity": "critical",
            "details": {},
        }
        alert1 = self.engine.create_alert(result)
        alert2 = self.engine.create_alert(result)
        assert alert1 is not None
        assert alert2 is None  # Deduplicated

    def test_acknowledge_alert(self):
        result = {
            "is_anomaly": True,
            "anomaly_score": 0.8,
            "attack_type": "syn_flood",
            "severity": "warning",
            "details": {},
        }
        alert = self.engine.create_alert(result)
        success = self.engine.acknowledge_alert(alert.alert_id, "admin")
        assert success is True
        assert alert.status == AlertStatus.ACKNOWLEDGED

    def test_resolve_alert(self):
        result = {
            "is_anomaly": True,
            "anomaly_score": 0.8,
            "attack_type": "udp_flood",
            "severity": "warning",
            "details": {},
        }
        alert = self.engine.create_alert(result)
        success = self.engine.resolve_alert(alert.alert_id)
        assert success is True
        assert alert.status == AlertStatus.RESOLVED

    def test_stats(self):
        result = {
            "is_anomaly": True,
            "anomaly_score": 0.8,
            "attack_type": "test",
            "severity": "info",
            "details": {},
        }
        self.engine.create_alert(result)
        stats = self.engine.stats
        assert stats["alerts_created"] == 1
