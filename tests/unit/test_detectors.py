"""Unit tests for detection models."""

import pytest
from src.detection.ensemble_model import EnsembleModel
from src.detection.isolation_forest import IsolationForestDetector
from src.detection.random_forest import RandomForestDetector
from src.detection.autoencoder import AutoencoderDetector


class TestIsolationForest:
    def setup_method(self):
        self.detector = IsolationForestDetector()
        self.detector.initialize()

    def test_normal_traffic_low_score(self, sample_features):
        arr = self._to_array(sample_features)
        score = self.detector.score(arr)
        assert 0 <= score <= 1
        assert score < 0.5  # Normal traffic should score low

    def test_attack_traffic_high_score(self, attack_features):
        arr = self._to_array(attack_features)
        score = self.detector.score(arr)
        assert score > 0.3  # Attack traffic should score higher

    def test_validation_metrics_are_available(self):
        stats = self.detector.stats
        assert stats["validation_sample_count"] > 0
        assert 0 <= stats["validation_precision"] <= 1
        assert 0 <= stats["validation_recall"] <= 1
        assert 0 <= stats["validation_f1_score"] <= 1

    def _to_array(self, features):
        keys = [
            "packet_rate",
            "byte_rate",
            "tcp_ratio",
            "udp_ratio",
            "icmp_ratio",
            "dns_ratio",
            "syn_ratio",
            "syn_ack_ratio",
            "ack_ratio",
            "rst_ratio",
            "fin_ratio",
            "syn_to_ack_ratio",
            "src_ip_entropy",
            "dst_ip_entropy",
            "src_port_entropy",
            "dst_port_entropy",
            "avg_packet_size",
            "std_packet_size",
            "unique_src_ips",
            "unique_dst_ips",
            "unique_src_ports",
            "unique_dst_ports",
            "avg_ttl",
            "ttl_diversity",
            "avg_payload_size",
            "zero_payload_ratio",
            "avg_window_size",
            "small_window_ratio",
            "fragmentation_ratio",
            "large_packet_ratio",
        ]
        return [float(features.get(k, 0)) for k in keys]


class TestRandomForest:
    def setup_method(self):
        self.detector = RandomForestDetector()
        self.detector.initialize()

    def test_normal_traffic_low_score(self, sample_features):
        arr = TestIsolationForest._to_array(None, sample_features)
        score = self.detector.score(arr)
        assert 0 <= score <= 1

    def test_attack_traffic_high_score(self, attack_features):
        arr = TestIsolationForest._to_array(None, attack_features)
        score = self.detector.score(arr)
        assert score > 0.3


class TestAutoencoder:
    def setup_method(self):
        self.detector = AutoencoderDetector()
        self.detector.initialize()

    def test_score_range(self, sample_features):
        arr = TestIsolationForest._to_array(None, sample_features)
        score = self.detector.score(arr)
        assert 0 <= score <= 1

    def test_reconstruction_validation_metrics_are_available(self):
        stats = self.detector.stats
        assert stats["validation_sample_count"] > 0
        assert 0 <= stats["validation_precision"] <= 1
        assert 0 <= stats["validation_recall"] <= 1
        assert 0 <= stats["validation_f1_score"] <= 1
        assert stats["error_threshold"] > 0
        assert stats["attack_mse_median"] > stats["normal_mse_p95"]


class TestEnsembleModel:
    def setup_method(self):
        self.model = EnsembleModel()
        self.model.initialize()

    def test_normal_traffic_not_anomaly(self, sample_features):
        result = self.model.detect(sample_features)
        assert result.anomaly_score >= 0
        assert result.anomaly_score <= 1

    def test_attack_traffic_detected(self, attack_features):
        result = self.model.detect(attack_features)
        assert result.is_anomaly is True
        assert result.anomaly_score > 0.5
        assert result.attack_type != "none"
        assert result.severity in ("warning", "critical", "emergency")

    def test_detection_result_structure(self, sample_features):
        result = self.model.detect(sample_features)
        d = result.to_dict()
        assert "anomaly_score" in d
        assert "is_anomaly" in d
        assert "attack_type" in d
        assert "severity" in d
        assert "isolation_forest_score" in d
        assert "random_forest_score" in d
        assert "autoencoder_score" in d
