"""Unit tests for the Feature Engineering pipeline."""
import pytest
from src.processing.feature_engine import FeatureEngine


class TestFeatureEngine:
    def setup_method(self):
        self.engine = FeatureEngine()

    def test_empty_packets(self):
        fv = self.engine.extract_features([])
        assert fv.packet_count == 0
        assert fv.packet_rate == 0.0

    def test_feature_extraction(self, sample_packets):
        fv = self.engine.extract_features(sample_packets, window_duration=1.0)
        assert fv.packet_count == len(sample_packets)
        assert fv.packet_rate > 0
        assert fv.byte_rate > 0
        assert 0 <= fv.tcp_ratio <= 1
        assert fv.unique_src_ips >= 1

    def test_feature_array_length(self, sample_packets):
        fv = self.engine.extract_features(sample_packets)
        arr = fv.to_feature_array()
        assert len(arr) == 30  # 30 features

    def test_entropy_calculation(self):
        values = ["a", "b", "c", "d"]
        entropy = FeatureEngine._entropy(values)
        assert entropy == 2.0  # log2(4)

    def test_entropy_single_value(self):
        values = ["a", "a", "a"]
        entropy = FeatureEngine._entropy(values)
        assert entropy == 0.0

    def test_attack_features_differ(self, sample_packets, attack_packets):
        normal_fv = self.engine.extract_features(sample_packets)
        attack_fv = self.engine.extract_features(attack_packets)

        # Attack should have significantly different characteristics
        assert attack_fv.syn_ratio > normal_fv.syn_ratio
        assert attack_fv.unique_src_ips > normal_fv.unique_src_ips
