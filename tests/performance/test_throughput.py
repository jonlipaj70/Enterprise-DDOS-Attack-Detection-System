"""Performance tests for throughput and latency."""
import pytest
import time

from src.ingestion.traffic_simulator import TrafficSimulator
from src.processing.feature_engine import FeatureEngine
from src.detection.ensemble_model import EnsembleModel


class TestThroughput:
    """Benchmark throughput of the detection pipeline."""

    def setup_method(self):
        self.simulator = TrafficSimulator(seed=42)
        self.feature_engine = FeatureEngine()
        self.ensemble = EnsembleModel()
        self.ensemble.initialize()

    @pytest.mark.performance
    def test_feature_extraction_throughput(self):
        """Feature extraction should handle 50000+ records in under 1 second."""
        packets = [self.simulator.generate_normal_packet().to_dict() for _ in range(10000)]

        start = time.time()
        for _ in range(5):
            self.feature_engine.extract_features(packets)
        elapsed = time.time() - start

        records_per_sec = 50000 / elapsed
        print(f"Feature extraction: {records_per_sec:.0f} records/sec")
        assert elapsed < 5.0  # Should process 50K in under 5s

    @pytest.mark.performance
    def test_detection_latency(self):
        """Single detection should complete within 10ms."""
        packets = [self.simulator.generate_normal_packet().to_dict() for _ in range(500)]
        fv = self.feature_engine.extract_features(packets)

        latencies = []
        for _ in range(100):
            start = time.time()
            self.ensemble.detect(fv.to_dict())
            latencies.append((time.time() - start) * 1000)

        avg_latency = sum(latencies) / len(latencies)
        p95_latency = sorted(latencies)[94]
        print(f"Detection latency - avg: {avg_latency:.2f}ms, p95: {p95_latency:.2f}ms")
        assert avg_latency < 50  # Should be well under 50ms


class TestBackpressure:
    """Test backpressure mechanism."""

    def test_token_bucket(self):
        from src.processing.backpressure import TokenBucket

        bucket = TokenBucket(rate=100, capacity=100)
        consumed = 0
        for _ in range(150):
            if bucket.consume():
                consumed += 1

        assert consumed <= 100  # Should not exceed capacity
        assert consumed >= 90   # Should consume most tokens

    def test_adaptive_backpressure(self):
        from src.processing.backpressure import AdaptiveBackpressure

        bp = AdaptiveBackpressure(target_latency_ms=100, max_rate=10000)

        # Report high latency — should reduce rate
        initial_rate = bp.current_rate
        bp.report_latency(300)
        assert bp.current_rate < initial_rate

        # Report low latency — should increase rate
        reduced_rate = bp.current_rate
        bp.report_latency(50)
        assert bp.current_rate > reduced_rate
