"""Integration tests for the full detection pipeline."""
import pytest
import asyncio
import time

from src.ingestion.traffic_simulator import TrafficSimulator, AttackType
from src.processing.feature_engine import FeatureEngine
from src.processing.window_aggregator import WindowAggregator
from src.detection.ensemble_model import EnsembleModel
from src.alerting.alert_engine import AlertEngine


class TestFullPipeline:
    """Test the complete detection pipeline end-to-end."""

    def setup_method(self):
        self.simulator = TrafficSimulator(seed=42)
        self.feature_engine = FeatureEngine()
        self.window_aggregator = WindowAggregator()
        self.ensemble = EnsembleModel()
        self.alert_engine = AlertEngine(dedup_window_seconds=1)
        self.ensemble.initialize()

    def test_normal_traffic_no_alerts(self):
        """Normal traffic should not generate alerts."""
        packets = [self.simulator.generate_normal_packet() for _ in range(500)]
        packet_dicts = [p.to_dict() for p in packets]

        features = self.window_aggregator.ingest(packet_dicts)
        fv = features.get("1s")
        assert fv is not None

        result = self.ensemble.detect(fv.to_dict())
        # Normal traffic should generally not be anomalous
        assert result.anomaly_score < 0.8

    def test_syn_flood_detected(self):
        """SYN flood attack should be detected with high score."""
        attack_packets = [
            self.simulator.generate_attack_packet(AttackType.SYN_FLOOD)
            for _ in range(1000)
        ]
        packet_dicts = [p.to_dict() for p in attack_packets]

        fv = self.feature_engine.extract_features(packet_dicts)
        result = self.ensemble.detect(fv.to_dict())

        assert result.is_anomaly is True
        assert result.anomaly_score > 0.5
        assert result.attack_type in ("syn_flood", "unknown")

    def test_dns_amplification_detected(self):
        """DNS amplification should be detected."""
        attack_packets = [
            self.simulator.generate_attack_packet(AttackType.DNS_AMPLIFICATION)
            for _ in range(500)
        ]
        packet_dicts = [p.to_dict() for p in attack_packets]

        fv = self.feature_engine.extract_features(packet_dicts)
        result = self.ensemble.detect(fv.to_dict())

        assert result.is_anomaly is True
        assert result.anomaly_score > 0.4

    def test_alert_created_from_detection(self):
        """Detection result should create an alert."""
        attack_packets = [
            self.simulator.generate_attack_packet(AttackType.SYN_FLOOD)
            for _ in range(1000)
        ]
        packet_dicts = [p.to_dict() for p in attack_packets]

        fv = self.feature_engine.extract_features(packet_dicts)
        result = self.ensemble.detect(fv.to_dict())

        if result.is_anomaly:
            alert = self.alert_engine.create_alert(result.to_dict())
            assert alert is not None
            assert alert.severity.value in ("warning", "critical", "emergency")
            assert len(alert.alert_id) > 0

    def test_pipeline_stats(self):
        """Pipeline components should track statistics."""
        packets = [self.simulator.generate_normal_packet() for _ in range(200)]
        packet_dicts = [p.to_dict() for p in packets]

        self.window_aggregator.ingest(packet_dicts)
        stats = self.window_aggregator.stats
        assert stats["aggregation_count"] == 1

        fe_stats = self.feature_engine.stats
        assert fe_stats["features_extracted"] >= 0


class TestSerializationRoundtrip:
    """Test packet serialization / deserialization."""

    def test_json_roundtrip(self):
        from src.ingestion.serialization import PacketSerializer

        serializer = PacketSerializer(format="json")
        packet = {
            "timestamp": time.time(),
            "src_ip": "10.0.1.50",
            "dst_ip": "10.0.1.100",
            "src_port": 45678,
            "dst_port": 80,
            "protocol": 6,
            "packet_size": 512,
            "ttl": 64,
            "flags": 16,
            "payload_size": 472,
            "fragment_offset": 0,
            "sequence_number": 12345,
            "ack_number": 67890,
            "window_size": 65535,
            "checksum": 0,
        }

        data = serializer.serialize(packet)
        result = serializer.deserialize(data)
        assert result["src_ip"] == packet["src_ip"]
        assert result["dst_port"] == packet["dst_port"]

    def test_binary_roundtrip(self):
        from src.ingestion.serialization import PacketSerializer

        serializer = PacketSerializer(format="binary")
        packet = {
            "timestamp": time.time(),
            "src_ip": "10.0.1.50",
            "dst_ip": "10.0.1.100",
            "src_port": 45678,
            "dst_port": 80,
            "protocol": 6,
            "packet_size": 512,
            "ttl": 64,
            "flags": 16,
            "payload_size": 472,
            "fragment_offset": 0,
            "sequence_number": 12345,
            "ack_number": 67890,
            "window_size": 65535,
            "checksum": 0,
        }

        data = serializer.serialize(packet)
        result = serializer.deserialize(data)
        assert result["src_ip"] == packet["src_ip"]
        assert result["dst_port"] == packet["dst_port"]


class TestSchemaRegistry:
    """Test schema registry operations."""

    def test_register_and_get(self):
        from src.ingestion.schema_registry import SchemaRegistry
        from src.ingestion.serialization import PACKET_SCHEMA

        registry = SchemaRegistry()
        schema_id = registry.register_schema("raw-packets-value", PACKET_SCHEMA)
        assert schema_id > 0

        schema = registry.get_schema(schema_id)
        assert schema is not None
        assert schema["name"] == "NetworkPacket"

    def test_duplicate_registration(self):
        from src.ingestion.schema_registry import SchemaRegistry
        from src.ingestion.serialization import PACKET_SCHEMA

        registry = SchemaRegistry()
        id1 = registry.register_schema("test", PACKET_SCHEMA)
        id2 = registry.register_schema("test", PACKET_SCHEMA)
        assert id1 == id2  # Same schema returns same ID
