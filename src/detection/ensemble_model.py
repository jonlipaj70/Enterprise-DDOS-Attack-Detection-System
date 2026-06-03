"""
Ensemble Detection Model — Real sklearn Implementation
=========================================================
Ensemble that combines three sklearn model scores with a stacking
meta-learner, fallback weighting, and attack fingerprint classification.
"""

from __future__ import annotations

import math
import time
import numpy as np
from dataclasses import dataclass, field
from typing import Any, Optional

from src.config.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class DetectionResult:
    """Result of ensemble detection."""
    timestamp: float
    is_anomaly: bool
    anomaly_score: float  # 0.0 to 1.0
    confidence: float     # 0.0 to 1.0
    attack_type: str
    severity: str  # info, warning, critical, emergency

    # Individual model scores
    isolation_forest_score: float = 0.0
    gradient_boosting_score: float = 0.0
    autoencoder_score: float = 0.0

    # Contributing features
    top_features: list[tuple[str, float]] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "is_anomaly": self.is_anomaly,
            "anomaly_score": round(self.anomaly_score, 4),
            "confidence": round(self.confidence, 4),
            "attack_type": self.attack_type,
            "severity": self.severity,
            "isolation_forest_score": round(self.isolation_forest_score, 4),
            "gradient_boosting_score": round(self.gradient_boosting_score, 4),
            # Legacy response field retained for clients using the previous model label.
            "random_forest_score": round(self.gradient_boosting_score, 4),
            "autoencoder_score": round(self.autoencoder_score, 4),
            "top_features": [(f, round(s, 4)) for f, s in self.top_features],
            "details": self.details,
            "expert_analysis": self._get_expert_analysis(),
        }

    def _get_expert_analysis(self) -> dict:
        """Enrich threat with SOC expert details."""
        analysis = {
            "syn_flood": {
                "mitre_id": "T1498.001",
                "osi_layer": "Layer 4 (Transport)",
                "description": "State exhaustion attack targeting TCP handshake queue.",
                "mitigation": "Enable SYN cookies, aggressive timeout for half-open connections."
            },
            "dns_amplification": {
                "mitre_id": "T1498.002",
                "osi_layer": "Layer 3/4 (Network/Transport)",
                "description": "Reflective volumetric attack using open DNS resolvers.",
                "mitigation": "Rate-limit DNS responses, deploy BCP38 anti-spoofing filters."
            },
            "udp_flood": {
                "mitre_id": "T1498.002",
                "osi_layer": "Layer 4 (Transport)",
                "description": "Bandwidth saturation via random UDP port spam.",
                "mitigation": "Block non-standard UDP ports, implement strict rate limits."
            },
            "http_flood": {
                "mitre_id": "T1499.004",
                "osi_layer": "Layer 7 (Application)",
                "description": "Resource exhaustion via valid HTTP GET/POST requests.",
                "mitigation": "Implement WAF JS-challenges, rate-limit per source context."
            },
            "slowloris": {
                "mitre_id": "T1499.002",
                "osi_layer": "Layer 7 (Application)",
                "description": "Low-bandwidth attack holding connection slots open with partial requests.",
                "mitigation": "Deploy reverse proxy buffer limits, set strict Request-Header timeouts."
            },
            "icmp_flood": {
                "mitre_id": "T1498.001",
                "osi_layer": "Layer 3 (Network)",
                "description": "Volumetric ping flood aiming to consume bandwidth.",
                "mitigation": "Drop all inbound ICMP Echo Requests at perimeter firewall."
            }
        }
        return analysis.get(self.attack_type, {
            "mitre_id": "Unknown",
            "osi_layer": "Multiple or Unknown",
            "description": "Anomalous traffic pattern detected without a specific known signature.",
            "mitigation": "Review Top Features in Forensics Panel. Isolate IP ranges."
        })


# ─── Attack fingerprints ─────────────────────────────────────
ATTACK_FINGERPRINTS = [
    {
        "name": "syn_flood",
        "conditions": [
            ("syn_ratio", ">", 0.25), ("zero_payload_ratio", ">", 0.30),
            ("unique_src_ips", ">", 30),
        ],
        "priority": 10,
    },
    {
        "name": "dns_amplification",
        "conditions": [
            ("dns_ratio", ">", 0.12), ("avg_packet_size", ">", 600),
        ],
        "priority": 9,
    },
    {
        "name": "udp_flood",
        "conditions": [
            ("udp_ratio", ">", 0.35), ("packet_rate", ">", 6000),
        ],
        "priority": 8,
    },
    {
        "name": "http_flood",
        "conditions": [
            ("tcp_ratio", ">", 0.70), ("unique_src_ips", ">", 60),
            ("src_ip_entropy", ">", 4.5),
        ],
        "priority": 7,
    },
    {
        "name": "slowloris",
        "conditions": [
            ("avg_packet_size", "<", 80), ("avg_payload_size", "<", 30),
            ("tcp_ratio", ">", 0.70),
        ],
        "priority": 6,
    },
    {
        "name": "icmp_flood",
        "conditions": [
            ("icmp_ratio", ">", 0.15), ("packet_rate", ">", 5000),
        ],
        "priority": 5,
    },
]


class EnsembleModel:
    """
    Ensemble DDoS detector combining:
    1. IsolationForest (sklearn) — unsupervised anomaly detection
    2. HistGradientBoostingClassifier (sklearn) — supervised classification
    3. Autoencoder (sklearn MLPRegressor) — reconstruction error

    With:
    - Stacking meta-learner for optimal model combination
    - Majority voting + probability calibration
    - Temporal smoothing for sustained attacks
    """

    def __init__(
        self,
        weights: Optional[list[float]] = None,
        anomaly_threshold: float = 0.45,
    ):
        self.base_weights = weights or [0.30, 0.40, 0.30]
        self.anomaly_threshold = anomaly_threshold

        from src.detection.isolation_forest import IsolationForestDetector
        from src.detection.gradient_boosting import GradientBoostingDetector
        from src.detection.autoencoder import AutoencoderDetector

        self.isolation_forest = IsolationForestDetector()
        self.gradient_boosting = GradientBoostingDetector()
        self.autoencoder = AutoencoderDetector()

        import joblib
        from pathlib import Path
        Path("models").mkdir(exist_ok=True)
        self.stacking_path = Path("models/stacking.joblib")
        self.stacking_metrics_path = Path("models/stacking_metrics.joblib")

        self._stacking_model = None
        self._detection_count = 0
        self._anomaly_count = 0
        self._initialized = False

        # Running state
        self._score_history: list[float] = []
        self._previous_score: float = 0.0
        self._stacking_accuracy = 0.0

    def initialize(self) -> None:
        """Initialize all sub-models and optionally train stacking meta-learner."""
        self.isolation_forest.initialize()
        self.gradient_boosting.initialize()
        self.autoencoder.initialize()

        # Train stacking meta-learner
        self._train_stacking()

        self._initialized = True
        logger.info(
            "ensemble_model_initialized",
            weights=self.base_weights,
            stacking_accuracy=round(self._stacking_accuracy, 4),
        )

    def _train_stacking(self):
        """Train or load the logistic regression meta-learner."""
        import joblib
        if self.stacking_path.exists() and self.stacking_metrics_path.exists():
            try:
                self._stacking_model = joblib.load(self.stacking_path)
                metrics = joblib.load(self.stacking_metrics_path)
                self._stacking_accuracy = metrics.get('accuracy', 0.0)
                logger.info("stacking_meta_learner_loaded_from_cache", accuracy=self._stacking_accuracy)
                return
            except Exception as e:
                logger.warning("stacking_cache_failed", error=str(e))

        try:
            from sklearn.linear_model import LogisticRegression
            from sklearn.metrics import accuracy_score, f1_score
            from src.detection.training_data import generate_training_data

            logger.info("stacking_meta_learner_training_start")

            X, y, _ = generate_training_data(n_normal=3000, n_attack_per_type=500, seed=99)

            if_scores = self.isolation_forest.score_batch(X)
            gb_scores = self.gradient_boosting.score_batch(X)
            ae_scores = self.autoencoder.score_batch(X)

            X_meta = np.column_stack([if_scores, gb_scores, ae_scores])

            n = len(X_meta)
            split = int(n * 0.8)
            idx = np.random.RandomState(99).permutation(n)
            X_train, X_test = X_meta[idx[:split]], X_meta[idx[split:]]
            y_train, y_test = y[idx[:split]], y[idx[split:]]

            self._stacking_model = LogisticRegression(
                C=10.0, max_iter=1000, class_weight="balanced", random_state=42
            )
            self._stacking_model.fit(X_train, y_train)

            y_pred = self._stacking_model.predict(X_test)
            self._stacking_accuracy = float(accuracy_score(y_test, y_pred))
            f1 = float(f1_score(y_test, y_pred, average="weighted"))
            
            joblib.dump(self._stacking_model, self.stacking_path)
            joblib.dump({'accuracy': self._stacking_accuracy}, self.stacking_metrics_path)

            logger.info(
                "stacking_meta_learner_trained",
                accuracy=round(self._stacking_accuracy, 4),
                f1_score=round(f1, 4),
            )

        except Exception as e:
            logger.warning("stacking_training_failed", error=str(e))
            self._stacking_model = None

    @property
    def weights(self) -> list[float]:
        return self.base_weights

    def detect(self, features: dict[str, Any]) -> DetectionResult:
        """
        Run ultimate-precision ensemble detection.

        Pipeline:
        1. Score with each real sklearn model
        2. Stacking meta-learner combines scores
        3. Majority voting analysis
        4. Temporal smoothing
        5. Attack fingerprint classification
        6. Confidence calibration
        """
        if not self._initialized:
            self.initialize()

        feature_array = self._extract_feature_array(features)

        # ── Step 1: Individual Model Scores ──
        if_score = self.isolation_forest.score(feature_array)
        gb_score = self.gradient_boosting.score(feature_array)
        ae_score = self.autoencoder.score(feature_array)

        # ── Step 2: Stacking Meta-Learner ──
        if self._stacking_model is not None:
            meta_input = np.array([[if_score, gb_score, ae_score]])
            stacking_proba = self._stacking_model.predict_proba(meta_input)[0]
            ensemble_score = float(stacking_proba[1]) if len(stacking_proba) > 1 else 0.0
        else:
            # Fallback: weighted average
            ensemble_score = (
                self.base_weights[0] * if_score +
                self.base_weights[1] * gb_score +
                self.base_weights[2] * ae_score
            )

        # ── Step 3: Majority Voting Adjustment ──
        scores = [if_score, gb_score, ae_score]
        models_above = sum(1 for s in scores if s >= 0.45)

        # All 3 models agree on attack → strong boost
        if models_above == 3 and ensemble_score > 0.3:
            ensemble_score = min(1.0, ensemble_score + 0.05)

        # Only 1 model flags → penalize (reduce false positives)
        if models_above == 1 and ensemble_score > 0.35:
            ensemble_score *= 0.80

        # No models flag → strong reduction
        if models_above == 0:
            ensemble_score *= 0.5

        # ── Step 4: Temporal Smoothing ──
        if self._previous_score > 0.4 and ensemble_score > 0.4:
            # Sustained anomaly — slight reinforcement
            ensemble_score = min(1.0, ensemble_score + 0.02)

        fingerprint_attack = self._match_attack_fingerprint(features)
        if fingerprint_attack != "unknown" and models_above >= 2:
            ensemble_score = max(ensemble_score, self.anomaly_threshold + 0.05)

        self._previous_score = ensemble_score

        # ── Step 5: Classification ──
        is_anomaly = ensemble_score >= self.anomaly_threshold

        attack_type = self._classify_attack(features, ensemble_score)
        severity = self._classify_severity(ensemble_score, models_above)

        # ── Step 6: Confidence ──
        confidence = self._compute_confidence(scores, ensemble_score, models_above)

        top_features = self._get_top_features(features)

        self._detection_count += 1
        if is_anomaly:
            self._anomaly_count += 1

        self._score_history.append(ensemble_score)
        if len(self._score_history) > 200:
            self._score_history = self._score_history[-200:]

        return DetectionResult(
            timestamp=time.time(),
            is_anomaly=is_anomaly,
            anomaly_score=ensemble_score,
            confidence=confidence,
            attack_type=attack_type,
            severity=severity,
            isolation_forest_score=if_score,
            gradient_boosting_score=gb_score,
            autoencoder_score=ae_score,
            top_features=top_features,
            details={
                "packet_rate": features.get("packet_rate", 0),
                "byte_rate": features.get("byte_rate", 0),
                "unique_src_ips": features.get("unique_src_ips", 0),
                "syn_ratio": features.get("syn_ratio", 0),
                "udp_ratio": features.get("udp_ratio", 0),
                "models_agreeing": models_above,
                "using_stacking": self._stacking_model is not None,
            },
        )

    def _classify_attack(self, features: dict[str, Any], score: float) -> str:
        """Multi-criteria attack fingerprint matching."""
        if score < self.anomaly_threshold:
            return "none"

        return self._match_attack_fingerprint(features)

    def _match_attack_fingerprint(self, features: dict[str, Any]) -> str:
        """Return the first matching known attack fingerprint."""
        for fp in ATTACK_FINGERPRINTS:
            all_match = True
            for feat_name, op, threshold in fp["conditions"]:
                value = features.get(feat_name, 0)
                if op == ">" and value <= threshold:
                    all_match = False
                    break
                elif op == "<" and value >= threshold:
                    all_match = False
                    break
            if all_match:
                return fp["name"]

        return "unknown"

    def _classify_severity(self, score: float, models_above: int) -> str:
        """Agreement-adjusted severity classification."""
        boost = models_above * 0.02  # More agreement → lower thresholds
        if score >= (0.88 - boost):
            return "emergency"
        if score >= (0.72 - boost):
            return "critical"
        if score >= self.anomaly_threshold:
            return "warning"
        return "info"

    def _compute_confidence(
        self, scores: list[float], ensemble_score: float, models_above: int
    ) -> float:
        """Calibrated confidence from model agreement and score magnitude."""
        spread = max(scores) - min(scores)
        agreement = 1.0 - min(spread, 1.0)

        boundary_dist = abs(ensemble_score - self.anomaly_threshold)

        conf = (
            agreement * 0.40 +
            min(0.30, boundary_dist * 0.5) +
            (models_above / 3.0) * 0.30
        )
        return min(1.0, max(0.05, conf))

    def _extract_feature_array(self, features: dict[str, Any]) -> list[float]:
        """Extract ordered feature array from dict."""
        feature_names = [
            "packet_rate", "byte_rate",
            "tcp_ratio", "udp_ratio", "icmp_ratio", "dns_ratio",
            "syn_ratio", "syn_ack_ratio", "ack_ratio", "rst_ratio",
            "fin_ratio", "syn_to_ack_ratio",
            "src_ip_entropy", "dst_ip_entropy",
            "src_port_entropy", "dst_port_entropy",
            "avg_packet_size", "std_packet_size",
            "unique_src_ips", "unique_dst_ips",
            "unique_src_ports", "unique_dst_ports",
            "avg_ttl", "ttl_diversity",
            "avg_payload_size", "zero_payload_ratio",
            "avg_window_size", "small_window_ratio",
            "fragmentation_ratio", "large_packet_ratio",
        ]
        return [float(features.get(name, 0.0)) for name in feature_names]

    def _get_top_features(self, features: dict[str, Any]) -> list[tuple[str, float]]:
        """Get the most anomalous features with z-score deviation."""
        baselines = {
            "packet_rate": (5000, 1500), "byte_rate": (2500000, 750000),
            "syn_ratio": (0.08, 0.04), "syn_to_ack_ratio": (0.20, 0.08),
            "udp_ratio": (0.20, 0.06), "dns_ratio": (0.10, 0.03),
            "src_ip_entropy": (3.5, 0.8), "unique_src_ips": (40, 12),
            "avg_packet_size": (500, 120), "zero_payload_ratio": (0.12, 0.06),
            "small_window_ratio": (0.04, 0.02), "large_packet_ratio": (0.08, 0.03),
        }
        deviations = []
        for name, (mean, std) in baselines.items():
            value = features.get(name, 0)
            if std > 0:
                z = abs(value - mean) / std
                deviations.append((name, round(z, 2)))
        deviations.sort(key=lambda x: x[1], reverse=True)
        return deviations[:6]

    @property
    def stats(self) -> dict:
        anomaly_rate = self._anomaly_count / max(self._detection_count, 1) * 100
        avg_score = 0.0
        if self._score_history:
            avg_score = sum(self._score_history[-50:]) / len(self._score_history[-50:])
        return {
            "detection_count": self._detection_count,
            "anomaly_count": self._anomaly_count,
            "anomaly_rate_pct": round(anomaly_rate, 2),
            "weights": self.base_weights,
            "threshold": self.anomaly_threshold,
            "avg_recent_score": round(avg_score, 4),
            "stacking_accuracy": round(self._stacking_accuracy, 4),
            "using_stacking": self._stacking_model is not None,
        }
