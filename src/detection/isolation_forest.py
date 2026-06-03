"""
Isolation Forest Detector — Real sklearn Implementation
=========================================================
Production-grade unsupervised anomaly detection using scikit-learn's
IsolationForest with proper training, contamination tuning, and
feature-aware scoring.
"""

from __future__ import annotations

import numpy as np
import joblib
from pathlib import Path
from typing import Optional

from src.config.logging_config import get_logger
from src.detection.cache_metadata import (
    ensure_sklearn_cache_compatible,
    sklearn_cache_metadata,
)

logger = get_logger(__name__)

# Directory to save models for instant loading
MODEL_DIR = Path("models")
VALIDATION_VERSION = 1
VALIDATION_SEED = 314


class IsolationForestDetector:
    """
    Real sklearn IsolationForest anomaly detector.

    - Trains on synthetic normal + attack data
    - Uses decision_function for calibrated anomaly scores
    - Feature normalization with StandardScaler
    """

    def __init__(
        self,
        n_estimators: int = 200,
        contamination: float = 0.05,
        max_samples: int = 512,
    ):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.max_samples = max_samples

        self._model = None
        self._scaler = None
        self._initialized = False
        self._score_offset = 0.0
        self._score_scale = 1.0
        self._validation_precision = 0.0
        self._validation_recall = 0.0
        self._validation_f1 = 0.0
        self._validation_sample_count = 0

        self.model_path = MODEL_DIR / "isolation_forest.joblib"
        self.scaler_path = MODEL_DIR / "if_scaler.joblib"
        self.metrics_path = MODEL_DIR / "if_metrics.joblib"

    def initialize(self) -> None:
        """Initialize via cache if exists, otherwise train deeply and save."""
        MODEL_DIR.mkdir(exist_ok=True)

        if self.model_path.exists() and self.scaler_path.exists() and self.metrics_path.exists():
            try:
                logger.info("isolation_forest_loading_cache")
                metrics = joblib.load(self.metrics_path)
                ensure_sklearn_cache_compatible(metrics, "isolation_forest")
                self._model = joblib.load(self.model_path)
                self._scaler = joblib.load(self.scaler_path)

                self._score_offset = metrics.get("score_offset", 0.0)
                self._score_scale = metrics.get("score_scale", 1.0)
                self._load_or_create_validation_metrics(metrics)

                self._initialized = True
                logger.info("isolation_forest_ready_from_cache")
                return
            except Exception as e:
                logger.warning("cache_load_failed_retraining", error=str(e))
                self._model = None

        self._train_and_cache()

    def _train_and_cache(self) -> None:
        """Train the IsolationForest on synthetic normal data."""
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import RobustScaler

            from src.detection.training_data import generate_training_data

            logger.info("isolation_forest_training_start")

            # Generate training data — IF only sees normal data
            X, y, _ = generate_training_data(n_normal=5000, n_attack_per_type=800, seed=42)

            # Use all data for fitting (IF learns what's normal vs anomalous)
            self._scaler = RobustScaler()
            X_scaled = self._scaler.fit_transform(X)

            # Only fit on normal data for better anomaly boundary
            X_normal = X_scaled[y == 0]

            self._model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                max_samples=min(self.max_samples, len(X_normal)),
                random_state=42,
                n_jobs=-1,
            )
            self._model.fit(X_normal)

            # Calibrate score mapping from decision_function range to [0, 1]
            all_scores = self._model.decision_function(X_scaled)
            normal_scores = all_scores[y == 0]
            attack_scores = all_scores[y == 1]

            # decision_function: negative = anomaly, positive = normal
            self._score_offset = float(np.median(normal_scores))
            self._score_scale = float(np.std(normal_scores)) * 2.0

            # Log training metrics
            normal_pred = self._model.predict(X_normal)
            attack_pred = self._model.predict(X_scaled[y == 1])

            tp = int(np.sum(attack_pred == -1))
            fp = int(np.sum(normal_pred == -1))
            fn = int(np.sum(attack_pred == 1))
            tn = int(np.sum(normal_pred == 1))

            precision = tp / max(tp + fp, 1)
            recall = tp / max(tp + fn, 1)
            f1 = 2 * precision * recall / max(precision + recall, 1e-6)

            logger.info(
                "isolation_forest_trained",
                n_estimators=self.n_estimators,
                n_normal=len(X_normal),
                n_attack=int(np.sum(y == 1)),
                precision=round(precision, 4),
                recall=round(recall, 4),
                f1_score=round(f1, 4),
                tp=tp,
                fp=fp,
                fn=fn,
                tn=tn,
            )

            joblib.dump(self._model, self.model_path)
            joblib.dump(self._scaler, self.scaler_path)
            joblib.dump(
                {
                    "score_offset": self._score_offset,
                    "score_scale": self._score_scale,
                    **sklearn_cache_metadata(),
                },
                self.metrics_path,
            )
            self._load_or_create_validation_metrics(
                {
                    "score_offset": self._score_offset,
                    "score_scale": self._score_scale,
                    **sklearn_cache_metadata(),
                }
            )

            self._initialized = True

        except ImportError:
            logger.warning("sklearn_not_available_falling_back_to_heuristic")
            self._init_fallback()

    def _load_or_create_validation_metrics(self, metrics: dict) -> None:
        if metrics.get("validation_version") == VALIDATION_VERSION:
            self._validation_precision = float(metrics.get("validation_precision", 0.0))
            self._validation_recall = float(metrics.get("validation_recall", 0.0))
            self._validation_f1 = float(metrics.get("validation_f1", 0.0))
            self._validation_sample_count = int(metrics.get("validation_sample_count", 0))
            return

        from src.detection.training_data import generate_training_data

        X_validation, y_validation, _ = generate_training_data(
            n_normal=2000, n_attack_per_type=300, seed=VALIDATION_SEED
        )
        X_scaled = self._scaler.transform(X_validation)
        predictions = (self._model.predict(X_scaled) == -1).astype(np.int32)
        self._validation_precision, self._validation_recall, self._validation_f1 = (
            self._classification_metrics(y_validation, predictions)
        )
        self._validation_sample_count = len(y_validation)

        updated_metrics = dict(metrics)
        updated_metrics.update(
            {
                "validation_version": VALIDATION_VERSION,
                "validation_seed": VALIDATION_SEED,
                "validation_precision": self._validation_precision,
                "validation_recall": self._validation_recall,
                "validation_f1": self._validation_f1,
                "validation_sample_count": self._validation_sample_count,
            }
        )
        joblib.dump(updated_metrics, self.metrics_path)

    @staticmethod
    def _classification_metrics(
        y_true: np.ndarray, y_pred: np.ndarray
    ) -> tuple[float, float, float]:
        tp = int(np.sum((y_pred == 1) & (y_true == 1)))
        fp = int(np.sum((y_pred == 1) & (y_true == 0)))
        fn = int(np.sum((y_pred == 0) & (y_true == 1)))
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-6)
        return float(precision), float(recall), float(f1)

    def _init_fallback(self):
        """Fallback initialization without sklearn."""
        self._means = [
            5000,
            2500000,
            0.65,
            0.20,
            0.05,
            0.10,
            0.10,
            0.10,
            0.40,
            0.05,
            0.05,
            0.25,
            4.0,
            2.5,
            8.0,
            3.5,
            500,
            150,
            50,
            5,
            200,
            15,
            80,
            3,
            300,
            0.15,
            40000,
            0.05,
            0.01,
            0.10,
        ]
        self._stds = [
            1500,
            750000,
            0.12,
            0.08,
            0.02,
            0.04,
            0.06,
            0.04,
            0.12,
            0.02,
            0.02,
            0.10,
            1.2,
            0.8,
            2.5,
            1.2,
            150,
            60,
            15,
            2,
            80,
            6,
            15,
            1.0,
            120,
            0.08,
            12000,
            0.02,
            0.008,
            0.04,
        ]
        self._initialized = True

    def score_batch(self, X: np.ndarray) -> np.ndarray:
        """Batch score multiple samples (ultra fast for stacking)."""
        if not self._initialized:
            self.initialize()

        if self._model is not None and self._scaler is not None:
            expected = self._scaler.n_features_in_
            if X.shape[1] < expected:
                X = np.pad(X, ((0, 0), (0, expected - X.shape[1])))
            elif X.shape[1] > expected:
                X = X[:, :expected]

            X_scaled = self._scaler.transform(X)
            raw_scores = self._model.decision_function(X_scaled)
            calibrated = -(raw_scores - self._score_offset) / max(self._score_scale, 0.01)
            scores = 1.0 / (1.0 + np.exp(-3.0 * calibrated))
            return np.clip(scores, 0.0, 1.0)
        else:
            return np.array([self._score_fallback(x.tolist()) for x in X])

    def score(self, feature_array: list[float]) -> float:
        """
        Score a feature vector for anomalousness.

        Returns:
            Anomaly score between 0.0 (normal) and 1.0 (anomalous)
        """
        if not self._initialized:
            self.initialize()

        if self._model is not None and self._scaler is not None:
            return self._score_sklearn(feature_array)
        else:
            return self._score_fallback(feature_array)

    def _score_sklearn(self, feature_array: list[float]) -> float:
        """Score using real sklearn model."""
        import numpy as np

        X = np.array(feature_array, dtype=np.float64).reshape(1, -1)

        # Pad or truncate to expected dimensions
        expected = self._scaler.n_features_in_
        if X.shape[1] < expected:
            X = np.pad(X, ((0, 0), (0, expected - X.shape[1])))
        elif X.shape[1] > expected:
            X = X[:, :expected]

        X_scaled = self._scaler.transform(X)

        # decision_function: negative = anomaly, positive = normal
        raw_score = float(self._model.decision_function(X_scaled)[0])

        # Map to [0, 1]: more negative = higher anomaly score
        calibrated = -(raw_score - self._score_offset) / max(self._score_scale, 0.01)
        score = 1.0 / (1.0 + np.exp(-3.0 * calibrated))

        return float(min(1.0, max(0.0, score)))

    def _score_fallback(self, feature_array: list[float]) -> float:
        """Heuristic scoring when sklearn is not available."""
        import math

        deviations = []
        for i, val in enumerate(feature_array):
            if i < len(self._means) and self._stds[i] > 0:
                dev = abs((val - self._means[i]) / self._stds[i])
                deviations.append(dev)
        if not deviations:
            return 0.0
        avg = sum(deviations) / len(deviations)
        mx = max(deviations)
        combined = 0.6 * avg + 0.4 * mx
        return min(1.0, max(0.0, 1.0 / (1.0 + math.exp(-2.5 * (combined - 1.6)))))

    @property
    def stats(self) -> dict:
        return {
            "model": "IsolationForest (sklearn)",
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "initialized": self._initialized,
            "cached": self.model_path.exists(),
            "custom_parameters": "RobustScaler",
            "using_sklearn": self._model is not None,
            "validation_precision": round(self._validation_precision, 4),
            "validation_recall": round(self._validation_recall, 4),
            "validation_f1_score": round(self._validation_f1, 4),
            "validation_sample_count": self._validation_sample_count,
        }
