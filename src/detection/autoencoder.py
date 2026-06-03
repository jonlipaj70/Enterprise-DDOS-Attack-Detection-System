"""
Autoencoder Detector — Real sklearn Implementation
=====================================================
Deep anomaly detection using sklearn's MLPRegressor as a neural
autoencoder. Trains on normal traffic to learn reconstruction.
Anomalies produce high reconstruction error.
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


class AutoencoderDetector:
    """
    Real neural autoencoder using sklearn's MLPRegressor.

    Architecture: 30 → 64 → 16 → 64 → 30 (bottleneck autoencoder)
    Trains on NORMAL traffic only. Attack traffic produces high
    reconstruction error which becomes the anomaly score.

    Includes:
    - Proper StandardScaler normalization
    - Percentile-based threshold calibration
    - Reconstruction error distribution analysis
    """

    def __init__(
        self,
        input_dim: int = 30,
        latent_dim: int = 16,
        threshold_percentile: float = 97.0,
    ):
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.threshold_percentile = threshold_percentile

        self._model = None
        self._scaler = None
        self._initialized = False

        # Calibration parameters learned from training
        self._error_threshold = 0.5
        self._error_mean = 0.0
        self._error_std = 1.0
        self._normal_p95 = 0.0
        self._attack_p50 = 0.0
        self._validation_precision = 0.0
        self._validation_recall = 0.0
        self._validation_f1 = 0.0
        self._validation_sample_count = 0

        self.model_path = MODEL_DIR / "autoencoder.joblib"
        self.scaler_path = MODEL_DIR / "ae_scaler.joblib"
        self.metrics_path = MODEL_DIR / "ae_metrics.joblib"

    def initialize(self) -> None:
        """Initialize via cache if exists, otherwise train deeply and save."""
        MODEL_DIR.mkdir(exist_ok=True)

        if self.model_path.exists() and self.scaler_path.exists() and self.metrics_path.exists():
            try:
                logger.info("autoencoder_loading_cache")
                metrics = joblib.load(self.metrics_path)
                ensure_sklearn_cache_compatible(metrics, "autoencoder")
                self._model = joblib.load(self.model_path)
                self._scaler = joblib.load(self.scaler_path)

                self._error_threshold = metrics.get("error_threshold", 0.5)
                self._error_mean = metrics.get("error_mean", 0.0)
                self._error_std = metrics.get("error_std", 1.0)
                self._normal_p95 = metrics.get("normal_p95", 0.0)
                self._attack_p50 = metrics.get("attack_p50", 0.0)
                self._load_or_create_validation_metrics(metrics)

                self._initialized = True
                logger.info("autoencoder_ready_from_cache")
                return
            except Exception as e:
                logger.warning("cache_load_failed_retraining", error=str(e))
                self._model = None

        self._train_and_cache()

    def _train_and_cache(self) -> None:
        """Train the autoencoder on normal traffic data."""
        try:
            from sklearn.neural_network import MLPRegressor
            from sklearn.preprocessing import RobustScaler
            from sklearn.metrics import mean_squared_error

            from src.detection.training_data import generate_training_data

            logger.info("autoencoder_training_start")

            # Generate training data
            X, y, _ = generate_training_data(n_normal=8000, n_attack_per_type=1200, seed=42)

            # Scale features
            self._scaler = RobustScaler()
            X_scaled = self._scaler.fit_transform(X)

            # Split normal data for train/val
            X_normal = X_scaled[y == 0]
            X_attack = X_scaled[y == 1]

            n_normal = len(X_normal)
            split = int(n_normal * 0.85)
            X_train = X_normal[:split]
            X_val = X_normal[split:]

            # Train autoencoder (input → hidden → bottleneck → hidden → output)
            # MLPRegressor learns to reconstruct input from input
            self._model = MLPRegressor(
                hidden_layer_sizes=(64, self.latent_dim, 64),
                activation="relu",
                solver="adam",
                learning_rate="adaptive",
                learning_rate_init=0.001,
                max_iter=300,
                batch_size=128,
                early_stopping=True,
                validation_fraction=0.15,
                n_iter_no_change=15,
                random_state=42,
                verbose=False,
            )
            self._model.fit(X_train, X_train)  # Autoencoder: target = input

            # Calculate reconstruction errors on normal vs attack data
            normal_reconstructed = self._model.predict(X_val)
            normal_errors = np.mean((X_val - normal_reconstructed) ** 2, axis=1)

            attack_reconstructed = self._model.predict(X_attack)
            attack_errors = np.mean((X_attack - attack_reconstructed) ** 2, axis=1)

            # Calibration: learn the error distribution
            self._error_mean = float(np.mean(normal_errors))
            self._error_std = float(np.std(normal_errors))
            self._normal_p95 = float(np.percentile(normal_errors, 95))
            self._attack_p50 = float(np.percentile(attack_errors, 50))

            # Set threshold at the percentile of normal errors
            self._error_threshold = float(np.percentile(normal_errors, self.threshold_percentile))

            # Compute metrics
            all_errors = np.concatenate([normal_errors, attack_errors])
            all_labels = np.concatenate(
                [
                    np.zeros(len(normal_errors)),
                    np.ones(len(attack_errors)),
                ]
            )
            predictions = (all_errors > self._error_threshold).astype(int)

            tp = int(np.sum((predictions == 1) & (all_labels == 1)))
            fp = int(np.sum((predictions == 1) & (all_labels == 0)))
            fn = int(np.sum((predictions == 0) & (all_labels == 1)))
            tn = int(np.sum((predictions == 0) & (all_labels == 0)))

            precision = tp / max(tp + fp, 1)
            recall = tp / max(tp + fn, 1)
            f1 = 2 * precision * recall / max(precision + recall, 1e-6)

            # Separation quality metric
            separation = (self._attack_p50 - self._normal_p95) / max(self._error_std, 1e-6)

            logger.info(
                "autoencoder_trained",
                architecture=f"30→64→{self.latent_dim}→64→30",
                n_normal_train=len(X_train),
                n_normal_val=len(X_val),
                n_attack_test=len(X_attack),
                normal_mse_mean=round(self._error_mean, 6),
                normal_mse_p95=round(self._normal_p95, 6),
                attack_mse_median=round(self._attack_p50, 6),
                threshold=round(self._error_threshold, 6),
                separation_score=round(separation, 2),
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
                    "error_threshold": self._error_threshold,
                    "error_mean": self._error_mean,
                    "error_std": self._error_std,
                    "normal_p95": self._normal_p95,
                    "attack_p50": self._attack_p50,
                    **sklearn_cache_metadata(),
                },
                self.metrics_path,
            )
            self._load_or_create_validation_metrics(
                {
                    "error_threshold": self._error_threshold,
                    "error_mean": self._error_mean,
                    "error_std": self._error_std,
                    "normal_p95": self._normal_p95,
                    "attack_p50": self._attack_p50,
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
        reconstructed = self._model.predict(X_scaled)
        errors = np.mean((X_scaled - reconstructed) ** 2, axis=1)
        predictions = (errors > self._error_threshold).astype(np.int32)
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
        """Fallback without sklearn."""
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
            X_reconstructed = self._model.predict(X_scaled)
            mse = np.mean((X_scaled - X_reconstructed) ** 2, axis=1)
            z = (mse - self._error_threshold) / max(self._error_std, 1e-6)
            scores = 1.0 / (1.0 + np.exp(-2.5 * z))
            return np.clip(scores, 0.0, 1.0)
        else:
            return np.array([self._score_fallback(x.tolist()) for x in X])

    def score(self, feature_array: list[float]) -> float:
        """
        Score using reconstruction error.

        Returns:
            Score 0.0 (normal/well-reconstructed) to 1.0 (anomalous/high error)
        """
        if not self._initialized:
            self.initialize()

        if self._model is not None and self._scaler is not None:
            return self._score_sklearn(feature_array)
        else:
            return self._score_fallback(feature_array)

    def _score_sklearn(self, feature_array: list[float]) -> float:
        """Score using real autoencoder reconstruction error."""
        X = np.array(feature_array, dtype=np.float64).reshape(1, -1)

        expected = self._scaler.n_features_in_
        if X.shape[1] < expected:
            X = np.pad(X, ((0, 0), (0, expected - X.shape[1])))
        elif X.shape[1] > expected:
            X = X[:, :expected]

        X_scaled = self._scaler.transform(X)

        # Reconstruct
        X_reconstructed = self._model.predict(X_scaled)

        # Mean squared error per sample
        mse = float(np.mean((X_scaled - X_reconstructed) ** 2))

        # Map MSE to [0, 1] using calibrated sigmoid
        # Centered at the threshold, steep transition
        z = (mse - self._error_threshold) / max(self._error_std, 1e-6)
        score = 1.0 / (1.0 + np.exp(-2.5 * z))

        return float(min(1.0, max(0.0, score)))

    def _score_fallback(self, feature_array: list[float]) -> float:
        """Heuristic scoring without sklearn."""
        import math

        errors = []
        for i, val in enumerate(feature_array):
            if i < len(self._means) and self._stds[i] > 0:
                z = abs((val - self._means[i]) / self._stds[i])
                errors.append(z**1.5)
        if not errors:
            return 0.0
        sorted_e = sorted(errors, reverse=True)[:10]
        weighted = sum(e * (1.0 / (i + 1)) for i, e in enumerate(sorted_e))
        avg = sum(errors) / len(errors)
        combined = 0.5 * weighted / 5.0 + 0.5 * avg / 3.0
        return min(1.0, max(0.0, 1.0 / (1.0 + math.exp(-3.0 * (combined - 1.0)))))

    @property
    def stats(self) -> dict:
        return {
            "model": "Autoencoder (sklearn MLPRegressor)",
            "architecture": f"30→64→{self.latent_dim}→64→30",
            "initialized": self._initialized,
            "cached": self.model_path.exists(),
            "custom_parameters": "RobustScaler",
            "using_sklearn": self._model is not None,
            "error_threshold": round(self._error_threshold, 6),
            "normal_mse_mean": round(self._error_mean, 6),
            "normal_mse_p95": round(self._normal_p95, 6),
            "attack_mse_median": round(self._attack_p50, 6),
            "validation_precision": round(self._validation_precision, 4),
            "validation_recall": round(self._validation_recall, 4),
            "validation_f1_score": round(self._validation_f1, 4),
            "validation_sample_count": self._validation_sample_count,
        }
