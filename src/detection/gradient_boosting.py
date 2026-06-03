"""
Gradient Boosting Detector — Optimized Iteration
==================================================
Production-grade supervised DDoS classification using scikit-learn's
HistGradientBoostingClassifier. Integrates RobustScaler for extreme 
anomaly handling and joblib persistence for instantaneous zero-latency startup
after the initial deep-calculation training session.
"""

from __future__ import annotations

import os
import math
import numpy as np
import joblib
from pathlib import Path

from src.config.logging_config import get_logger

logger = get_logger(__name__)

# Directory to save models for instant loading
MODEL_DIR = Path("models")


class GradientBoostingDetector:
    """
    Advanced Gradient Boosting classifier for supervised DDoS detection.

    - Uses LightGBM-style HistGradientBoosting for maximum computational depth
    - Implements RobustScaler to mitigate outlier distortions
    - Highly accelerated initial startup via model caching
    """

    def __init__(self, max_iter: int = 400, max_depth: int = 25):
        self.max_iter = max_iter
        self.max_depth = max_depth
        self._model = None
        self._scaler = None
        self._initialized = False
        self._feature_importances: list[float] = [] # Approximated for GB
        self._accuracy = 0.0
        self._f1 = 0.0
        
        self.model_path = MODEL_DIR / "gradient_boosting.joblib"
        self.scaler_path = MODEL_DIR / "gb_scaler.joblib"
        self.metrics_path = MODEL_DIR / "gb_metrics.joblib"

    def initialize(self) -> None:
        """Initialize via cache if exists, otherwise train deeply and save."""
        MODEL_DIR.mkdir(exist_ok=True)
        
        if self.model_path.exists() and self.scaler_path.exists() and self.metrics_path.exists():
            try:
                logger.info("gradient_boosting_loading_cache")
                self._model = joblib.load(self.model_path)
                self._scaler = joblib.load(self.scaler_path)
                metrics = joblib.load(self.metrics_path)
                
                self._accuracy = metrics.get('accuracy', 0.0)
                self._f1 = metrics.get('f1', 0.0)
                self._feature_importances = metrics.get('feature_importances', [0.1]*30)
                self._initialized = True
                
                logger.info("gradient_boosting_ready_from_cache", accuracy=self._accuracy)
                return
            except Exception as e:
                logger.warning("cache_load_failed_retraining", error=str(e))
                self._model = None

        self._train_and_cache()

    def _train_and_cache(self) -> None:
        """Perform deep calculation training and disk caching."""
        try:
            from sklearn.ensemble import HistGradientBoostingClassifier
            from sklearn.preprocessing import RobustScaler
            from sklearn.metrics import accuracy_score, f1_score
            from src.detection.training_data import generate_training_data

            logger.info("gradient_boosting_deep_training_start")

            # Emphasize depth and difficulty (increased samples for deeper pattern extraction)
            X, y, y_type = generate_training_data(n_normal=10000, n_attack_per_type=1500, seed=42)

            # Robust scaling mitigates extreme 
            self._scaler = RobustScaler()
            X_scaled = self._scaler.fit_transform(X)

            # Split (80/20)
            n = len(X_scaled)
            split = int(n * 0.8)
            indices = np.random.RandomState(42).permutation(n)
            train_idx, test_idx = indices[:split], indices[split:]

            X_train, X_test = X_scaled[train_idx], X_scaled[test_idx]
            y_train, y_test = y[train_idx], y[test_idx]

            # Deep Gradient Boosting Computation parameters (LightGBM equivalent natively)
            self._model = HistGradientBoostingClassifier(
                max_iter=self.max_iter,
                max_depth=self.max_depth,
                l2_regularization=0.5, # Constrain to prevent overfitting
                learning_rate=0.08,
                max_leaf_nodes=63,
                class_weight="balanced",
                random_state=42,
            )
            self._model.fit(X_train, y_train)

            # Evaluate
            y_pred = self._model.predict(X_test)
            self._accuracy = float(accuracy_score(y_test, y_pred))
            self._f1 = float(f1_score(y_test, y_pred, average="weighted"))

            # Calculate proxy feature importances via standard deviation impact
            # (HistGB doesn't natively expose feature_importances_, proxy heuristic)
            self._feature_importances = (np.std(X_train, axis=0) * 0.1).tolist()
            
            # Persist to disk instantly
            joblib.dump(self._model, self.model_path)
            joblib.dump(self._scaler, self.scaler_path)
            joblib.dump({
                'accuracy': self._accuracy, 
                'f1': self._f1, 
                'feature_importances': self._feature_importances
            }, self.metrics_path)

            logger.info(
                "gradient_boosting_trained_and_cached",
                accuracy=round(self._accuracy, 4),
                f1_score=round(self._f1, 4),
                iterations=self._model.n_iter_
            )
            self._initialized = True

        except ImportError:
            logger.warning("sklearn_not_available_crashing")
            raise

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
            probas = self._model.predict_proba(X_scaled)
            if probas.shape[1] > 1:
                return np.clip(probas[:, 1], 0.0, 1.0)
            return np.zeros(len(X))
        return np.zeros(len(X))

    def score(self, feature_array: list[float]) -> float:
        """Secure probability scoring."""
        if not self._initialized:
            self.initialize()

        if self._model is not None and self._scaler is not None:
            X = np.array(feature_array, dtype=np.float64).reshape(1, -1)
            expected = self._scaler.n_features_in_
            if X.shape[1] < expected:
                X = np.pad(X, ((0, 0), (0, expected - X.shape[1])))
            elif X.shape[1] > expected:
                X = X[:, :expected]

            X_scaled = self._scaler.transform(X)
            proba = self._model.predict_proba(X_scaled)[0]
            attack_prob = float(proba[1]) if len(proba) > 1 else 0.0
            return min(1.0, max(0.0, attack_prob))
        return 0.0

    @property
    def stats(self) -> dict:
        return {
            "model": "GradientBoosting (sklearn)",
            "max_iter": self.max_iter,
            "max_depth": self.max_depth,
            "initialized": self._initialized,
            "cached": self.model_path.exists(),
            "custom_parameters": "RobustScaler + L2 Regularization",
            "accuracy": round(self._accuracy, 4),
            "f1_score": round(self._f1, 4),
        }
