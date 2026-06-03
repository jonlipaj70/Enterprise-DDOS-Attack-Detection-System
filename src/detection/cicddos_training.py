"""Offline CICDDoS2019 flow-model training from uploaded CSV datasets."""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import time
import uuid
import zipfile
from collections import Counter
from pathlib import Path
from threading import Lock
from typing import Any

import joblib
import numpy as np
import pandas as pd

from src.config.logging_config import get_logger

logger = get_logger(__name__)

MODEL_KIND = "cicddos2019_flow_classifier"
DEFAULT_MODEL_TYPE = "hist_gradient_boosting"
AUTO_MODEL_TYPE = "auto"
SCHEMA_NOTE = (
    "Offline tabular flow classifier. It is not active in live packet-window detection "
    "until a compatible live feature extractor is implemented."
)
SUPPORTED_MODEL_TYPES = {
    AUTO_MODEL_TYPE: "Auto select best supported model",
    "hist_gradient_boosting": "Hist Gradient Boosting",
    "random_forest": "Random Forest",
    "extra_trees": "Extra Trees",
    "logistic_regression": "Logistic Regression",
    "linear_svm": "Linear SVM",
    "mlp": "Neural Network (MLP)",
    "gaussian_nb": "Gaussian Naive Bayes",
    "knn": "K-Nearest Neighbors",
}
AUTO_CANDIDATE_MODEL_TYPES = (
    "hist_gradient_boosting",
    "random_forest",
    "extra_trees",
    "logistic_regression",
    "linear_svm",
    "gaussian_nb",
    "knn",
)
SUPPORTED_CSV_ARCHIVE_SUFFIXES = (".csv", ".csv.gz", ".csv.bz2", ".csv.xz")
SUPPORTED_UPLOAD_SUFFIXES = (*SUPPORTED_CSV_ARCHIVE_SUFFIXES, ".zip")
MAX_NESTED_ZIP_DEPTH = 3
_TARGET_COLUMNS = {
    "label",
    "class",
    "target",
    "y",
    "outcome",
    "attack",
    "attacktype",
    "category",
    "result",
    "malicious",
    "isattack",
    "ddos",
}
_NORMAL_LABELS = {"BENIGN", "NORMAL"}
_MODEL_ALIASES = {
    "auto": AUTO_MODEL_TYPE,
    "best": AUTO_MODEL_TYPE,
    "hgb": "hist_gradient_boosting",
    "histgradientboosting": "hist_gradient_boosting",
    "histgradientboostingclassifier": "hist_gradient_boosting",
    "gradientboosting": "hist_gradient_boosting",
    "gb": "hist_gradient_boosting",
    "rf": "random_forest",
    "randomforest": "random_forest",
    "randomforestclassifier": "random_forest",
    "extra": "extra_trees",
    "extratrees": "extra_trees",
    "extratreesclassifier": "extra_trees",
    "logreg": "logistic_regression",
    "logistic": "logistic_regression",
    "logisticregression": "logistic_regression",
    "svm": "linear_svm",
    "linearsvc": "linear_svm",
    "linearsvm": "linear_svm",
    "mlp": "mlp",
    "neuralnetwork": "mlp",
    "neuralnet": "mlp",
    "gaussiannb": "gaussian_nb",
    "naivebayes": "gaussian_nb",
    "nb": "gaussian_nb",
    "knn": "knn",
    "kneighbors": "knn",
    "knearestneighbors": "knn",
}
_DROP_COLUMNS = {
    "unnamed0",
    "flowid",
    "sourceip",
    "srcip",
    "destinationip",
    "dstip",
    "timestamp",
    "simillarhttp",
}


class CICDDOSTrainingError(ValueError):
    """Raised when an uploaded dataset cannot train the CICDDoS model."""


def _column_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.strip().lower())


def normalize_model_type(model_type: str | None) -> str:
    """Return the canonical model type requested by the API or dashboard."""
    requested = (model_type or DEFAULT_MODEL_TYPE).strip()
    canonical = _MODEL_ALIASES.get(_column_key(requested), requested.lower().replace("-", "_"))
    if canonical not in SUPPORTED_MODEL_TYPES:
        supported = ", ".join(SUPPORTED_MODEL_TYPES)
        raise CICDDOSTrainingError(
            f"Unsupported model_type '{requested}'. Supported values: {supported}."
        )
    return canonical


def is_supported_training_filename(filename: str) -> bool:
    return filename.lower().endswith(SUPPORTED_UPLOAD_SUFFIXES)


class CICDDOSTrainingService:
    """Trains and persists a bounded offline flow classifier from CSV or ZIP uploads."""

    def __init__(
        self,
        *,
        model_dir: str | Path = "./models",
        upload_dir: str | Path = "./data/uploads/cicddos2019",
        max_rows_per_class: int = 100_000,
    ) -> None:
        self.model_dir = Path(model_dir)
        self.upload_dir = Path(upload_dir)
        self.max_rows_per_class = max_rows_per_class
        self.model_path = self.model_dir / "cicddos_flow_classifier.joblib"
        self.metadata_path = self.model_dir / "cicddos_flow_classifier.json"
        self._lock = Lock()
        self._status = self._initial_status()

    def _initial_status(self) -> dict[str, Any]:
        base = {
            "model_kind": MODEL_KIND,
            "model_type": DEFAULT_MODEL_TYPE,
            "model_name": SUPPORTED_MODEL_TYPES[DEFAULT_MODEL_TYPE],
            "supported_model_types": self.available_model_types(),
            "live_model_active": False,
        }
        if self.metadata_path.exists():
            try:
                with self.metadata_path.open("r", encoding="utf-8") as handle:
                    metadata = json.load(handle)
                return {
                    **base,
                    "state": "ready",
                    "model_type": metadata.get("requested_model_type")
                    or metadata.get("model_type")
                    or DEFAULT_MODEL_TYPE,
                    "model_name": metadata.get("model_name")
                    or SUPPORTED_MODEL_TYPES[DEFAULT_MODEL_TYPE],
                    "message": SCHEMA_NOTE,
                    "result": metadata,
                }
            except (OSError, ValueError):
                logger.warning("cicddos_training_metadata_read_failed")
        return {
            **base,
            "state": "idle",
            "message": SCHEMA_NOTE,
            "result": None,
        }

    @staticmethod
    def available_model_types() -> list[dict[str, str | bool]]:
        return [
            {
                "id": model_type,
                "name": name,
                "default": model_type == DEFAULT_MODEL_TYPE,
            }
            for model_type, name in SUPPORTED_MODEL_TYPES.items()
        ]

    def status(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._status)

    def begin_upload(
        self, filename: str, *, model_type: str = DEFAULT_MODEL_TYPE
    ) -> tuple[str, Path]:
        canonical_model_type = normalize_model_type(model_type)
        with self._lock:
            if self._status["state"] in {"uploading", "queued", "training"}:
                raise CICDDOSTrainingError("A dataset training job is already running.")
            job_id = str(uuid.uuid4())
            self.upload_dir.mkdir(parents=True, exist_ok=True)
            upload_path = self.upload_dir / f"{job_id}{Path(filename).suffix.lower()}"
            self._status = {
                "state": "uploading",
                "job_id": job_id,
                "filename": filename,
                "model_kind": MODEL_KIND,
                "model_type": canonical_model_type,
                "model_name": SUPPORTED_MODEL_TYPES[canonical_model_type],
                "supported_model_types": self.available_model_types(),
                "live_model_active": False,
                "message": "Uploading dataset.",
                "result": None,
            }
        return job_id, upload_path

    def mark_queued(self, job_id: str, uploaded_bytes: int) -> dict[str, Any]:
        with self._lock:
            self._status.update(
                {
                    "state": "queued",
                    "job_id": job_id,
                    "uploaded_bytes": uploaded_bytes,
                    "message": "Upload complete. Training job queued.",
                }
            )
            return dict(self._status)

    def mark_failed(self, job_id: str, error: str) -> dict[str, Any]:
        with self._lock:
            self._status.update(
                {
                    "state": "failed",
                    "job_id": job_id,
                    "message": error,
                    "live_model_active": False,
                    "result": None,
                }
            )
            return dict(self._status)

    def train_uploaded_dataset(
        self,
        dataset_path: Path,
        *,
        job_id: str,
        filename: str,
        model_type: str = DEFAULT_MODEL_TYPE,
        target_column: str | None = None,
    ) -> dict[str, Any]:
        canonical_model_type = normalize_model_type(model_type)
        with self._lock:
            self._status.update(
                {
                    "state": "training",
                    "job_id": job_id,
                    "filename": filename,
                    "model_type": canonical_model_type,
                    "model_name": SUPPORTED_MODEL_TYPES[canonical_model_type],
                    "message": (
                        "Reading bounded dataset sample and training "
                        f"{SUPPORTED_MODEL_TYPES[canonical_model_type]} offline tabular model."
                    ),
                }
            )

        started_at = time.time()
        (
            X,
            y,
            feature_names,
            label_counts,
            source_files,
            resolved_target_column,
            numeric_features,
            categorical_features,
            dropped_features,
        ) = self._load_training_sample(dataset_path, target_column=target_column)
        result = self._fit_and_persist(
            X,
            y,
            feature_names,
            label_counts=label_counts,
            source_files=source_files,
            filename=filename,
            started_at=started_at,
            model_type=canonical_model_type,
            target_column=resolved_target_column,
            requested_target_column=target_column,
            numeric_features=numeric_features,
            categorical_features=categorical_features,
            dropped_features=dropped_features,
        )

        with self._lock:
            self._status = {
                "state": "ready",
                "job_id": job_id,
                "filename": filename,
                "model_kind": MODEL_KIND,
                "model_type": canonical_model_type,
                "model_name": result["model_name"],
                "supported_model_types": self.available_model_types(),
                "live_model_active": False,
                "message": SCHEMA_NOTE,
                "result": result,
            }
            return dict(self._status)

    def train_uploaded_csv(
        self,
        csv_path: Path,
        *,
        job_id: str,
        filename: str,
        model_type: str = DEFAULT_MODEL_TYPE,
        target_column: str | None = None,
    ) -> dict[str, Any]:
        """Backward-compatible CSV entry point."""
        return self.train_uploaded_dataset(
            csv_path,
            job_id=job_id,
            filename=filename,
            model_type=model_type,
            target_column=target_column,
        )

    def _load_training_sample(
        self,
        dataset_path: Path,
        *,
        target_column: str | None = None,
    ) -> tuple[
        pd.DataFrame,
        np.ndarray,
        list[str],
        dict[str, int],
        list[str],
        str,
        list[str],
        list[str],
        list[str],
    ]:
        if dataset_path.suffix.lower() == ".zip":
            return self._load_zip_training_sample(dataset_path, target_column=target_column)
        return self._load_csv_training_sample(dataset_path, target_column=target_column)

    @staticmethod
    def _find_columns(chunk: pd.DataFrame, target_column: str | None = None) -> tuple[str, list[str]]:
        chunk.columns = [str(column).strip() for column in chunk.columns]
        if not chunk.columns.any():
            raise CICDDOSTrainingError("CSV must contain at least one feature column and one target column.")

        if target_column:
            requested_key = _column_key(target_column)
            label_column = next(
                (column for column in chunk.columns if _column_key(column) == requested_key),
                None,
            )
            if label_column is None:
                available = ", ".join(str(column) for column in chunk.columns[:20])
                raise CICDDOSTrainingError(
                    f"Target column '{target_column}' was not found. Available columns: {available}."
                )
        else:
            label_column = next(
                (column for column in chunk.columns if _column_key(column) in _TARGET_COLUMNS),
                None,
            )
            if label_column is None:
                label_column = str(chunk.columns[-1]).strip()

        feature_columns = [
            column
            for column in chunk.columns
            if column != label_column and _column_key(column) not in _DROP_COLUMNS
        ]
        if not feature_columns:
            raise CICDDOSTrainingError(
                "Dataset must contain at least one feature column besides the target column."
            )
        return label_column, feature_columns

    @staticmethod
    def _append_label_rows(
        chunk: pd.DataFrame,
        *,
        label_column: str,
        feature_columns: list[str],
        selected_by_label: dict[str, int],
        max_rows_per_label: int,
        frames: list[pd.DataFrame],
        labels: list[np.ndarray],
        labels_by_name: Counter[str],
    ) -> int:
        original_labels = chunk[label_column]
        valid = original_labels.notna() & (original_labels.astype(str).str.strip() != "")
        chunk = chunk.loc[valid]
        if chunk.empty:
            return 0
        raw_labels = original_labels.loc[valid].astype(str).str.strip()
        added = 0
        for label_value, indexes in raw_labels.groupby(raw_labels).groups.items():
            remaining = max_rows_per_label - selected_by_label.get(label_value, 0)
            if remaining <= 0:
                continue
            selected_indexes = list(indexes[:remaining])
            if not selected_indexes:
                continue
            selected_rows = chunk.loc[selected_indexes, feature_columns]
            selected_labels = raw_labels.loc[selected_indexes].to_numpy(dtype=object)
            labels_by_name.update(selected_labels.tolist())
            selected_by_label[label_value] = selected_by_label.get(label_value, 0) + len(
                selected_rows
            )
            frames.append(selected_rows)
            labels.append(selected_labels)
            added += len(selected_rows)
        return added

    def _load_csv_training_sample(
        self,
        csv_path: Path,
        *,
        target_column: str | None = None,
    ) -> tuple[
        pd.DataFrame,
        np.ndarray,
        list[str],
        dict[str, int],
        list[str],
        str,
        list[str],
        list[str],
        list[str],
    ]:
        frames: list[pd.DataFrame] = []
        labels: list[np.ndarray] = []
        labels_by_name: Counter[str] = Counter()
        selected_by_label: dict[str, int] = {}
        feature_columns: list[str] | None = None
        label_column: str | None = None

        try:
            chunks = pd.read_csv(csv_path, chunksize=50_000, low_memory=False)
            for chunk in chunks:
                chunk.columns = [str(column).strip() for column in chunk.columns]
                if label_column is None:
                    label_column, feature_columns = self._find_columns(
                        chunk,
                        target_column=target_column,
                    )
                elif label_column not in chunk.columns or any(
                    column not in chunk.columns for column in feature_columns or []
                ):
                    raise CICDDOSTrainingError("CSV feature schema changed between chunks.")

                self._append_label_rows(
                    chunk,
                    label_column=label_column,
                    feature_columns=feature_columns or [],
                    selected_by_label=selected_by_label,
                    max_rows_per_label=self.max_rows_per_class,
                    frames=frames,
                    labels=labels,
                    labels_by_name=labels_by_name,
                )
        except pd.errors.EmptyDataError as error:
            raise CICDDOSTrainingError("The uploaded CSV is empty.") from error
        except UnicodeDecodeError as error:
            raise CICDDOSTrainingError("The uploaded file is not a readable UTF-8 CSV.") from error

        return self._finalize_sample(
            frames,
            labels,
            labels_by_name,
            selected_by_label,
            feature_columns,
            [csv_path.name],
            label_column,
        )

    def _load_zip_training_sample(
        self,
        zip_path: Path,
        *,
        target_column: str | None = None,
    ) -> tuple[
        pd.DataFrame,
        np.ndarray,
        list[str],
        dict[str, int],
        list[str],
        str,
        list[str],
        list[str],
        list[str],
    ]:
        frames: list[pd.DataFrame] = []
        labels: list[np.ndarray] = []
        labels_by_name: Counter[str] = Counter()
        selected_by_label: dict[str, int] = {}
        feature_columns: list[str] | None = None
        label_column: str | None = None
        source_files: list[str] = []

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                csv_sources: list[tuple[Path, str, str]] = []
                archive_entries: list[str] = []
                self._collect_zip_csv_sources(
                    zip_path,
                    csv_sources,
                    archive_entries,
                    temp_root=Path(temp_dir),
                )
                if not csv_sources:
                    preview = ", ".join(archive_entries[:8])
                    if len(archive_entries) > 8:
                        preview += ", ..."
                    found = f" Found archive entries: {preview}." if preview else ""
                    raise CICDDOSTrainingError(
                        "ZIP does not contain any CSV files. Upload a .csv file, "
                        "a ZIP with .csv/.csv.gz files, or a ZIP containing inner "
                        f"ZIPs with CSV files.{found}"
                    )

                for source_zip_path, member_name, display_name in csv_sources:
                    source_files.append(display_name)
                    with zipfile.ZipFile(source_zip_path) as archive:
                        member = archive.getinfo(member_name)
                        if member.flag_bits & 0x1:
                            raise CICDDOSTrainingError(
                                "Password-protected ZIP files are not supported."
                            )
                        with archive.open(member) as handle:
                            chunks = pd.read_csv(
                                handle,
                                chunksize=50_000,
                                low_memory=False,
                                compression=self._csv_compression(member_name),
                            )
                            for chunk in chunks:
                                chunk.columns = [str(column).strip() for column in chunk.columns]
                                if label_column is None:
                                    label_column, feature_columns = self._find_columns(
                                        chunk,
                                        target_column=target_column,
                                    )
                                elif label_column not in chunk.columns or any(
                                    column not in chunk.columns for column in feature_columns or []
                                ):
                                    raise CICDDOSTrainingError(
                                        f"CSV feature schema does not match in {display_name}."
                                    )

                                self._append_label_rows(
                                    chunk,
                                    label_column=label_column,
                                    feature_columns=feature_columns or [],
                                    selected_by_label=selected_by_label,
                                    max_rows_per_label=self.max_rows_per_class,
                                    frames=frames,
                                    labels=labels,
                                    labels_by_name=labels_by_name,
                                )

        except zipfile.BadZipFile as error:
            raise CICDDOSTrainingError("The uploaded ZIP archive is invalid.") from error
        except pd.errors.EmptyDataError as error:
            raise CICDDOSTrainingError("A CSV inside the ZIP archive is empty.") from error
        except UnicodeDecodeError as error:
            raise CICDDOSTrainingError("A CSV inside the ZIP is not readable UTF-8.") from error

        return self._finalize_sample(
            frames,
            labels,
            labels_by_name,
            selected_by_label,
            feature_columns,
            source_files,
            label_column,
        )

    @staticmethod
    def _is_csv_archive_member(filename: str) -> bool:
        return filename.lower().endswith(SUPPORTED_CSV_ARCHIVE_SUFFIXES)

    @staticmethod
    def _csv_compression(filename: str) -> str | None:
        lower = filename.lower()
        if lower.endswith(".csv.gz"):
            return "gzip"
        if lower.endswith(".csv.bz2"):
            return "bz2"
        if lower.endswith(".csv.xz"):
            return "xz"
        return None

    def _collect_zip_csv_sources(
        self,
        zip_path: Path,
        sources: list[tuple[Path, str, str]],
        archive_entries: list[str],
        *,
        temp_root: Path,
        prefix: str = "",
        depth: int = 0,
    ) -> None:
        if depth > MAX_NESTED_ZIP_DEPTH:
            raise CICDDOSTrainingError("ZIP nesting is too deep to process safely.")

        with zipfile.ZipFile(zip_path) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                display_name = f"{prefix}{member.filename}"
                archive_entries.append(display_name)
                lower_name = member.filename.lower()
                if self._is_csv_archive_member(lower_name):
                    sources.append((zip_path, member.filename, display_name))
                elif lower_name.endswith(".zip"):
                    if member.flag_bits & 0x1:
                        raise CICDDOSTrainingError(
                            "Password-protected ZIP files are not supported."
                        )
                    nested_zip_path = temp_root / f"nested-{uuid.uuid4()}.zip"
                    with archive.open(member) as source, nested_zip_path.open("wb") as target:
                        shutil.copyfileobj(source, target)
                    self._collect_zip_csv_sources(
                        nested_zip_path,
                        sources,
                        archive_entries,
                        temp_root=temp_root,
                        prefix=f"{display_name}!",
                        depth=depth + 1,
                    )

    @staticmethod
    def _finalize_sample(
        frames: list[pd.DataFrame],
        labels: list[np.ndarray],
        labels_by_name: Counter[str],
        selected_by_label: dict[str, int],
        feature_columns: list[str] | None,
        source_files: list[str],
        label_column: str | None,
    ) -> tuple[
        pd.DataFrame,
        np.ndarray,
        list[str],
        dict[str, int],
        list[str],
        str,
        list[str],
        list[str],
        list[str],
    ]:
        if not frames or feature_columns is None:
            raise CICDDOSTrainingError("No usable rows were found in the dataset.")
        usable_labels = {label: count for label, count in selected_by_label.items() if count > 0}
        if len(usable_labels) < 2:
            raise CICDDOSTrainingError("Training requires at least two target classes.")
        rare_labels = [label for label, count in usable_labels.items() if count < 5]
        if rare_labels:
            preview = ", ".join(f"{label}={usable_labels[label]}" for label in rare_labels[:6])
            raise CICDDOSTrainingError(
                "Training requires at least 5 rows for every sampled target class. "
                f"Too few rows: {preview}."
            )

        X_df = pd.concat(frames, ignore_index=True)
        numeric_features: list[str] = []
        categorical_features: list[str] = []
        dropped_features: list[str] = []
        for column in list(feature_columns):
            values = X_df[column]
            non_empty = values.notna() & (values.astype(str).str.strip() != "")
            if not non_empty.any():
                X_df.drop(columns=[column], inplace=True)
                dropped_features.append(column)
                continue

            numeric_values = pd.to_numeric(values, errors="coerce")
            numeric_ratio = float(numeric_values.notna().sum()) / float(non_empty.sum())
            if numeric_ratio >= 0.9:
                X_df[column] = numeric_values
                numeric_features.append(column)
            else:
                X_df[column] = values.astype("string").fillna("__missing__")
                unique_count = int(X_df[column].nunique(dropna=True))
                max_categories = min(1000, max(100, len(X_df) // 2))
                if unique_count > max_categories:
                    X_df.drop(columns=[column], inplace=True)
                    dropped_features.append(column)
                else:
                    categorical_features.append(column)

        X_df.replace([np.inf, -np.inf], np.nan, inplace=True)
        feature_names = list(X_df.columns)
        if not feature_names:
            raise CICDDOSTrainingError(
                "Dataset does not contain usable feature columns after preprocessing."
            )

        y = np.concatenate(labels)
        return (
            X_df,
            y,
            feature_names,
            dict(labels_by_name),
            source_files,
            label_column or "target",
            numeric_features,
            categorical_features,
            dropped_features,
        )

    def _fit_and_persist(
        self,
        X: pd.DataFrame,
        y: np.ndarray,
        feature_names: list[str],
        *,
        label_counts: dict[str, int],
        source_files: list[str],
        filename: str,
        started_at: float,
        model_type: str,
        target_column: str,
        requested_target_column: str | None,
        numeric_features: list[str],
        categorical_features: list[str],
        dropped_features: list[str],
    ) -> dict[str, Any]:
        from sklearn.compose import ColumnTransformer
        from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.exceptions import ConvergenceWarning
        from sklearn.impute import SimpleImputer
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import (
            accuracy_score,
            balanced_accuracy_score,
            f1_score,
            precision_score,
            recall_score,
        )
        from sklearn.model_selection import train_test_split
        from sklearn.naive_bayes import GaussianNB
        from sklearn.neighbors import KNeighborsClassifier
        from sklearn.neural_network import MLPClassifier
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import OneHotEncoder, StandardScaler
        from sklearn.svm import LinearSVC
        import warnings

        canonical_model_type = normalize_model_type(model_type)
        class_counts = Counter(str(label) for label in y.tolist())
        class_count = len(class_counts)
        test_size = max(0.2, class_count / len(y))
        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=test_size,
            stratify=y,
            random_state=42,
        )
        candidate_types = (
            AUTO_CANDIDATE_MODEL_TYPES
            if canonical_model_type == AUTO_MODEL_TYPE
            else (canonical_model_type,)
        )

        def build_pipeline(candidate_type: str) -> Pipeline:
            classifier: Any
            needs_scaling = False
            if candidate_type == "hist_gradient_boosting":
                classifier = HistGradientBoostingClassifier(
                    max_iter=180,
                    max_depth=12,
                    l2_regularization=0.5,
                    learning_rate=0.08,
                    class_weight="balanced",
                    random_state=42,
                )
            elif candidate_type == "random_forest":
                classifier = RandomForestClassifier(
                    n_estimators=180,
                    max_depth=24,
                    min_samples_leaf=2,
                    class_weight="balanced_subsample",
                    n_jobs=-1,
                    random_state=42,
                )
            elif candidate_type == "extra_trees":
                classifier = ExtraTreesClassifier(
                    n_estimators=220,
                    max_depth=24,
                    min_samples_leaf=2,
                    class_weight="balanced",
                    n_jobs=-1,
                    random_state=42,
                )
            elif candidate_type == "logistic_regression":
                needs_scaling = True
                classifier = LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    solver="lbfgs",
                    random_state=42,
                )
            elif candidate_type == "linear_svm":
                needs_scaling = True
                classifier = LinearSVC(
                    max_iter=5000,
                    class_weight="balanced",
                    dual="auto",
                    random_state=42,
                )
            elif candidate_type == "mlp":
                needs_scaling = True
                classifier = MLPClassifier(
                    hidden_layer_sizes=(64, 32),
                    activation="relu",
                    solver="adam",
                    alpha=0.0005,
                    batch_size=min(512, max(1, len(X_train))),
                    learning_rate_init=0.001,
                    early_stopping=len(X_train) >= 50,
                    n_iter_no_change=8,
                    max_iter=250,
                    random_state=42,
                )
            elif candidate_type == "gaussian_nb":
                classifier = GaussianNB()
            elif candidate_type == "knn":
                needs_scaling = True
                classifier = KNeighborsClassifier(
                    n_neighbors=min(7, max(1, len(X_train) - 1)),
                    weights="distance",
                    n_jobs=-1,
                )
            else:
                raise CICDDOSTrainingError(f"Unsupported model_type '{candidate_type}'.")

            numeric_steps: list[tuple[str, Any]] = [
                ("imputer", SimpleImputer(strategy="median"))
            ]
            if needs_scaling:
                numeric_steps.append(("scaler", StandardScaler()))

            transformers: list[tuple[str, Any, list[str]]] = []
            if numeric_features:
                transformers.append(
                    (
                        "numeric",
                        Pipeline(steps=numeric_steps),
                        numeric_features,
                    )
                )
            if categorical_features:
                transformers.append(
                    (
                        "categorical",
                        Pipeline(
                            steps=[
                                ("imputer", SimpleImputer(strategy="most_frequent")),
                                (
                                    "onehot",
                                    OneHotEncoder(handle_unknown="ignore", sparse_output=False),
                                ),
                            ]
                        ),
                        categorical_features,
                    )
                )

            return Pipeline(
                steps=[
                    ("preprocessor", ColumnTransformer(transformers=transformers)),
                    ("classifier", classifier),
                ]
            )

        best_result: dict[str, Any] | None = None
        candidate_metrics: list[dict[str, Any]] = []
        for candidate_type in candidate_types:
            pipeline = build_pipeline(candidate_type)
            try:
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", category=ConvergenceWarning)
                    pipeline.fit(X_train, y_train)
                predictions = pipeline.predict(X_test)
                accuracy = float(accuracy_score(y_test, predictions))
                balanced_accuracy = float(balanced_accuracy_score(y_test, predictions))
                f1 = float(f1_score(y_test, predictions, average="weighted"))
                precision = float(
                    precision_score(y_test, predictions, average="weighted", zero_division=0)
                )
                recall = float(
                    recall_score(y_test, predictions, average="weighted", zero_division=0)
                )
            except Exception as error:
                logger.warning(
                    "cicddos_candidate_model_failed",
                    model_type=candidate_type,
                    error=str(error),
                )
                candidate_metrics.append(
                    {
                        "model_type": candidate_type,
                        "model_name": SUPPORTED_MODEL_TYPES[candidate_type],
                        "status": "failed",
                        "error": str(error),
                    }
                )
                continue

            summary = {
                "model_type": candidate_type,
                "model_name": SUPPORTED_MODEL_TYPES[candidate_type],
                "status": "trained",
                "accuracy": round(accuracy, 4),
                "balanced_accuracy": round(balanced_accuracy, 4),
                "f1_score": round(f1, 4),
                "precision": round(precision, 4),
                "recall": round(recall, 4),
            }
            candidate_metrics.append(summary)
            ranking = (balanced_accuracy, f1, accuracy)
            if best_result is None or ranking > best_result["ranking"]:
                best_result = {
                    "pipeline": pipeline,
                    "model_type": candidate_type,
                    "model_name": SUPPORTED_MODEL_TYPES[candidate_type],
                    "accuracy": accuracy,
                    "balanced_accuracy": balanced_accuracy,
                    "f1_score": f1,
                    "precision": precision,
                    "recall": recall,
                    "ranking": ranking,
                }

        if best_result is None:
            raise CICDDOSTrainingError("No supported model candidate could be trained.")

        pipeline = best_result["pipeline"]
        selected_model_type = best_result["model_type"]
        selected_model_name = best_result["model_name"]
        accuracy = float(best_result["accuracy"])
        balanced_accuracy = float(best_result["balanced_accuracy"])
        f1 = float(best_result["f1_score"])
        precision = float(best_result["precision"])
        recall = float(best_result["recall"])
        normal_rows = int(sum(str(label).upper() in _NORMAL_LABELS for label in y.tolist()))
        attack_rows = int(len(y) - normal_rows) if normal_rows else None

        completed_at = time.time()
        result = {
            "filename": filename,
            "schema": "tabular_classification_features",
            "target_column": target_column,
            "requested_target_column": requested_target_column,
            "requested_model_type": canonical_model_type,
            "selected_model_type": selected_model_type,
            "model_type": selected_model_type,
            "model_name": selected_model_name,
            "model_selection": "auto" if canonical_model_type == AUTO_MODEL_TYPE else "manual",
            "candidate_metrics": candidate_metrics,
            "rows_used": int(len(X)),
            "train_rows": int(len(X_train)),
            "test_rows": int(len(X_test)),
            "class_count": class_count,
            "classes": sorted(class_counts),
            "normal_rows": normal_rows,
            "attack_rows": attack_rows,
            "feature_count": len(feature_names),
            "feature_names": feature_names,
            "numeric_feature_count": len(numeric_features),
            "categorical_feature_count": len(categorical_features),
            "dropped_features": dropped_features,
            "label_counts": label_counts,
            "source_files": source_files,
            "accuracy": round(accuracy, 4),
            "balanced_accuracy": round(balanced_accuracy, 4),
            "f1_score": round(f1, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "trained_at": completed_at,
            "training_seconds": round(completed_at - started_at, 2),
            "live_model_active": False,
            "compatibility_note": SCHEMA_NOTE,
        }
        artifact = {
            "pipeline": pipeline,
            "feature_names": feature_names,
            "target_column": target_column,
            "numeric_features": numeric_features,
            "categorical_features": categorical_features,
            "metadata": result,
            "model_type": selected_model_type,
        }

        self.model_dir.mkdir(parents=True, exist_ok=True)
        temporary_model = self.model_path.with_suffix(".joblib.tmp")
        temporary_metadata = self.metadata_path.with_suffix(".json.tmp")
        joblib.dump(artifact, temporary_model)
        with temporary_metadata.open("w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, sort_keys=True)
        os.replace(temporary_model, self.model_path)
        os.replace(temporary_metadata, self.metadata_path)
        logger.info(
            "cicddos_flow_model_trained",
            requested_model_type=canonical_model_type,
            selected_model_type=selected_model_type,
            rows_used=result["rows_used"],
            feature_count=result["feature_count"],
            balanced_accuracy=result["balanced_accuracy"],
            live_model_active=False,
        )
        return result
