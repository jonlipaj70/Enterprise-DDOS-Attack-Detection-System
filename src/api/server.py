"""
FastAPI REST + WebSocket Server
=================================
Main application server integrating all components.
Provides REST API and WebSocket endpoints for the dashboard.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.api.auth import AuthService, AuthenticatedUser, Role, SESSION_COOKIE_NAME
from src.api.redaction import redact_alerts, redact_ws_payload
from src.config.settings import CaptureSource, ResponseMode, get_settings
from src.config.logging_config import setup_logging, get_logger
from src.control.response_control import ResponseControlService
from src.ingestion.traffic_simulator import TrafficSimulator, AttackType
from src.ingestion.tshark_capture import (
    TSharkCaptureAgent,
    TSharkConfigurationError,
    TSharkInterfaceChanged,
    list_tshark_interfaces,
    resolve_capture_interface,
    resolve_tshark_path,
)
from src.processing.feature_engine import FeatureEngine
from src.processing.window_aggregator import WindowAggregator
from src.processing.feature_store import FeatureStore
from src.detection.ensemble_model import EnsembleModel
from src.detection.cicddos_training import (
    DEFAULT_MODEL_TYPE,
    CICDDOSTrainingError,
    CICDDOSTrainingService,
    is_supported_training_filename,
    normalize_model_type,
)
from src.detection.live_attack_gate import evaluate_live_attack
from src.alerting.alert_engine import AlertEngine
from src.local_security.wifi_guard import LocalSecuritySnapshot, LocalThreatGuard
from src.response.response_engine import ResponseEngine
from src.storage.audit_repository import AuditRepository
from src.storage.database import Database
from src.storage.repositories import RuntimeControlRepository, SessionRepository, UserRepository

logger = get_logger(__name__)


# ─── Global State ────────────────────────────────────────────


class SystemState:
    """Global system state shared across components."""

    def __init__(self):
        self.settings = get_settings()
        self.simulator = TrafficSimulator()
        self.feature_engine = FeatureEngine()
        self.window_aggregator = WindowAggregator()
        self.feature_store = FeatureStore()
        self.ensemble_model = EnsembleModel()
        self.cicddos_trainer = CICDDOSTrainingService(
            model_dir=self.settings.ml.model_dir,
            upload_dir=self.settings.ml.training_upload_dir,
            max_rows_per_class=self.settings.ml.training_max_rows_per_class,
        )
        self.alert_engine = AlertEngine()
        self.database = Database(self.settings.database.database_url)
        self.users = UserRepository(self.database)
        self.sessions = SessionRepository(self.database)
        self.audit = AuditRepository(self.database)
        self.auth = AuthService(
            self.users,
            self.sessions,
            secret_key=self.settings.jwt.jwt_secret_key,
            algorithm=self.settings.jwt.jwt_algorithm,
            expiration_minutes=self.settings.jwt.jwt_expiration_minutes,
        )
        self.response_control = ResponseControlService(
            RuntimeControlRepository(self.database),
            self.audit,
            mitigation_activation_allowed=self.settings.response.mitigation_activation_allowed,
        )
        self.response_engine = ResponseEngine.from_settings(self.settings.response)
        self.response_engine.set_policy_provider(self.response_control.engine_policy)
        self.local_threat_guard = LocalThreatGuard.from_settings(self.settings.local_threat)
        self.tshark_capture: TSharkCaptureAgent | None = None
        self.local_threat_snapshot: dict[str, Any] | None = None

        self.is_running = False
        self.start_time = 0.0
        self.capture_state = "starting"
        self.capture_started_at: float | None = None
        self.last_packet_at: float | None = None
        self.last_detection_at: float | None = None
        self.last_capture_error: str | None = None
        self.model_ready = False
        self.current_attack: str | None = None
        self.websocket_clients: list[tuple[WebSocket, AuthenticatedUser | None]] = []
        self.training_tasks: set[asyncio.Task[Any]] = set()

        # Metrics for dashboard
        self.metrics = {
            "packets_processed": 0,
            "bytes_processed": 0,
            "detections_run": 0,
            "attacks_detected": 0,
            "alerts_generated": 0,
            "uptime_seconds": 0,
            "current_pps": 0,
            "current_bps": 0,
            "detection_latency_ms": 0,
            "capture_source": self.settings.capture.capture_source.value,
            "suppressed_detections": 0,
            "response_active_blocks": 0,
            "response_actions": 0,
            "local_threats_detected": 0,
            "local_threat_highest_severity": "info",
            "local_threat_last_scan": 0,
            "local_threat_response_actions": 0,
            "capture_restarts": 0,
        }

        # Time-series for charts
        self.traffic_history: list[dict] = []
        self.detection_history: list[dict] = []
        self.alert_list: list[dict] = []

    def create_tshark_capture(self) -> TSharkCaptureAgent:
        capture_settings = self.settings.capture
        return TSharkCaptureAgent(
            interface=capture_settings.capture_interface,
            target_host=capture_settings.capture_target_host,
            target_ports=capture_settings.target_ports_list,
            tshark_path=capture_settings.tshark_path,
            batch_size=capture_settings.capture_batch_size,
        )

    def validate_capture_configuration(self) -> None:
        if self.settings.capture.capture_source != CaptureSource.TSHARK:
            return
        capture = self.create_tshark_capture()
        capture.validate_configuration()

    def initialize_control_plane(self) -> None:
        self.settings.validate_runtime_safety()
        self.database.initialize()
        self.response_control.initialize()


state = SystemState()


class BlockIPRequest(BaseModel):
    """Manual block request body."""

    ip: str = Field(..., description="Source IP to block")
    ttl_seconds: int | None = Field(default=None, gt=0)
    reason: str = Field(default="manual_block")
    requested_by: str = Field(default="api_user")


class UnblockIPRequest(BaseModel):
    """Manual unblock request body."""

    ip: str = Field(..., description="Source IP to unblock")
    reason: str = Field(default="manual_unblock")
    requested_by: str = Field(default="api_user")


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class KillSwitchRequest(BaseModel):
    enabled: bool
    reason: str = Field(..., min_length=1)


class ResponseModeRequest(BaseModel):
    mode: ResponseMode
    auto_block_enabled: bool = False
    reason: str = Field(..., min_length=1)
    confirmation: str = ""


# ─── Detection Pipeline ─────────────────────────────────────


async def run_detection_pipeline():
    """Main detection pipeline loop."""
    state.is_running = True
    state.start_time = time.time()
    state.capture_started_at = state.start_time
    state.capture_state = "starting"
    state.last_capture_error = None

    try:
        logger.info(
            "model_training_starting", msg="Training 3 sklearn ML models... (this may take 15-30s)"
        )
        train_start = time.time()
        state.ensemble_model.initialize()
        state.model_ready = True
        train_time = time.time() - train_start
        logger.info("model_training_complete", training_time_seconds=round(train_time, 2))
    except Exception as e:
        logger.error("model_initialization_error", error=str(e))
        state.capture_state = "failed"
        state.last_capture_error = str(e)
        return

    logger.info(
        "detection_pipeline_started",
        capture_source=state.settings.capture.capture_source.value,
    )

    if state.settings.capture.capture_source == CaptureSource.TSHARK:
        await _run_tshark_detection_loop()
    else:
        await _run_simulated_detection_loop()


async def _run_simulated_detection_loop() -> None:
    """Run the existing synthetic traffic pipeline."""

    batch_size = state.settings.capture.capture_batch_size
    interval = 0.5  # 500ms batches

    attack_schedule = [
        {"time": 15, "type": AttackType.SYN_FLOOD, "duration": 35, "intensity": 0.65},
        {"time": 80, "type": AttackType.DNS_AMPLIFICATION, "duration": 25, "intensity": 0.8},
        {"time": 140, "type": AttackType.HTTP_FLOOD, "duration": 40, "intensity": 0.5},
        {"time": 220, "type": AttackType.SLOWLORIS, "duration": 50, "intensity": 0.35},
        {"time": 310, "type": AttackType.UDP_FLOOD, "duration": 30, "intensity": 0.7},
        {"time": 380, "type": AttackType.SYN_FLOOD, "duration": 20, "intensity": 0.9},
        {"time": 440, "type": AttackType.MULTI_VECTOR, "duration": 45, "intensity": 0.6},
    ]

    async for packet_batch, current_attack in state.simulator.generate_traffic(
        normal_pps=5000,
        batch_size=batch_size,
        attack_schedule=attack_schedule,
    ):
        if not state.is_running:
            break

        await process_packet_batch(packet_batch, current_attack)

        await asyncio.sleep(interval)


async def _run_tshark_detection_loop() -> None:
    """Run live TShark under a supervisor that heals transient capture failures."""
    retry_delay = 1.0
    while state.is_running:
        capture = state.create_tshark_capture()
        state.tshark_capture = capture
        backoff_required = False

        try:
            await capture.start()
            state.capture_started_at = time.time()
            state.capture_state = "starting"
            state.last_capture_error = None
            async for packet_batch in capture.capture_packets():
                if not state.is_running:
                    break
                retry_delay = 1.0
                await process_packet_batch(packet_batch, current_attack=None)
            if state.is_running:
                raise RuntimeError("TShark packet stream stopped unexpectedly")
        except asyncio.CancelledError:
            raise
        except TSharkInterfaceChanged as error:
            state.metrics["capture_restarts"] += 1
            state.capture_state = "switching"
            state.last_capture_error = None
            logger.info("live_capture_interface_switch", reason=str(error))
        except Exception as error:
            state.metrics["capture_restarts"] += 1
            state.capture_state = "recovering"
            state.last_capture_error = str(error)
            backoff_required = True
            logger.error(
                "live_capture_recovering",
                error=str(error),
                retry_seconds=retry_delay,
            )
        finally:
            await capture.stop()
            state.tshark_capture = None

        if not state.is_running:
            break
        if backoff_required:
            await asyncio.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 30.0)
        else:
            await asyncio.sleep(0)


async def run_capture_state_monitor() -> None:
    """Track liveness independently of actual packet receipt."""
    while True:
        if state.is_running:
            state.metrics["uptime_seconds"] = round(time.time() - state.start_time)
            reference = state.last_packet_at or state.capture_started_at
            if (
                state.capture_state in {"starting", "receiving", "idle"}
                and reference is not None
                and time.time() - reference > state.settings.capture.capture_idle_timeout_seconds
            ):
                state.capture_state = "idle"
        await asyncio.sleep(1)


async def run_local_threat_monitor() -> None:
    """Monitor local Wi-Fi/USB threat signals in the background."""
    if not state.settings.local_threat.local_threat_monitor_enabled:
        logger.info("local_threat_monitor_disabled")
        return

    interval = state.settings.local_threat.local_threat_scan_interval_seconds
    logger.info("local_threat_monitor_started", interval_seconds=interval)

    while True:
        try:
            snapshot = await asyncio.to_thread(state.local_threat_guard.scan)
            await process_local_threat_snapshot(snapshot)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("local_threat_monitor_error", error=str(e))

        await asyncio.sleep(interval)


async def process_local_threat_snapshot(snapshot: LocalSecuritySnapshot) -> None:
    """Store local security scan results, create alerts, and broadcast changes."""
    snapshot_dict = snapshot.to_dict()
    findings = snapshot_dict["findings"]
    state.local_threat_snapshot = snapshot_dict
    state.metrics["local_threats_detected"] = len(findings)
    state.metrics["local_threat_highest_severity"] = snapshot_dict["highest_severity"]
    state.metrics["local_threat_last_scan"] = round(snapshot.timestamp)
    state.metrics["local_threat_response_actions"] += len(snapshot.response_actions)

    new_alerts = []
    for finding in snapshot.findings:
        alert = state.alert_engine.create_security_alert(finding.to_alert_payload())
        if alert:
            state.metrics["alerts_generated"] += 1
            alert_dict = alert.to_dict()
            state.alert_list.append(alert_dict)
            new_alerts.append(alert_dict)

    if len(state.alert_list) > 200:
        state.alert_list = state.alert_list[-200:]

    await broadcast_ws(
        {
            "type": "local_security_update",
            "metrics": state.metrics,
            "local_security": snapshot_dict,
            "alerts": state.alert_list[-20:],
            "new_alerts": new_alerts,
            **capture_status_payload(),
        }
    )


async def process_packet_batch(packet_batch: list[Any], current_attack: Any = None) -> None:
    """Convert packets into features, run detection, update state, and broadcast."""
    try:
        start_time = time.time()
        state.last_packet_at = start_time
        state.capture_state = "receiving"

        packet_dicts = [p.to_dict() for p in packet_batch]
        window_features = state.window_aggregator.ingest(packet_dicts)
        features_1s = window_features.get("1s")
        if not features_1s:
            return

        feature_dict = features_1s.to_dict()
        state.feature_store.put("window_1s", feature_dict, ttl=60)

        detection_result = state.ensemble_model.detect(feature_dict)
        state.last_detection_at = time.time()
        detection_latency = (time.time() - start_time) * 1000

        state.metrics["packets_processed"] += len(packet_batch)
        state.metrics["bytes_processed"] += sum(p.packet_size for p in packet_batch)
        state.metrics["detections_run"] += 1
        state.metrics["current_pps"] = feature_dict.get("packet_rate", 0)
        state.metrics["current_bps"] = feature_dict.get("byte_rate", 0)
        state.metrics["detection_latency_ms"] = round(detection_latency, 2)
        state.metrics["uptime_seconds"] = round(time.time() - state.start_time)
        state.metrics["capture_source"] = state.settings.capture.capture_source.value

        detection_payload = detection_result.to_dict()
        traffic_context = summarize_packet_context(packet_dicts)
        detection_payload = {
            **detection_payload,
            "source_ips": traffic_context["source_ips"],
            "target_ips": traffic_context["target_ips"],
            "source_ports": traffic_context["source_ports"],
            "target_ports": traffic_context["target_ports"],
            "protocol": traffic_context["protocol"],
            "first_seen": traffic_context["first_seen"],
            "last_seen": traffic_context["last_seen"],
            "packet_rate": feature_dict.get("packet_rate", 0),
            "byte_rate": feature_dict.get("byte_rate", 0),
            "detection_sources": ["ml_ensemble"],
            "details": {
                **detection_payload.get("details", {}),
                "traffic_context": traffic_context,
            },
        }
        if state.settings.capture.capture_source == CaptureSource.TSHARK and detection_payload.get(
            "is_anomaly", False
        ):
            gate_decision = evaluate_live_attack(feature_dict, detection_payload)
            if not gate_decision.allowed:
                state.metrics["suppressed_detections"] += 1
                detection_payload = {
                    **detection_payload,
                    "is_anomaly": False,
                    "raw_anomaly_score": detection_payload.get("anomaly_score", 0),
                    "anomaly_score": min(detection_payload.get("anomaly_score", 0), 0.44),
                    "attack_type": "none",
                    "severity": "info",
                    "suppressed": True,
                    "suppression_reason": gate_decision.reason,
                    "gate_evidence": gate_decision.evidence,
                    "details": {
                        **detection_payload.get("details", {}),
                        "gate_evidence": gate_decision.evidence,
                        "suppression_reason": gate_decision.reason,
                    },
                }
            else:
                detection_payload = {
                    **detection_payload,
                    "suppressed": False,
                    "gate_reason": gate_decision.reason,
                    "gate_evidence": gate_decision.evidence,
                    "details": {
                        **detection_payload.get("details", {}),
                        "gate_evidence": gate_decision.evidence,
                        "gate_reason": gate_decision.reason,
                    },
                }

        if current_attack is not None:
            state.current_attack = (
                current_attack.value if hasattr(current_attack, "value") else str(current_attack)
            )
        else:
            state.current_attack = None

        history_entry = {
            "timestamp": time.time(),
            "packet_rate": feature_dict.get("packet_rate", 0),
            "byte_rate": feature_dict.get("byte_rate", 0),
            "anomaly_score": detection_payload.get("anomaly_score", 0),
            "attack_type": state.current_attack,
            "syn_ratio": feature_dict.get("syn_ratio", 0),
            "udp_ratio": feature_dict.get("udp_ratio", 0),
            "unique_src_ips": feature_dict.get("unique_src_ips", 0),
            "src_ip_entropy": feature_dict.get("src_ip_entropy", 0),
        }
        state.traffic_history.append(history_entry)
        if len(state.traffic_history) > 500:
            state.traffic_history = state.traffic_history[-500:]

        mitigation_result = {"status": "not_applicable", "reason": "no_alert_created"}
        state.response_engine.expire_blocks()

        if detection_payload.get("is_anomaly", False):
            state.metrics["attacks_detected"] += 1
            alert = state.alert_engine.create_alert(detection_payload)
            if alert:
                mitigation_result = state.response_engine.respond_to_alert(alert.to_dict())
                alert.mitigation = mitigation_result
                alert.details["mitigation"] = mitigation_result
                detection_payload["mitigation"] = mitigation_result
                state.metrics["alerts_generated"] += 1
                state.alert_list.append(alert.to_dict())
                if len(state.alert_list) > 200:
                    state.alert_list = state.alert_list[-200:]
            else:
                mitigation_result = {"status": "deduplicated", "reason": "no_new_alert"}

        response_stats = state.response_engine.stats
        state.metrics["response_active_blocks"] = response_stats["active_blocks"]
        state.metrics["response_actions"] = response_stats["actions_total"]

        ws_data = {
            "type": "update",
            "metrics": state.metrics,
            "latest_features": feature_dict,
            "detection": {
                "anomaly_score": detection_payload.get("anomaly_score", 0),
                "raw_anomaly_score": detection_payload.get("raw_anomaly_score"),
                "is_anomaly": detection_payload.get("is_anomaly", False),
                "attack_type": detection_payload.get("attack_type", "none"),
                "severity": detection_payload.get("severity", "info"),
                "if_score": detection_payload.get("isolation_forest_score", 0),
                "gb_score": detection_payload.get("gradient_boosting_score", 0),
                "ae_score": detection_payload.get("autoencoder_score", 0),
                "top_features": detection_payload.get("top_features", []),
                "expert_analysis": detection_payload.get("expert_analysis", {}),
                "suppressed": detection_payload.get("suppressed", False),
                "suppression_reason": detection_payload.get("suppression_reason"),
                "gate_evidence": detection_payload.get("gate_evidence", []),
                "mitigation": detection_payload.get("mitigation", mitigation_result),
            },
            "current_attack": state.current_attack,
            "traffic_history": state.traffic_history[-60:],
            "alerts": state.alert_list[-20:],
            "local_security": state.local_threat_snapshot,
            **capture_status_payload(),
        }

        await broadcast_ws(ws_data)
    except Exception as e:
        logger.error("pipeline_batch_error", error=str(e))
        state.capture_state = "failed"
        state.last_capture_error = str(e)


def summarize_packet_context(packet_dicts: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize endpoint evidence from the current packet batch."""

    src_ips = Counter(
        str(packet.get("src_ip", "")) for packet in packet_dicts if packet.get("src_ip")
    )
    dst_ips = Counter(
        str(packet.get("dst_ip", "")) for packet in packet_dicts if packet.get("dst_ip")
    )
    src_ports = Counter(_safe_int(packet.get("src_port")) for packet in packet_dicts)
    dst_ports = Counter(_safe_int(packet.get("dst_port")) for packet in packet_dicts)
    protocols = Counter(_safe_int(packet.get("protocol")) for packet in packet_dicts)
    timestamps = [
        float(packet.get("timestamp", 0))
        for packet in packet_dicts
        if packet.get("timestamp") is not None
    ]

    return {
        "packet_sample_count": len(packet_dicts),
        "source_ips": [ip for ip, _ in src_ips.most_common(20)],
        "target_ips": [ip for ip, _ in dst_ips.most_common(20)],
        "source_ports": [port for port, _ in src_ports.most_common(20) if port > 0],
        "target_ports": [port for port, _ in dst_ports.most_common(20) if port > 0],
        "protocol": protocols.most_common(1)[0][0] if protocols else None,
        "first_seen": min(timestamps) if timestamps else time.time(),
        "last_seen": max(timestamps) if timestamps else time.time(),
        "source_ip_counts": dict(src_ips.most_common(20)),
        "target_ip_counts": dict(dst_ips.most_common(20)),
        "target_port_counts": {
            str(port): count for port, count in dst_ports.most_common(20) if port > 0
        },
        "protocol_counts": {str(protocol): count for protocol, count in protocols.most_common(10)},
    }


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def request_id(request: Request) -> str:
    return request.headers.get("X-Request-ID") or str(uuid.uuid4())


def capture_status_payload() -> dict[str, Any]:
    now = time.time()
    seconds_since_last_packet = (
        round(now - state.last_packet_at, 2) if state.last_packet_at is not None else None
    )
    control = state.response_control.get_state().to_dict()
    return {
        "capture_state": state.capture_state,
        "capture_started_at": state.capture_started_at,
        "last_packet_at": state.last_packet_at,
        "seconds_since_last_packet": seconds_since_last_packet,
        "last_detection_at": state.last_detection_at,
        "last_capture_error": state.last_capture_error,
        "capture_source": state.settings.capture.capture_source.value,
        "response_mode": control["mode"],
        "auto_block_enabled": control["auto_block_enabled"],
        "kill_switch": control["kill_switch"],
    }


def readiness_payload() -> dict[str, Any]:
    capture = capture_status_payload()
    ready = state.model_ready and state.capture_state in {"receiving", "idle"}
    return {
        "status": "ready" if ready else "not_ready",
        "ready": ready,
        "model_ready": state.model_ready,
        "pipeline_running": state.is_running,
        **capture,
    }


def capture_diagnostics_payload() -> dict[str, Any]:
    """Build admin-only live capture diagnostics without starting packet capture."""
    capture_settings = state.settings.capture
    capture = state.create_tshark_capture()
    payload: dict[str, Any] = {
        "capture_source": capture_settings.capture_source.value,
        "configured_interface": capture_settings.capture_interface,
        "target_host": capture_settings.capture_target_host or "all",
        "target_ports": capture_settings.target_ports_list,
        "capture_filter": capture.capture_filter,
        "batch_size": capture_settings.capture_batch_size,
        "tshark": {
            "configured_path": capture_settings.tshark_path,
            "resolved_path": None,
            "available": False,
            "interfaces": [],
            "resolved_capture_interface": None,
            "error": None,
        },
        "running_capture": state.tshark_capture.stats if state.tshark_capture else None,
        "capture_state": state.capture_state,
        "last_capture_error": state.last_capture_error,
    }

    try:
        resolved_path = resolve_tshark_path(capture_settings.tshark_path)
        interfaces = list_tshark_interfaces(resolved_path)
        payload["tshark"].update(
            {
                "resolved_path": resolved_path,
                "available": True,
                "interfaces": [interface.to_dict() for interface in interfaces],
            }
        )
        try:
            payload["tshark"]["resolved_capture_interface"] = resolve_capture_interface(
                capture_settings.capture_interface,
                resolved_path,
            )
        except TSharkConfigurationError as error:
            payload["tshark"]["error"] = str(error)
    except TSharkConfigurationError as error:
        payload["tshark"]["error"] = str(error)

    return payload


def model_validation_payload() -> dict[str, Any]:
    """Expose persisted validation metrics without implying unsupported accuracy."""
    ensemble = state.ensemble_model.stats
    isolation_forest = state.ensemble_model.isolation_forest.stats
    gradient_boosting = state.ensemble_model.gradient_boosting.stats
    autoencoder = state.ensemble_model.autoencoder.stats
    cicddos_result = state.cicddos_trainer.status().get("result") or {}
    isolation_ready = state.model_ready and isolation_forest.get("initialized", False)
    gradient_ready = state.model_ready and gradient_boosting.get("initialized", False)
    autoencoder_ready = state.model_ready and autoencoder.get("initialized", False)
    stacking_ready = state.model_ready and ensemble.get("using_stacking", False)

    return {
        "validation_note": (
            "Live model validation uses labeled synthetic evaluation traffic; "
            "CICDDoS metrics use the uploaded labeled flow sample."
        ),
        "models": [
            {
                "id": "isolation_forest",
                "name": "Isolation Forest",
                "category": "LIVE / UNSUPERVISED",
                "primary_metric": "Validation F1",
                "primary_value": (
                    isolation_forest.get("validation_f1_score") if isolation_ready else None
                ),
                "secondary_metric": "Precision",
                "secondary_value": (
                    isolation_forest.get("validation_precision") if isolation_ready else None
                ),
                "secondary_format": "percentage",
                "details": [
                    {
                        "label": "Recall",
                        "value": (
                            isolation_forest.get("validation_recall") if isolation_ready else None
                        ),
                        "format": "percentage",
                    },
                    {
                        "label": "Trees",
                        "value": isolation_forest.get("n_estimators"),
                        "format": "integer",
                    },
                    {
                        "label": "Contamination",
                        "value": isolation_forest.get("contamination"),
                        "format": "percentage",
                    },
                ],
                "basis": "Model is unsupervised; F1 uses separate labeled synthetic evaluation data.",
            },
            {
                "id": "gradient_boosting",
                "name": "Gradient Boosting",
                "category": "LIVE / SUPERVISED",
                "primary_metric": "Accuracy",
                "primary_value": (gradient_boosting.get("accuracy") if gradient_ready else None),
                "secondary_metric": "F1 score",
                "secondary_value": (gradient_boosting.get("f1_score") if gradient_ready else None),
                "secondary_format": "percentage",
                "basis": "Held-out synthetic traffic.",
            },
            {
                "id": "autoencoder",
                "name": "Autoencoder",
                "category": "LIVE / UNSUPERVISED",
                "primary_metric": "Validation F1",
                "primary_value": (
                    autoencoder.get("validation_f1_score") if autoencoder_ready else None
                ),
                "secondary_metric": "Precision",
                "secondary_value": (
                    autoencoder.get("validation_precision") if autoencoder_ready else None
                ),
                "secondary_format": "percentage",
                "details": [
                    {
                        "label": "Recall",
                        "value": (
                            autoencoder.get("validation_recall") if autoencoder_ready else None
                        ),
                        "format": "percentage",
                    },
                    {
                        "label": "Error threshold",
                        "value": (
                            autoencoder.get("error_threshold") if autoencoder_ready else None
                        ),
                        "format": "decimal",
                    },
                    {
                        "label": "Normal MSE p95",
                        "value": (autoencoder.get("normal_mse_p95") if autoencoder_ready else None),
                        "format": "decimal",
                    },
                    {
                        "label": "Attack MSE p50",
                        "value": (
                            autoencoder.get("attack_mse_median") if autoencoder_ready else None
                        ),
                        "format": "decimal",
                    },
                ],
                "basis": "Model is unsupervised; F1 applies its error threshold to labeled synthetic evaluation data.",
            },
            {
                "id": "stacking_ensemble",
                "name": "Stacking Ensemble",
                "category": "LIVE / META MODEL",
                "primary_metric": "Accuracy",
                "primary_value": ensemble.get("stacking_accuracy") if stacking_ready else None,
                "secondary_metric": "Combines",
                "secondary_value": "IF + GB + AE",
                "secondary_format": "text",
                "basis": "Held-out synthetic traffic.",
            },
            {
                "id": "cicddos_flow_classifier",
                "name": cicddos_result.get("model_name") or "Offline Tabular Classifier",
                "category": "OFFLINE / UPLOADED DATA",
                "primary_metric": "Balanced accuracy",
                "primary_value": cicddos_result.get("balanced_accuracy"),
                "secondary_metric": "Accuracy",
                "secondary_value": cicddos_result.get("accuracy"),
                "secondary_format": "percentage",
                "details": [
                    {
                        "label": "F1 score",
                        "value": cicddos_result.get("f1_score"),
                        "format": "percentage",
                    },
                    {
                        "label": "Target",
                        "value": cicddos_result.get("target_column"),
                        "format": "text",
                    },
                    {
                        "label": "Classes",
                        "value": cicddos_result.get("class_count"),
                        "format": "integer",
                    },
                    {
                        "label": "Requested",
                        "value": cicddos_result.get("requested_model_type"),
                        "format": "text",
                    },
                    {
                        "label": "Selected",
                        "value": cicddos_result.get("selected_model_type"),
                        "format": "text",
                    },
                ],
                "basis": (
                    f"Uploaded sample: {cicddos_result.get('filename')}"
                    if cicddos_result.get("filename")
                    else "Train with a CSV or ZIP and selected model type to populate metrics."
                ),
            },
        ],
    }


def current_user(request: Request) -> AuthenticatedUser:
    user = state.auth.authenticate_token(request.cookies.get(SESSION_COOKIE_NAME))
    if user is None:
        state.audit.append(
            action="authorization_denied",
            target_type="endpoint",
            target_id=request.url.path,
            outcome="rejected",
            request_id=request_id(request),
            details={"reason": "valid session required"},
        )
        raise HTTPException(status_code=401, detail="authentication required")
    return user


def require_role(required: Role):
    def dependency(
        request: Request, user: AuthenticatedUser = Depends(current_user)
    ) -> AuthenticatedUser:
        if not state.auth.has_role(user, required):
            state.audit.append(
                actor_user_id=user.user_id,
                actor_role=user.role.value,
                action="authorization_denied",
                target_type="endpoint",
                target_id=request.url.path,
                outcome="rejected",
                request_id=request_id(request),
                details={"required_role": required.value},
            )
            raise HTTPException(status_code=403, detail="insufficient role")
        return user

    return dependency


require_viewer = require_role(Role.VIEWER)
require_analyst = require_role(Role.ANALYST)
require_admin = require_role(Role.ADMIN)


async def broadcast_ws(data: dict[str, Any]):
    """Broadcast data to all connected WebSocket clients."""
    disconnected: list[tuple[WebSocket, AuthenticatedUser | None]] = []

    for ws, user in state.websocket_clients:
        try:
            role = user.role.value if user else Role.VIEWER.value
            await ws.send_text(json.dumps(redact_ws_payload(data, role)))
        except Exception:
            disconnected.append((ws, user))

    for client in disconnected:
        state.websocket_clients.remove(client)


async def run_cicddos_training_job(
    *,
    job_id: str,
    upload_path: Path,
    filename: str,
    model_type: str,
    target_column: str | None,
    user: AuthenticatedUser | None,
    req_id: str,
) -> None:
    """Train an offline tabular classifier without blocking API requests."""
    outcome = "failed"
    details: dict[str, Any] = {
        "filename": filename,
        "job_id": job_id,
        "model_type": model_type,
        "target_column": target_column,
    }
    try:
        status = await asyncio.to_thread(
            state.cicddos_trainer.train_uploaded_dataset,
            upload_path,
            job_id=job_id,
            filename=filename,
            model_type=model_type,
            target_column=target_column,
        )
        outcome = "executed"
        details["result"] = status.get("result")
    except (CICDDOSTrainingError, OSError, ValueError) as error:
        status = state.cicddos_trainer.mark_failed(job_id, str(error))
        details["error"] = str(error)
        logger.warning("cicddos_training_failed", job_id=job_id, error=str(error))
    except Exception as error:
        status = state.cicddos_trainer.mark_failed(job_id, "Dataset training failed.")
        details["error"] = str(error)
        logger.exception("cicddos_training_unexpected_failure", job_id=job_id)
    finally:
        upload_path.unlink(missing_ok=True)

    state.audit.append(
        actor_user_id=user.user_id if user else None,
        actor_role=user.role.value if user else None,
        action="cicddos_flow_training",
        target_type="ml_model",
        target_id=job_id,
        outcome=outcome,
        request_id=req_id,
        details=details,
    )


# ─── App Lifecycle ───────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle manager."""
    setup_logging(log_level="INFO", json_output=False)
    logger.info("application_starting")

    try:
        state.initialize_control_plane()
        state.validate_capture_configuration()
    except (RuntimeError, TSharkConfigurationError) as e:
        logger.error("startup_safety_or_capture_error", error=str(e))
        raise

    # Start detection and local protection monitors in background
    pipeline_task = asyncio.create_task(run_detection_pipeline())
    local_threat_task = asyncio.create_task(run_local_threat_monitor())
    capture_state_task = asyncio.create_task(run_capture_state_monitor())

    yield

    # Shutdown
    state.is_running = False
    for task in (pipeline_task, local_threat_task, capture_state_task):
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    logger.info("application_stopped")


# ─── FastAPI App ─────────────────────────────────────────────

app = FastAPI(
    title="DDoS Detection System",
    description="Enterprise-grade real-time DDoS detection and response",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def enforce_secure_transport(request: Request, call_next):
    host = (request.url.hostname or "").lower()
    localhost = host in {"localhost", "127.0.0.1", "::1"}
    requires_https = settings.is_production or settings.api.require_https
    forwarded_proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    if requires_https and not localhost and forwarded_proto != "https":
        if request.method == "GET" and not request.url.path.startswith("/api/"):
            return RedirectResponse(str(request.url.replace(scheme="https")), status_code=307)
        return JSONResponse(
            status_code=426,
            content={"detail": "HTTPS is required for this endpoint"},
        )
    response = await call_next(request)
    no_store_paths = {
        "/",
        "/login",
        "/api/training/cicddos/status",
        "/api/models/validation",
        "/api/admin/capture/diagnostics",
    }
    if request.url.path in no_store_paths or request.url.path.startswith(("/css/", "/js/")):
        response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


# Serve dashboard static files — mount css/ and js/ at matching URL paths
dashboard_path = Path(__file__).parent.parent.parent / "dashboard"

# ─── REST Endpoints ──────────────────────────────────────────


@app.get("/")
async def root():
    """Serve the public monitor-only dashboard."""
    index_path = dashboard_path / "index.html"
    if index_path.exists():
        return FileResponse(
            str(index_path),
            media_type="text/html",
            headers={"Cache-Control": "no-store, max-age=0"},
        )
    return {"message": "DDoS Detection System API", "version": "1.0.0"}


@app.get("/login")
async def login_page(request: Request):
    """Serve the unauthenticated login view."""
    if state.auth.authenticate_token(request.cookies.get(SESSION_COOKIE_NAME)) is not None:
        return RedirectResponse("/", status_code=303)
    return FileResponse(
        str(dashboard_path / "login.html"),
        media_type="text/html",
        headers={"Cache-Control": "no-store, max-age=0"},
    )


# Mount static subdirectories AFTER explicit routes so / still works.
# This must come after the @app.get("/") so FastAPI checks the explicit route first.
if dashboard_path.exists():
    css_path = dashboard_path / "css"
    js_path = dashboard_path / "js"
    if css_path.exists():
        app.mount("/css", StaticFiles(directory=str(css_path)), name="css")
    if js_path.exists():
        app.mount("/js", StaticFiles(directory=str(js_path)), name="js")


@app.post("/api/auth/login")
async def login(payload: LoginRequest, request: Request, response: Response):
    result = state.auth.login(payload.username, payload.password)
    req_id = request_id(request)
    if result is None:
        state.audit.append(
            action="login",
            target_type="auth_session",
            target_id=payload.username,
            outcome="rejected",
            request_id=req_id,
            details={"reason": "invalid credentials"},
        )
        raise HTTPException(status_code=401, detail="invalid credentials")
    token, user, expires_at = result
    state.audit.append(
        actor_user_id=user.user_id,
        actor_role=user.role.value,
        action="login",
        target_type="auth_session",
        target_id=user.jti,
        outcome="executed",
        request_id=req_id,
    )
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        httponly=True,
        secure=settings.is_production or settings.api.require_https,
        samesite="strict",
        max_age=settings.jwt.jwt_expiration_minutes * 60,
        path="/",
    )
    return {"user": user.to_dict(), "expires_at": expires_at}


@app.post("/api/auth/logout")
async def logout(
    request: Request, response: Response, user: AuthenticatedUser = Depends(require_viewer)
):
    state.auth.logout(request.cookies.get(SESSION_COOKIE_NAME))
    state.audit.append(
        actor_user_id=user.user_id,
        actor_role=user.role.value,
        action="logout",
        target_type="auth_session",
        target_id=user.jti,
        outcome="executed",
        request_id=request_id(request),
    )
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"success": True}


@app.get("/api/auth/me")
async def auth_me(user: AuthenticatedUser = Depends(require_viewer)):
    return {"user": user.to_dict()}


@app.get("/api/health/live")
@app.get("/api/health")
async def health_live():
    return {"status": "alive"}


@app.get("/api/health/ready")
async def health_ready():
    return readiness_payload()


@app.get("/api/metrics")
async def get_metrics():
    return {"metrics": state.metrics, **capture_status_payload()}


@app.get("/api/alerts")
async def get_alerts(
    severity: str | None = Query(default=None),
    source: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    user: AuthenticatedUser = Depends(require_analyst),
):
    alerts = state.alert_engine.get_alerts(
        severity=severity,
        source=source,
        status=status,
        limit=limit,
    )
    visible_alerts = redact_alerts(alerts, user.role.value)
    return {"alerts": visible_alerts, "total": len(visible_alerts)}


@app.get("/api/alerts/active")
async def get_active_alerts(
    severity: str | None = Query(default=None),
    source: str | None = Query(default=None),
    status: str | None = Query(default=None),
    user: AuthenticatedUser = Depends(require_analyst),
):
    alerts = state.alert_engine.get_active_alerts(severity=severity, source=source, status=status)
    return {"alerts": redact_alerts(alerts, user.role.value)}


@app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_analyst),
):
    success = state.alert_engine.acknowledge_alert(alert_id, user=user.username)
    state.audit.append(
        actor_user_id=user.user_id,
        actor_role=user.role.value,
        action="alert_acknowledge",
        target_type="alert",
        target_id=alert_id,
        outcome="executed" if success else "not_found",
        request_id=request_id(request),
    )
    return {"success": success}


@app.post("/api/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_analyst),
):
    success = state.alert_engine.resolve_alert(alert_id)
    state.audit.append(
        actor_user_id=user.user_id,
        actor_role=user.role.value,
        action="alert_resolve",
        target_type="alert",
        target_id=alert_id,
        outcome="executed" if success else "not_found",
        request_id=request_id(request),
    )
    return {"success": success}


@app.post("/api/response/block-ip")
async def block_ip(
    payload: BlockIPRequest,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin),
):
    action = state.response_engine.block_ip(
        payload.ip,
        reason=payload.reason,
        ttl_seconds=payload.ttl_seconds,
        requested_by=user.username,
        source="manual",
    )
    state.audit.append(
        actor_user_id=user.user_id,
        actor_role=user.role.value,
        action="block_ip_request",
        target_type="ip_address",
        target_id=payload.ip,
        reason=payload.reason,
        outcome=action["status"],
        request_id=request_id(request),
    )
    response_stats = state.response_engine.stats
    state.metrics["response_active_blocks"] = response_stats["active_blocks"]
    state.metrics["response_actions"] = response_stats["actions_total"]
    return {"action": action}


@app.post("/api/response/unblock-ip")
async def unblock_ip(
    payload: UnblockIPRequest,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin),
):
    action = state.response_engine.unblock_ip(
        payload.ip,
        reason=payload.reason,
        requested_by=user.username,
    )
    state.audit.append(
        actor_user_id=user.user_id,
        actor_role=user.role.value,
        action="unblock_ip_request",
        target_type="ip_address",
        target_id=payload.ip,
        reason=payload.reason,
        outcome=action["status"],
        request_id=request_id(request),
    )
    response_stats = state.response_engine.stats
    state.metrics["response_active_blocks"] = response_stats["active_blocks"]
    state.metrics["response_actions"] = response_stats["actions_total"]
    return {"action": action}


@app.get("/api/response/actions")
async def get_response_actions(
    status: str | None = Query(default=None),
    action_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    user: AuthenticatedUser = Depends(require_admin),
):
    return {
        "actions": state.response_engine.get_actions(
            status=status, action_type=action_type, limit=limit
        ),
        "active_blocks": state.response_engine.get_active_blocks(),
    }


@app.get("/api/response/status")
async def get_response_status(user: AuthenticatedUser = Depends(require_admin)):
    return {
        "stats": state.response_engine.stats,
        "active_blocks": state.response_engine.get_active_blocks(),
    }


@app.post("/api/admin/response/kill-switch")
async def update_kill_switch(
    payload: KillSwitchRequest,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin),
):
    control = state.response_control.update_kill_switch(
        enabled=payload.enabled,
        reason=payload.reason,
        actor_user_id=user.user_id,
        actor_role=user.role.value,
        actor_username=user.username,
        request_id=request_id(request),
    )
    return {"control": control.to_dict()}


@app.post("/api/admin/response/mode")
async def update_response_mode(
    payload: ResponseModeRequest,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin),
):
    try:
        control = state.response_control.update_mode(
            mode=payload.mode,
            auto_block_enabled=payload.auto_block_enabled,
            reason=payload.reason,
            confirmation=payload.confirmation,
            actor_user_id=user.user_id,
            actor_role=user.role.value,
            actor_username=user.username,
            request_id=request_id(request),
        )
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    return {"control": control.to_dict()}


@app.get("/api/admin/audit")
async def audit_events(
    limit: int = Query(default=100, ge=1, le=500),
    action: str | None = Query(default=None),
    since: float | None = Query(default=None),
    user: AuthenticatedUser = Depends(require_admin),
):
    return {"events": state.audit.list(limit=limit, action=action, since=since)}


@app.get("/api/training/cicddos/status")
async def cicddos_training_status():
    return state.cicddos_trainer.status()


@app.get("/api/models/validation")
async def model_validation_status():
    return model_validation_payload()


@app.post("/api/training/cicddos/upload", status_code=202)
async def upload_cicddos_training_csv(
    request: Request,
    filename: str = Query(..., min_length=1, max_length=255),
    model_type: str = Query(default=DEFAULT_MODEL_TYPE, min_length=1, max_length=64),
    target_column: str | None = Query(default=None, min_length=1, max_length=128),
):
    """Accept a public raw CSV/ZIP request body and queue bounded offline tabular training."""
    user = state.auth.authenticate_token(request.cookies.get(SESSION_COOKIE_NAME))
    safe_filename = Path(filename).name
    if not is_supported_training_filename(safe_filename):
        raise HTTPException(
            status_code=415,
            detail="Only .csv, .csv.gz, .csv.bz2, .csv.xz, or .zip training files are accepted.",
        )
    try:
        canonical_model_type = normalize_model_type(model_type)
    except CICDDOSTrainingError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    normalized_target_column = target_column.strip() if target_column else None

    max_bytes = state.settings.ml.training_max_upload_bytes
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > max_bytes:
                raise HTTPException(
                    status_code=413, detail="Dataset upload exceeds configured size limit."
                )
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header.")

    try:
        job_id, upload_path = state.cicddos_trainer.begin_upload(
            safe_filename,
            model_type=canonical_model_type,
        )
    except CICDDOSTrainingError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error

    uploaded_bytes = 0
    try:
        with upload_path.open("wb") as handle:
            async for chunk in request.stream():
                uploaded_bytes += len(chunk)
                if uploaded_bytes > max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail="Dataset upload exceeds configured size limit.",
                    )
                handle.write(chunk)
        if uploaded_bytes == 0:
            raise HTTPException(status_code=400, detail="The uploaded dataset is empty.")
    except HTTPException as error:
        upload_path.unlink(missing_ok=True)
        state.cicddos_trainer.mark_failed(job_id, str(error.detail))
        raise
    except OSError as error:
        upload_path.unlink(missing_ok=True)
        state.cicddos_trainer.mark_failed(job_id, "Failed to store uploaded dataset.")
        raise HTTPException(status_code=500, detail="Failed to store uploaded dataset.") from error

    status = state.cicddos_trainer.mark_queued(job_id, uploaded_bytes)
    req_id = request_id(request)
    state.audit.append(
        actor_user_id=user.user_id if user else None,
        actor_role=user.role.value if user else None,
        action="cicddos_flow_training_upload",
        target_type="dataset",
        target_id=job_id,
        outcome="queued",
        request_id=req_id,
        details={
            "filename": safe_filename,
            "uploaded_bytes": uploaded_bytes,
            "model_type": canonical_model_type,
            "target_column": normalized_target_column,
        },
    )
    task = asyncio.create_task(
        run_cicddos_training_job(
            job_id=job_id,
            upload_path=upload_path,
            filename=safe_filename,
            model_type=canonical_model_type,
            target_column=normalized_target_column,
            user=user,
            req_id=req_id,
        )
    )
    state.training_tasks.add(task)
    task.add_done_callback(state.training_tasks.discard)
    return status


@app.get("/api/detection/status")
async def detection_status():
    return {
        **readiness_payload(),
        "current_attack": state.current_attack,
        "models": {"ensemble": state.ensemble_model.stats},
    }


@app.get("/api/traffic/history")
async def traffic_history():
    return {"history": state.traffic_history[-120:]}


@app.get("/api/features/latest")
async def latest_features():
    return {"features": state.feature_store.get_latest()}


@app.get("/api/local-security/status")
async def local_security_status(user: AuthenticatedUser = Depends(require_admin)):
    wireless_analyzer = state.local_threat_guard.wireless_analyzer
    return {
        "enabled": state.settings.local_threat.local_threat_monitor_enabled,
        "response_mode": state.settings.local_threat.local_threat_response_mode.value,
        "auto_disconnect": state.settings.local_threat.local_threat_auto_disconnect,
        "auto_disable_adapters": state.settings.local_threat.local_threat_auto_disable_adapters,
        "wireless_intelligence_enabled": state.settings.local_threat.wireless_intelligence_enabled,
        "wireless_capabilities": (
            wireless_analyzer.status() if wireless_analyzer else {"enabled": False}
        ),
        "snapshot": state.local_threat_snapshot,
    }


@app.post("/api/local-security/scan")
async def local_security_scan(request: Request, user: AuthenticatedUser = Depends(require_admin)):
    snapshot = await asyncio.to_thread(state.local_threat_guard.scan)
    await process_local_threat_snapshot(snapshot)
    state.audit.append(
        actor_user_id=user.user_id,
        actor_role=user.role.value,
        action="local_security_scan",
        target_type="host",
        outcome="executed",
        request_id=request_id(request),
    )
    return state.local_threat_snapshot


@app.get("/api/admin/capture/diagnostics")
async def capture_diagnostics(user: AuthenticatedUser = Depends(require_admin)):
    return capture_diagnostics_payload()


@app.get("/api/system/stats")
async def system_stats(user: AuthenticatedUser = Depends(require_admin)):
    return {
        "metrics": state.metrics,
        "feature_store": state.feature_store.stats,
        "alert_engine": state.alert_engine.stats,
        "response_engine": state.response_engine.stats,
        "detection": state.ensemble_model.stats,
        "window_aggregator": state.window_aggregator.stats,
        "capture": state.tshark_capture.stats if state.tshark_capture else None,
        "local_security": state.local_threat_snapshot,
        **capture_status_payload(),
    }


# ─── WebSocket Endpoint ─────────────────────────────────────


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    user = state.auth.authenticate_token(websocket.cookies.get(SESSION_COOKIE_NAME))
    origin = websocket.headers.get("origin")
    same_origin = (
        bool(origin)
        and urlparse(origin).netloc.lower() == websocket.headers.get("host", "").lower()
    )
    allowed_origin = not origin or same_origin or origin in settings.api.cors_origins_list
    if not allowed_origin:
        await websocket.close(code=4403)
        return
    host = (websocket.url.hostname or "").lower()
    localhost = host in {"localhost", "127.0.0.1", "::1"}
    if (settings.is_production or settings.api.require_https) and not localhost:
        forwarded_proto = websocket.headers.get("x-forwarded-proto", websocket.url.scheme)
        if forwarded_proto not in {"https", "wss"}:
            await websocket.close(code=4403)
            return
    await websocket.accept()
    client = (websocket, user)
    state.websocket_clients.append(client)
    logger.info("websocket_client_connected", total_clients=len(state.websocket_clients))
    role = user.role.value if user else Role.VIEWER.value
    await websocket.send_json(redact_ws_payload({"type": "status", **readiness_payload()}, role))

    try:
        while True:
            # Keep connection alive, handle client messages
            data = await websocket.receive_text()
            msg = json.loads(data)

            if msg.get("type") == "ping":
                await websocket.send_json({"type": "pong"})

    except WebSocketDisconnect:
        if client in state.websocket_clients:
            state.websocket_clients.remove(client)
        logger.info("websocket_client_disconnected", total_clients=len(state.websocket_clients))
    except Exception as e:
        if client in state.websocket_clients:
            state.websocket_clients.remove(client)
        logger.warning("websocket_client_error", error=str(e))


# ─── Main Entry Point ───────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
