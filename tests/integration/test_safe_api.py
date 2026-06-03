"""Authenticated API and WebSocket behavior for Release 1."""

import asyncio
import io
import json
import time
import zipfile

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from src.alerting.alert_engine import AlertEngine
from src.api import server
from src.api.auth import AuthService, Role
from src.config.settings import CaptureSource
from src.control.response_control import ResponseControlService
from src.detection.cicddos_training import CICDDOSTrainingService
from src.response.response_engine import ResponseEngine
from src.storage.audit_repository import AuditRepository
from src.storage.database import Database
from src.storage.repositories import RuntimeControlRepository, SessionRepository, UserRepository


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    database = Database(f"sqlite:///{tmp_path / 'api.db'}")
    database.initialize()
    users = UserRepository(database)
    sessions = SessionRepository(database)
    audit = AuditRepository(database)
    auth = AuthService(
        users,
        sessions,
        secret_key="integration-secret",
        algorithm="HS256",
        expiration_minutes=15,
    )
    auth.create_user("admin", "integration-admin-pass", Role.ADMIN)
    auth.create_user("analyst", "integration-analyst-pass", Role.ANALYST)
    auth.create_user("viewer", "integration-viewer-pass", Role.VIEWER)

    control = ResponseControlService(
        RuntimeControlRepository(database),
        audit,
        mitigation_activation_allowed=False,
    )
    response_engine = ResponseEngine.from_settings(server.state.settings.response)
    response_engine.set_policy_provider(control.engine_policy)

    monkeypatch.setattr(server.state, "database", database)
    monkeypatch.setattr(server.state, "users", users)
    monkeypatch.setattr(server.state, "sessions", sessions)
    monkeypatch.setattr(server.state, "audit", audit)
    monkeypatch.setattr(server.state, "auth", auth)
    monkeypatch.setattr(server.state, "response_control", control)
    monkeypatch.setattr(server.state, "response_engine", response_engine)
    monkeypatch.setattr(server.state, "alert_engine", AlertEngine())
    monkeypatch.setattr(
        server.state,
        "cicddos_trainer",
        CICDDOSTrainingService(
            model_dir=tmp_path / "models",
            upload_dir=tmp_path / "uploads",
            max_rows_per_class=20,
        ),
    )
    monkeypatch.setattr(server.state.settings.capture, "capture_source", CaptureSource.SIMULATION)
    monkeypatch.setattr(server.settings.api, "require_https", False)
    monkeypatch.setattr(server.state, "model_ready", True)
    monkeypatch.setattr(server.state, "capture_state", "idle")

    async def idle_pipeline():
        server.state.is_running = True
        await asyncio.Event().wait()

    async def idle_monitor():
        await asyncio.Event().wait()

    monkeypatch.setattr(server, "run_detection_pipeline", idle_pipeline)
    monkeypatch.setattr(server, "run_local_threat_monitor", idle_monitor)

    with TestClient(server.app, base_url="http://localhost:8000", follow_redirects=False) as client:
        yield client, audit


def login(client: TestClient, username: str, password: str) -> None:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200


def test_public_monitor_dashboard_and_readiness_work_without_login(api_client):
    client, _ = api_client
    assert client.get("/api/health/live").json() == {"status": "alive"}
    response = client.get("/")
    assert response.status_code == 200
    assert "operational-banner" in response.text
    assert "Model Training / Tabular CSV" in response.text
    assert "Algorithm Validation Metrics" in response.text
    assert "Available to all dashboard users." in response.text
    assert "training-model-type" in response.text
    assert "training-target-column" in response.text
    assert 'src="js/vendor/chart.umd.min.js?v=20260527-enterprise-1"' in response.text
    assert 'href="css/enterprise-theme.css?v=20260528-anomaly-metrics-1"' in response.text
    assert 'src="js/app.js?v=20260528-anomaly-metrics-1"' in response.text
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert "cdn.jsdelivr.net/npm/chart.js" not in response.text
    chart_asset = client.get("/js/vendor/chart.umd.min.js")
    assert chart_asset.status_code == 200
    assert chart_asset.headers["cache-control"] == "no-store, max-age=0"
    assert "Chart.js v4.4.0" in chart_asset.text
    ready = client.get("/api/health/ready")
    assert ready.status_code == 200
    assert ready.json()["response_mode"] == "monitor"
    assert client.get("/api/metrics").status_code == 200
    assert client.get("/api/training/cicddos/status").status_code == 200
    validation_response = client.get("/api/models/validation")
    assert validation_response.headers["cache-control"] == "no-store, max-age=0"
    validation = validation_response.json()
    models = {model["id"]: model for model in validation["models"]}
    assert models["isolation_forest"]["primary_metric"] == "Validation F1"
    assert {item["label"] for item in models["isolation_forest"]["details"]} >= {
        "Recall",
        "Trees",
        "Contamination",
    }
    assert models["autoencoder"]["primary_metric"] == "Validation F1"
    assert {item["label"] for item in models["autoencoder"]["details"]} >= {
        "Recall",
        "Error threshold",
        "Normal MSE p95",
        "Attack MSE p50",
    }
    assert "cicddos_flow_classifier" in models
    assert "supported_model_types" in client.get("/api/training/cicddos/status").json()
    assert client.get("/api/response/status").status_code == 401


def test_admin_control_is_audited_but_enforcement_is_rejected(api_client):
    client, audit = api_client
    login(client, "admin", "integration-admin-pass")

    response = client.post(
        "/api/admin/response/kill-switch",
        json={"enabled": True, "reason": "keep containment active"},
    )
    assert response.status_code == 200
    response = client.post(
        "/api/admin/response/mode",
        json={
            "mode": "enforce",
            "auto_block_enabled": True,
            "reason": "must be rejected",
            "confirmation": "ENABLE_ENFORCEMENT",
        },
    )
    assert response.status_code == 409
    assert audit.list(action="response_mode_change")[0]["outcome"] == "rejected"

    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/health/ready").status_code == 200


def test_rbac_limits_viewer_and_analyst(api_client):
    client, _ = api_client
    login(client, "viewer", "integration-viewer-pass")
    assert client.get("/api/metrics").status_code == 200
    assert client.get("/api/alerts").status_code == 403
    client.post("/api/auth/logout")

    login(client, "analyst", "integration-analyst-pass")
    assert client.get("/api/alerts").status_code == 200
    assert client.post("/api/alerts/not-present/acknowledge").status_code == 200
    assert client.get("/api/local-security/status").status_code == 403


def test_admin_local_security_status_reports_wireless_capabilities(api_client):
    client, _ = api_client
    login(client, "admin", "integration-admin-pass")

    response = client.get("/api/local-security/status")

    assert response.status_code == 200
    status = response.json()
    assert status["wireless_intelligence_enabled"] is True
    assert "wireless_capabilities" in status
    assert "oui_vendor_lookup" in status["wireless_capabilities"]["capabilities"]


def test_admin_capture_diagnostics_requires_admin(api_client, monkeypatch):
    client, _ = api_client
    monkeypatch.setattr(
        server,
        "capture_diagnostics_payload",
        lambda: {
            "capture_source": "tshark",
            "configured_interface": "auto",
            "capture_filter": "ip or ip6",
            "tshark": {
                "available": True,
                "resolved_path": "C:/Program Files/Wireshark/tshark.exe",
                "interfaces": [{"index": 1, "name": "Wi-Fi", "display_name": "Adapter (Wi-Fi)"}],
                "resolved_capture_interface": "Wi-Fi",
                "error": None,
            },
        },
    )

    assert client.get("/api/admin/capture/diagnostics").status_code == 401

    login(client, "viewer", "integration-viewer-pass")
    assert client.get("/api/admin/capture/diagnostics").status_code == 403
    client.post("/api/auth/logout")

    login(client, "admin", "integration-admin-pass")
    response = client.get("/api/admin/capture/diagnostics")

    assert response.status_code == 200
    diagnostics = response.json()
    assert diagnostics["tshark"]["available"] is True
    assert diagnostics["tshark"]["resolved_capture_interface"] == "Wi-Fi"


def test_public_user_can_upload_cicddos_csv_for_offline_flow_training(api_client):
    client, audit = api_client
    csv_lines = ["Flow Duration,Total Fwd Packets,Flow Bytes/s,Label"]
    csv_lines.extend(f"{100 + index},{2 + index},{300 + index},BENIGN" for index in range(25))
    csv_lines.extend(
        f"{10000 + index},{200 + index},{90000 + index},DrDoS_DNS" for index in range(25)
    )
    csv_body = ("\n".join(csv_lines) + "\n").encode("utf-8")

    queued = client.post(
        "/api/training/cicddos/upload?filename=sample.csv",
        content=csv_body,
        headers={"content-type": "text/csv"},
    )
    assert queued.status_code == 202
    assert queued.json()["state"] in {"queued", "training", "ready"}

    status = {}
    for _ in range(200):
        status = client.get("/api/training/cicddos/status").json()
        if status["state"] in {"ready", "failed"}:
            break
        time.sleep(0.05)

    assert status["state"] == "ready"
    assert status["live_model_active"] is False
    assert status["model_type"] == "hist_gradient_boosting"
    assert status["result"]["requested_model_type"] == "hist_gradient_boosting"
    assert status["result"]["selected_model_type"] == "hist_gradient_boosting"
    assert status["result"]["rows_used"] == 40
    assert status["result"]["feature_count"] == 3
    validation_models = {
        model["id"]: model for model in client.get("/api/models/validation").json()["models"]
    }
    assert (
        validation_models["cicddos_flow_classifier"]["primary_value"]
        == status["result"]["balanced_accuracy"]
    )
    assert (
        validation_models["cicddos_flow_classifier"]["secondary_value"]
        == status["result"]["accuracy"]
    )
    upload_event = audit.list(action="cicddos_flow_training_upload")[0]
    training_event = audit.list(action="cicddos_flow_training")[0]
    assert upload_event["outcome"] == "queued"
    assert upload_event["actor_user_id"] is None
    assert training_event["outcome"] == "executed"
    assert training_event["actor_user_id"] is None


def test_public_user_can_choose_cicddos_model_type(api_client):
    client, audit = api_client
    csv_lines = ["Flow Duration,Total Fwd Packets,Flow Bytes/s,Label"]
    csv_lines.extend(f"{100 + index},{2 + index},{300 + index},BENIGN" for index in range(25))
    csv_lines.extend(
        f"{10000 + index},{200 + index},{90000 + index},DrDoS_DNS" for index in range(25)
    )
    csv_body = ("\n".join(csv_lines) + "\n").encode("utf-8")

    queued = client.post(
        "/api/training/cicddos/upload?filename=sample.csv&model_type=logistic_regression",
        content=csv_body,
        headers={"content-type": "text/csv"},
    )
    assert queued.status_code == 202
    assert queued.json()["model_type"] == "logistic_regression"

    status = {}
    for _ in range(200):
        status = client.get("/api/training/cicddos/status").json()
        if status["state"] in {"ready", "failed"}:
            break
        time.sleep(0.05)

    assert status["state"] == "ready"
    assert status["result"]["requested_model_type"] == "logistic_regression"
    assert status["result"]["selected_model_type"] == "logistic_regression"
    assert status["result"]["model_name"] == "Logistic Regression"
    upload_details = json.loads(
        audit.list(action="cicddos_flow_training_upload")[0]["details_json"]
    )
    assert upload_details["model_type"] == "logistic_regression"


def test_public_user_can_train_generic_dataset_with_target_column(api_client):
    client, _ = api_client
    csv_lines = ["duration,protocol,region,outcome"]
    for index in range(24):
        csv_lines.append(f"{100 + index},tcp,us,clean")
    for index in range(24):
        csv_lines.append(f"{900 + index},udp,eu,attack")
    csv_body = ("\n".join(csv_lines) + "\n").encode("utf-8")

    queued = client.post(
        "/api/training/cicddos/upload?filename=generic.csv&model_type=auto&target_column=outcome",
        content=csv_body,
        headers={"content-type": "text/csv"},
    )
    assert queued.status_code == 202

    status = {}
    for _ in range(200):
        status = client.get("/api/training/cicddos/status").json()
        if status["state"] in {"ready", "failed"}:
            break
        time.sleep(0.05)

    assert status["state"] == "ready"
    result = status["result"]
    assert result["target_column"] == "outcome"
    assert result["class_count"] == 2
    assert result["categorical_feature_count"] == 2
    assert result["numeric_feature_count"] == 1
    assert result["model_selection"] == "auto"
    assert len(result["candidate_metrics"]) >= 2
    assert all("accuracy" in metric for metric in result["candidate_metrics"] if metric["status"] == "trained")


def test_invalid_cicddos_model_type_is_rejected(api_client):
    client, _ = api_client
    response = client.post(
        "/api/training/cicddos/upload?filename=sample.csv&model_type=not_a_model",
        content=b"Flow Duration,Total Fwd Packets,Flow Bytes/s,Label\n1,2,3,BENIGN\n",
        headers={"content-type": "text/csv"},
    )

    assert response.status_code == 400
    assert "Unsupported model_type" in response.json()["detail"]


def test_public_user_can_train_from_cicddos_zip_archive(api_client):
    client, _ = api_client

    def csv_payload(attack_name: str, offset: int) -> str:
        rows = ["Unnamed: 0,Flow Duration,Total Fwd Packets,Flow Bytes/s,Label"]
        rows.extend(
            f"{index},{100 + index},{2 + index},{300 + index},BENIGN" for index in range(25)
        )
        rows.extend(
            f"{25 + index},{offset + index},{200 + index},{90000 + index},{attack_name}"
            for index in range(25)
        )
        return "\n".join(rows) + "\n"

    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("01-12/DrDoS_DNS.csv", csv_payload("DrDoS_DNS", 10000))
        archive.writestr("01-12/Syn.csv", csv_payload("Syn", 20000))

    queued = client.post(
        "/api/training/cicddos/upload?filename=CSV-01-12.zip",
        content=payload.getvalue(),
        headers={"content-type": "application/zip"},
    )
    assert queued.status_code == 202

    status = {}
    for _ in range(200):
        status = client.get("/api/training/cicddos/status").json()
        if status["state"] in {"ready", "failed"}:
            break
        time.sleep(0.05)

    assert status["state"] == "ready"
    assert status["result"]["rows_used"] == 60
    assert "Unnamed: 0" not in status["result"]["feature_names"]
    assert status["result"]["source_files"] == ["01-12/DrDoS_DNS.csv", "01-12/Syn.csv"]
    assert status["result"]["class_count"] == 3
    assert status["result"]["label_counts"]["DrDoS_DNS"] == 20
    assert status["result"]["label_counts"]["Syn"] == 20


def test_public_user_can_train_from_nested_cicddos_zip_archive(api_client):
    client, _ = api_client

    rows = ["Flow Duration,Total Fwd Packets,Flow Bytes/s,Label"]
    rows.extend(f"{100 + index},{2 + index},{300 + index},BENIGN" for index in range(25))
    rows.extend(f"{10000 + index},{200 + index},{90000 + index},Syn" for index in range(25))
    inner_payload = io.BytesIO()
    with zipfile.ZipFile(inner_payload, "w", zipfile.ZIP_DEFLATED) as inner:
        inner.writestr("inner/Syn.csv", "\n".join(rows) + "\n")

    outer_payload = io.BytesIO()
    with zipfile.ZipFile(outer_payload, "w", zipfile.ZIP_DEFLATED) as outer:
        outer.writestr("CSV-01-12.zip", inner_payload.getvalue())

    queued = client.post(
        "/api/training/cicddos/upload?filename=nested.zip&model_type=random_forest",
        content=outer_payload.getvalue(),
        headers={"content-type": "application/zip"},
    )
    assert queued.status_code == 202

    status = {}
    for _ in range(200):
        status = client.get("/api/training/cicddos/status").json()
        if status["state"] in {"ready", "failed"}:
            break
        time.sleep(0.05)

    assert status["state"] == "ready"
    assert status["result"]["selected_model_type"] == "random_forest"
    assert status["result"]["source_files"] == ["CSV-01-12.zip!inner/Syn.csv"]


def test_zip_without_csv_reports_archive_entries(api_client):
    client, _ = api_client
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("readme.txt", "not a dataset")

    queued = client.post(
        "/api/training/cicddos/upload?filename=no-csv.zip",
        content=payload.getvalue(),
        headers={"content-type": "application/zip"},
    )
    assert queued.status_code == 202

    status = {}
    for _ in range(200):
        status = client.get("/api/training/cicddos/status").json()
        if status["state"] in {"ready", "failed"}:
            break
        time.sleep(0.05)

    assert status["state"] == "failed"
    assert "ZIP does not contain any CSV files" in status["message"]
    assert "readme.txt" in status["message"]


def test_websocket_allows_public_masked_monitor_and_accepts_admin(api_client):
    client, _ = api_client
    with client.websocket_connect("ws://localhost:8000/ws") as socket:
        message = socket.receive_json()
        assert message["type"] == "status"
        assert message["response_mode"] == "monitor"

    login(client, "admin", "integration-admin-pass")
    with client.websocket_connect("ws://localhost:8000/ws") as socket:
        message = socket.receive_json()
        assert message["type"] == "status"
        assert message["response_mode"] == "monitor"


def test_websocket_rejects_unconfigured_origin(api_client):
    client, _ = api_client
    with pytest.raises(WebSocketDisconnect) as rejected:
        with client.websocket_connect(
            "ws://localhost:8000/ws",
            headers={"origin": "https://untrusted.example"},
        ):
            pass
    assert rejected.value.code == 4403


def test_cors_rejects_unconfigured_origin(api_client):
    client, _ = api_client
    response = client.options(
        "/api/auth/login",
        headers={
            "Origin": "https://untrusted.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert response.status_code == 400


def test_https_is_required_for_non_localhost_when_enabled(api_client, monkeypatch):
    client, _ = api_client
    monkeypatch.setattr(server.settings.api, "require_https", True)

    response = client.post(
        "http://sensor.example/api/auth/login",
        json={"username": "admin", "password": "integration-admin-pass"},
    )
    assert response.status_code == 426

    local_response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "integration-admin-pass"},
    )
    assert local_response.status_code == 200
