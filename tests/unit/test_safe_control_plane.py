"""Safety tests for Release 1 authentication, controls, and audit storage."""

import sqlite3

import pytest

from src.api.auth import AuthService, Role
from src.api.redaction import redact_ws_payload
from src.config.settings import ResponseMode, Settings
from src.control.response_control import ResponseControlService
from src.response.response_engine import ResponseEngine
from src.storage.audit_repository import AuditRepository
from src.storage.database import Database
from src.storage.repositories import RuntimeControlRepository, SessionRepository, UserRepository


def make_database(tmp_path) -> Database:
    database = Database(f"sqlite:///{tmp_path / 'control.db'}")
    database.initialize()
    return database


def test_startup_guard_rejects_enforcement_without_release_gate(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RESPONSE_MODE", "enforce")
    monkeypatch.setenv("AUTO_BLOCK_ENABLED", "true")
    monkeypatch.setenv("MITIGATION_ACTIVATION_ALLOWED", "false")
    settings = Settings()

    with pytest.raises(RuntimeError, match="MITIGATION_ACTIVATION_ALLOWED"):
        settings.validate_runtime_safety()


def test_startup_guard_rejects_local_adapter_enforcement(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LOCAL_THREAT_RESPONSE_MODE", "enforce")
    monkeypatch.setenv("LOCAL_THREAT_AUTO_DISABLE_ADAPTERS", "true")
    monkeypatch.setenv("LOCAL_THREAT_ENFORCEMENT_ALLOWED", "false")
    settings = Settings()

    with pytest.raises(RuntimeError, match="LOCAL_THREAT_ENFORCEMENT_ALLOWED"):
        settings.validate_runtime_safety()


def test_runtime_control_defaults_safe_and_refuses_release_one_enforcement(tmp_path):
    database = make_database(tmp_path)
    audit = AuditRepository(database)
    service = ResponseControlService(
        RuntimeControlRepository(database),
        audit,
        mitigation_activation_allowed=False,
    )

    initial = service.initialize()
    assert initial.mode == ResponseMode.MONITOR
    assert initial.auto_block_enabled is False
    assert initial.kill_switch is True

    with pytest.raises(ValueError, match="Release 1"):
        service.update_mode(
            mode=ResponseMode.ENFORCE,
            auto_block_enabled=True,
            reason="test attempt",
            confirmation="ENABLE_ENFORCEMENT",
            actor_user_id="admin-1",
            actor_role="admin",
            actor_username="admin",
            request_id="request-1",
        )

    events = audit.list(action="response_mode_change")
    assert events[0]["outcome"] == "rejected"


def test_response_engine_obeys_persistent_kill_switch(tmp_path):
    database = make_database(tmp_path)
    service = ResponseControlService(
        RuntimeControlRepository(database),
        AuditRepository(database),
        mitigation_activation_allowed=False,
    )
    service.initialize()
    engine = ResponseEngine(mode=ResponseMode.ENFORCE, firewall_backend="windows")
    engine.set_policy_provider(service.engine_policy)

    action = engine.block_ip("203.0.113.1", reason="must_not_execute")

    assert action["mode"] == "monitor"
    assert action["status"] == "rejected"
    assert action["error"] == "response kill switch is enabled"


def test_auth_session_can_be_revoked(tmp_path):
    database = make_database(tmp_path)
    users = UserRepository(database)
    sessions = SessionRepository(database)
    auth = AuthService(
        users,
        sessions,
        secret_key="test-secret-only",
        algorithm="HS256",
        expiration_minutes=15,
    )
    auth.create_user("operator", "strong-test-password", Role.ADMIN)

    token, user, _ = auth.login("operator", "strong-test-password")
    assert user.role == Role.ADMIN
    assert auth.authenticate_token(token) is not None

    auth.logout(token)
    assert auth.authenticate_token(token) is None


def test_audit_events_are_immutable_and_hash_chain_verifies(tmp_path):
    database = make_database(tmp_path)
    audit = AuditRepository(database)
    first = audit.append(action="login", target_type="auth_session", outcome="executed")
    audit.append(
        action="response_mode_change",
        target_type="runtime_response_control",
        outcome="rejected",
        details={"requested_mode": "enforce"},
    )

    assert audit.verify_chain() is True
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        with database.connect() as connection:
            connection.execute(
                "UPDATE audit_events SET outcome = 'altered' WHERE event_id = ?",
                (first["event_id"],),
            )


def test_non_admin_websocket_payload_redacts_host_inventory():
    payload = {
        "alerts": [{"alert_id": "a1", "details": {"adapter_name": "Wi-Fi"}}],
        "local_security": {"adapters": [{"mac_address": "00:11:22:33:44:55"}]},
        "response_actions": [{"command": ["netsh"]}],
        "detection": {
            "is_anomaly": False,
            "raw_anomaly_score": 0.91,
            "suppression_reason": "filtered",
            "gate_evidence": ["internal"],
        },
    }

    analyst = redact_ws_payload(payload, "analyst")
    viewer = redact_ws_payload(payload, "viewer")

    assert analyst["local_security"] is None
    assert analyst["alerts"][0]["details"]["adapter_name"] == "[REDACTED]"
    assert "response_actions" not in analyst
    assert viewer["alerts"] == []
    assert "suppression_reason" not in viewer["detection"]
    assert "raw_anomaly_score" not in viewer["detection"]
