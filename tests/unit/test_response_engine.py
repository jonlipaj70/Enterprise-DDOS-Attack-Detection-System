"""Tests for controlled response automation."""

import subprocess

from src.config.settings import ResponseMode
from src.response.response_engine import ResponseEngine


def test_monitor_mode_records_would_block_without_execution():
    engine = ResponseEngine(
        mode=ResponseMode.MONITOR,
        allowlist=["127.0.0.1"],
        block_ttl_seconds=60,
    )

    action = engine.block_ip("203.0.113.10", reason="manual_test")

    assert action["status"] == "monitor_only"
    assert action["mode"] == "monitor"
    assert action["target_ip"] == "203.0.113.10"
    assert engine.stats["active_blocks"] == 0
    assert engine.stats["actions_total"] == 1


def test_allowlisted_ip_is_rejected():
    engine = ResponseEngine(
        mode=ResponseMode.ENFORCE,
        allowlist=["10.0.0.0/8"],
    )

    action = engine.block_ip("10.0.1.5", reason="should_not_block")

    assert action["status"] == "rejected"
    assert action["error"] == "target IP is allowlisted"


def test_enforce_mode_uses_command_runner_and_can_unblock():
    commands = []

    def fake_runner(command):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    engine = ResponseEngine(
        mode=ResponseMode.ENFORCE,
        allowlist=[],
        firewall_backend="windows",
        command_runner=fake_runner,
    )

    block = engine.block_ip("203.0.113.20", reason="unit_test")
    unblock = engine.unblock_ip("203.0.113.20", reason="rollback")

    assert block["status"] == "executed"
    assert unblock["status"] == "rolled_back"
    assert commands[0][:4] == ["netsh", "advfirewall", "firewall", "add"]
    assert commands[1][:4] == ["netsh", "advfirewall", "firewall", "delete"]
    assert engine.stats["active_blocks"] == 0


def test_auto_response_requires_critical_alert_and_evidence():
    engine = ResponseEngine(
        mode=ResponseMode.MONITOR,
        auto_block_enabled=True,
        allowlist=[],
        auto_block_max_ips_per_alert=2,
    )
    alert = {
        "alert_id": "a1",
        "severity": "critical",
        "attack_type": "syn_flood",
        "source_ips": ["203.0.113.1", "203.0.113.2", "203.0.113.3"],
        "anomaly_score": 0.91,
        "confidence": 0.8,
        "details": {"gate_evidence": ["packet_rate=50000"]},
    }

    decision = engine.respond_to_alert(alert)

    assert decision["status"] == "actions_recorded"
    assert decision["reason"] == "critical_alert_policy"
    assert len(decision["actions"]) == 2
    assert all(action["status"] == "monitor_only" for action in decision["actions"])


def test_auto_response_skips_medium_alerts():
    engine = ResponseEngine(
        mode=ResponseMode.MONITOR,
        auto_block_enabled=True,
        allowlist=[],
    )
    alert = {
        "alert_id": "a2",
        "severity": "medium",
        "attack_type": "scan",
        "source_ips": ["203.0.113.10"],
        "details": {"gate_evidence": ["scan"]},
    }

    decision = engine.respond_to_alert(alert)

    assert decision["status"] == "monitoring"
    assert decision["reason"] == "severity_below_auto_block_threshold"
    assert decision["actions"] == []
