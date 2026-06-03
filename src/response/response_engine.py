"""Controlled network response engine.

The engine defaults to monitor-only mode. In that mode it records the action
that would have been taken, including TTL and evidence, without changing the
host firewall. Enforce mode currently supports Windows Defender Firewall via
``netsh`` and keeps every action auditable and reversible.
"""

from __future__ import annotations

import platform
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from typing import Any, Callable, Iterable

from src.config.settings import ResponseMode, ResponseSettings
from src.config.logging_config import get_logger

logger = get_logger(__name__)


CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]
PolicyProvider = Callable[[], dict[str, Any]]


SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "warning": 2,
    "medium": 2,
    "high": 3,
    "critical": 4,
    "emergency": 5,
}


@dataclass
class ResponseAction:
    """Audit record for one response action."""

    action_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    action_type: str = "block_ip"
    target_ip: str = ""
    status: str = "pending"
    mode: str = ResponseMode.MONITOR.value
    reason: str = ""
    source: str = "manual"
    requested_by: str = "api_user"
    alert_id: str | None = None
    created_at: float = field(default_factory=time.time)
    expires_at: float | None = None
    command: list[str] = field(default_factory=list)
    error: str | None = None
    evidence: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "target_ip": self.target_ip,
            "status": self.status,
            "mode": self.mode,
            "reason": self.reason,
            "source": self.source,
            "requested_by": self.requested_by,
            "alert_id": self.alert_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "command": self.command,
            "error": self.error,
            "evidence": self.evidence,
            "metadata": self.metadata,
        }


class ResponseEngine:
    """TTL-based IP blocking with allowlists, rate limits, and audit trail."""

    def __init__(
        self,
        mode: ResponseMode = ResponseMode.MONITOR,
        auto_block_enabled: bool = False,
        kill_switch: bool = False,
        allowlist: Iterable[str] | None = None,
        block_ttl_seconds: int = 1800,
        max_blocks_per_minute: int = 10,
        max_active_blocks: int = 100,
        auto_block_max_ips_per_alert: int = 5,
        firewall_backend: str = "auto",
        command_runner: CommandRunner | None = None,
        policy_provider: PolicyProvider | None = None,
    ) -> None:
        self.mode = mode
        self.auto_block_enabled = auto_block_enabled
        self.kill_switch = kill_switch
        self.block_ttl_seconds = block_ttl_seconds
        self.max_blocks_per_minute = max_blocks_per_minute
        self.max_active_blocks = max_active_blocks
        self.auto_block_max_ips_per_alert = auto_block_max_ips_per_alert
        self.firewall_backend = firewall_backend.lower()
        self._allowlist = [ip_network(entry, strict=False) for entry in allowlist or []]
        self._command_runner = command_runner or self._run_command
        self._policy_provider = policy_provider
        self._actions: list[ResponseAction] = []
        self._active_blocks: dict[str, ResponseAction] = {}
        self._recent_block_times: list[float] = []

    def set_policy_provider(self, policy_provider: PolicyProvider) -> None:
        """Use persistent runtime state as the authoritative response policy."""
        self._policy_provider = policy_provider

    def _refresh_policy(self) -> None:
        if self._policy_provider is None:
            return
        policy = self._policy_provider()
        self.mode = ResponseMode(policy["mode"])
        self.auto_block_enabled = bool(policy["auto_block_enabled"])
        self.kill_switch = bool(policy["kill_switch"])

    @classmethod
    def from_settings(cls, settings: ResponseSettings) -> "ResponseEngine":
        return cls(
            mode=settings.response_mode,
            auto_block_enabled=settings.auto_block_enabled,
            kill_switch=settings.response_kill_switch,
            allowlist=settings.allowlist_entries,
            block_ttl_seconds=settings.block_ttl_seconds,
            max_blocks_per_minute=settings.max_blocks_per_minute,
            max_active_blocks=settings.max_active_blocks,
            auto_block_max_ips_per_alert=settings.auto_block_max_ips_per_alert,
            firewall_backend=settings.firewall_backend,
        )

    def block_ip(
        self,
        ip: str,
        *,
        reason: str,
        alert_id: str | None = None,
        requested_by: str = "api_user",
        source: str = "manual",
        ttl_seconds: int | None = None,
        evidence: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Block or record a would-block action for one IP."""

        self._refresh_policy()
        now = time.time()
        normalized_ip, validation_error = self._normalize_ip(ip)
        expires_at = now + (ttl_seconds or self.block_ttl_seconds)
        action = ResponseAction(
            action_type="block_ip",
            target_ip=normalized_ip or ip,
            mode=self.mode.value,
            reason=reason,
            source=source,
            requested_by=requested_by,
            alert_id=alert_id,
            created_at=now,
            expires_at=expires_at,
            evidence=evidence or [],
            metadata=metadata or {},
        )

        rejection = validation_error or self._block_rejection_reason(normalized_ip)
        if rejection:
            action.status = "rejected"
            action.error = rejection
            self._record(action)
            return action.to_dict()

        assert normalized_ip is not None
        if self.mode == ResponseMode.MONITOR:
            action.status = "monitor_only"
            action.command = self._build_block_command(normalized_ip, action.action_id)
            self._record(action)
            return action.to_dict()

        command = self._build_block_command(normalized_ip, action.action_id)
        if not command:
            action.status = "failed"
            action.error = f"firewall backend is not available: {self.firewall_backend}"
            self._record(action)
            return action.to_dict()

        action.command = command
        result = self._command_runner(command)
        if result.returncode == 0:
            action.status = "executed"
            self._active_blocks[normalized_ip] = action
            self._recent_block_times.append(now)
        else:
            action.status = "failed"
            action.error = (result.stderr or result.stdout or "firewall command failed").strip()

        self._record(action)
        return action.to_dict()

    def unblock_ip(
        self,
        ip: str,
        *,
        reason: str = "manual_unblock",
        requested_by: str = "api_user",
    ) -> dict[str, Any]:
        """Rollback an active block for one IP."""

        self._refresh_policy()
        normalized_ip, validation_error = self._normalize_ip(ip)
        action = ResponseAction(
            action_type="unblock_ip",
            target_ip=normalized_ip or ip,
            mode=self.mode.value,
            reason=reason,
            requested_by=requested_by,
        )
        if validation_error:
            action.status = "rejected"
            action.error = validation_error
            self._record(action)
            return action.to_dict()

        assert normalized_ip is not None
        active = self._active_blocks.get(normalized_ip)
        if active is None:
            action.status = "not_found"
            action.error = "no active block for target_ip"
            self._record(action)
            return action.to_dict()

        if self.mode == ResponseMode.MONITOR:
            action.status = "monitor_only"
            self._active_blocks.pop(normalized_ip, None)
            self._record(action)
            return action.to_dict()

        command = self._build_unblock_command(normalized_ip, active.action_id)
        if not command:
            action.status = "failed"
            action.error = f"firewall backend is not available: {self.firewall_backend}"
            self._record(action)
            return action.to_dict()

        action.command = command
        result = self._command_runner(command)
        if result.returncode == 0:
            action.status = "rolled_back"
            active.status = "rolled_back"
            self._active_blocks.pop(normalized_ip, None)
        else:
            action.status = "failed"
            action.error = (result.stderr or result.stdout or "firewall command failed").strip()

        self._record(action)
        return action.to_dict()

    def respond_to_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Apply the configured auto-response policy to an alert."""

        self._refresh_policy()
        self.expire_blocks()
        severity = str(alert.get("severity", "info"))
        source_ips = [str(ip) for ip in alert.get("source_ips", []) if ip]
        details = alert.get("details", {}) if isinstance(alert.get("details"), dict) else {}
        gate_evidence = alert.get("gate_evidence") or details.get("gate_evidence") or []
        model_score = float(alert.get("anomaly_score", 0.0) or 0.0)
        confidence = float(alert.get("confidence", 0.0) or 0.0)

        decision = {
            "status": "monitoring",
            "auto_block_enabled": self.auto_block_enabled,
            "mode": self.mode.value,
            "reason": "auto_block_disabled",
            "actions": [],
        }

        if not self.auto_block_enabled:
            return decision
        if self.kill_switch:
            decision["reason"] = "kill_switch_enabled"
            return decision
        if SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["critical"]:
            decision["reason"] = "severity_below_auto_block_threshold"
            return decision
        if not source_ips:
            decision["reason"] = "no_source_ips_available"
            return decision
        if not gate_evidence and model_score < 0.88 and confidence < 0.75:
            decision["reason"] = "insufficient_multi_evidence"
            return decision

        blocked = []
        limit = max(0, self.auto_block_max_ips_per_alert)
        for ip in source_ips[:limit]:
            action = self.block_ip(
                ip,
                reason=f"auto_response:{alert.get('attack_type', 'unknown')}",
                alert_id=alert.get("alert_id"),
                requested_by="response_engine",
                source="auto",
                evidence=[str(item) for item in gate_evidence],
                metadata={
                    "severity": severity,
                    "anomaly_score": model_score,
                    "confidence": confidence,
                },
            )
            blocked.append(action)

        decision["status"] = "actions_recorded" if self.mode == ResponseMode.MONITOR else "actions_executed"
        decision["reason"] = "critical_alert_policy"
        decision["actions"] = blocked
        return decision

    def expire_blocks(self) -> list[dict[str, Any]]:
        """Expire TTL blocks and rollback firewall state where possible."""

        now = time.time()
        expired: list[dict[str, Any]] = []
        for ip, action in list(self._active_blocks.items()):
            if action.expires_at is None or action.expires_at > now:
                continue
            rollback = self.unblock_ip(ip, reason="ttl_expired", requested_by="response_engine")
            rollback["expired_action_id"] = action.action_id
            expired.append(rollback)
        return expired

    def get_actions(
        self,
        *,
        status: str | None = None,
        action_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return recent audit actions with optional filters."""

        actions = self._actions
        if status:
            actions = [action for action in actions if action.status == status]
        if action_type:
            actions = [action for action in actions if action.action_type == action_type]
        return [action.to_dict() for action in actions[-limit:]]

    def get_active_blocks(self) -> list[dict[str, Any]]:
        self.expire_blocks()
        return [action.to_dict() for action in self._active_blocks.values()]

    @property
    def stats(self) -> dict[str, Any]:
        self._refresh_policy()
        self.expire_blocks()
        return {
            "mode": self.mode.value,
            "auto_block_enabled": self.auto_block_enabled,
            "kill_switch": self.kill_switch,
            "actions_total": len(self._actions),
            "active_blocks": len(self._active_blocks),
            "max_active_blocks": self.max_active_blocks,
        }

    def _block_rejection_reason(self, normalized_ip: str | None) -> str | None:
        if normalized_ip is None:
            return "invalid IP address"
        if self.kill_switch:
            return "response kill switch is enabled"
        if self._is_allowlisted(normalized_ip):
            return "target IP is allowlisted"
        if normalized_ip in self._active_blocks:
            return "target IP is already blocked"
        if len(self._active_blocks) >= self.max_active_blocks:
            return "maximum active block limit reached"
        self._recent_block_times = [
            timestamp for timestamp in self._recent_block_times if time.time() - timestamp < 60
        ]
        if len(self._recent_block_times) >= self.max_blocks_per_minute:
            return "block rate limit exceeded"
        return None

    def _normalize_ip(self, value: str) -> tuple[str | None, str | None]:
        try:
            return str(ip_address(value.strip())), None
        except ValueError:
            return None, "invalid IP address"

    def _is_allowlisted(self, normalized_ip: str) -> bool:
        target = ip_address(normalized_ip)
        return any(target in network for network in self._allowlist)

    def _record(self, action: ResponseAction) -> None:
        self._actions.append(action)
        logger.info(
            "response_action_recorded",
            action_id=action.action_id,
            action_type=action.action_type,
            target_ip=action.target_ip,
            status=action.status,
            mode=action.mode,
        )

    def _build_block_command(self, normalized_ip: str, action_id: str) -> list[str]:
        backend = self._select_backend()
        if backend == "windows":
            return [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name=ddos-response-{action_id}",
                "dir=in",
                "action=block",
                f"remoteip={normalized_ip}",
            ]
        return []

    def _build_unblock_command(self, normalized_ip: str, action_id: str) -> list[str]:
        backend = self._select_backend()
        if backend == "windows":
            return [
                "netsh",
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                f"name=ddos-response-{action_id}",
                f"remoteip={normalized_ip}",
            ]
        return []

    def _select_backend(self) -> str:
        if self.firewall_backend == "disabled":
            return "disabled"
        if self.firewall_backend in {"windows"}:
            return self.firewall_backend
        if self.firewall_backend == "auto" and platform.system().lower() == "windows":
            return "windows"
        return "disabled"

    @staticmethod
    def _run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
