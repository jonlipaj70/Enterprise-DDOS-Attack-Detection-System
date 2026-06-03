"""Audited runtime control for response enforcement and the emergency switch."""

from __future__ import annotations

from dataclasses import dataclass

from src.config.settings import ResponseMode
from src.storage.audit_repository import AuditRepository
from src.storage.repositories import RuntimeControlRepository, RuntimeResponseRecord


@dataclass(frozen=True)
class ResponseControlState:
    mode: ResponseMode
    auto_block_enabled: bool
    kill_switch: bool
    updated_by: str | None
    updated_at: float
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode.value,
            "auto_block_enabled": self.auto_block_enabled,
            "kill_switch": self.kill_switch,
            "updated_by": self.updated_by,
            "updated_at": self.updated_at,
            "reason": self.reason,
        }


class ResponseControlService:
    def __init__(
        self,
        repository: RuntimeControlRepository,
        audit: AuditRepository,
        *,
        mitigation_activation_allowed: bool,
    ) -> None:
        self.repository = repository
        self.audit = audit
        self.mitigation_activation_allowed = mitigation_activation_allowed

    @staticmethod
    def _state(record: RuntimeResponseRecord) -> ResponseControlState:
        return ResponseControlState(
            mode=ResponseMode(record.mode),
            auto_block_enabled=record.auto_block_enabled,
            kill_switch=record.kill_switch,
            updated_by=record.updated_by,
            updated_at=record.updated_at,
            reason=record.reason,
        )

    def initialize(self) -> ResponseControlState:
        state = self._state(self.repository.ensure_safe_default())
        if not self.mitigation_activation_allowed and (
            state.mode == ResponseMode.ENFORCE or state.auto_block_enabled or not state.kill_switch
        ):
            record = self.repository.update(
                mode=ResponseMode.MONITOR.value,
                auto_block_enabled=False,
                kill_switch=True,
                updated_by=None,
                reason="Release 1 safety gate reset persistent response state",
            )
            self.audit.append(
                action="response_control_safety_reset",
                target_type="runtime_response_control",
                outcome="executed",
                reason="MITIGATION_ACTIVATION_ALLOWED=false",
            )
            return self._state(record)
        return state

    def get_state(self) -> ResponseControlState:
        return self._state(self.repository.get())

    def engine_policy(self) -> dict[str, object]:
        return self.get_state().to_dict()

    def update_kill_switch(
        self,
        *,
        enabled: bool,
        reason: str,
        actor_user_id: str,
        actor_role: str,
        actor_username: str,
        request_id: str,
    ) -> ResponseControlState:
        cleaned_reason = reason.strip()
        if not cleaned_reason:
            raise ValueError("reason is required")
        current = self.get_state()
        record = self.repository.update(
            mode=current.mode.value,
            auto_block_enabled=current.auto_block_enabled,
            kill_switch=enabled,
            updated_by=actor_username,
            reason=cleaned_reason,
        )
        self.audit.append(
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            action="response_kill_switch_change",
            target_type="runtime_response_control",
            target_id="singleton",
            reason=cleaned_reason,
            outcome="executed",
            request_id=request_id,
            details={"enabled": enabled, "previous_enabled": current.kill_switch},
        )
        return self._state(record)

    def update_mode(
        self,
        *,
        mode: ResponseMode,
        auto_block_enabled: bool,
        reason: str,
        confirmation: str,
        actor_user_id: str,
        actor_role: str,
        actor_username: str,
        request_id: str,
    ) -> ResponseControlState:
        cleaned_reason = reason.strip()
        current = self.get_state()
        requested_enforcement = mode == ResponseMode.ENFORCE or auto_block_enabled
        rejection: str | None = None
        if not cleaned_reason:
            rejection = "reason is required"
        elif requested_enforcement and confirmation != "ENABLE_ENFORCEMENT":
            rejection = "confirmation must equal ENABLE_ENFORCEMENT"
        elif requested_enforcement and not self.mitigation_activation_allowed:
            rejection = "enforcement is disabled for Release 1"
        elif requested_enforcement and current.kill_switch:
            rejection = "disable the kill switch in a separate audited action first"

        if rejection:
            self.audit.append(
                actor_user_id=actor_user_id,
                actor_role=actor_role,
                action="response_mode_change",
                target_type="runtime_response_control",
                target_id="singleton",
                reason=cleaned_reason or None,
                outcome="rejected",
                request_id=request_id,
                details={
                    "requested_mode": mode.value,
                    "requested_auto_block_enabled": auto_block_enabled,
                    "rejection": rejection,
                },
            )
            raise ValueError(rejection)

        record = self.repository.update(
            mode=mode.value,
            auto_block_enabled=auto_block_enabled,
            kill_switch=current.kill_switch,
            updated_by=actor_username,
            reason=cleaned_reason,
        )
        self.audit.append(
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            action="response_mode_change",
            target_type="runtime_response_control",
            target_id="singleton",
            reason=cleaned_reason,
            outcome="executed",
            request_id=request_id,
            details={
                "mode": mode.value,
                "auto_block_enabled": auto_block_enabled,
                "previous_mode": current.mode.value,
                "previous_auto_block_enabled": current.auto_block_enabled,
            },
        )
        return self._state(record)
