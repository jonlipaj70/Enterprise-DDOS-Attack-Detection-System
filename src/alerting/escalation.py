"""
Escalation Workflow Engine
============================
Configurable escalation chains with timeout-based escalation.
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Any, Optional

@dataclass
class EscalationLevel:
    name: str
    timeout_seconds: int
    notifiers: list[str]  # Integration names

@dataclass
class EscalationChain:
    name: str
    levels: list[EscalationLevel]

DEFAULT_CHAIN = EscalationChain(
    name="default",
    levels=[
        EscalationLevel("L1 - SOC Analyst", 300, ["slack"]),
        EscalationLevel("L2 - Security Engineer", 600, ["slack", "pagerduty"]),
        EscalationLevel("L3 - CISO", 900, ["slack", "pagerduty", "email"]),
    ],
)

class EscalationEngine:
    """Manages alert escalation workflows."""

    def __init__(self):
        self._chains: dict[str, EscalationChain] = {"default": DEFAULT_CHAIN}
        self._active: dict[str, dict] = {}  # alert_id -> escalation state

    def start_escalation(self, alert_id: str, severity: str, chain_name: str = "default") -> dict:
        chain = self._chains.get(chain_name, DEFAULT_CHAIN)
        state = {
            "alert_id": alert_id,
            "chain": chain_name,
            "current_level": 0,
            "started_at": time.time(),
            "last_escalated": time.time(),
        }
        self._active[alert_id] = state
        return {"level": chain.levels[0].name, "notifiers": chain.levels[0].notifiers}

    def check_escalations(self) -> list[dict]:
        """Check for alerts that need escalation."""
        escalations = []
        now = time.time()

        for alert_id, state in list(self._active.items()):
            chain = self._chains.get(state["chain"], DEFAULT_CHAIN)
            level_idx = state["current_level"]

            if level_idx >= len(chain.levels) - 1:
                continue

            current_level = chain.levels[level_idx]
            elapsed = now - state["last_escalated"]

            if elapsed >= current_level.timeout_seconds:
                next_level = chain.levels[level_idx + 1]
                state["current_level"] = level_idx + 1
                state["last_escalated"] = now
                escalations.append({
                    "alert_id": alert_id,
                    "from_level": current_level.name,
                    "to_level": next_level.name,
                    "notifiers": next_level.notifiers,
                })

        return escalations

    def resolve(self, alert_id: str) -> None:
        self._active.pop(alert_id, None)

    @property
    def stats(self) -> dict:
        return {"active_escalations": len(self._active)}
