"""Role-aware removal of host inventory and response command details."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

SENSITIVE_KEYS = {
    "adapter",
    "adapter_name",
    "adapter_description",
    "adapters",
    "bssid",
    "command",
    "commands",
    "default_gateway",
    "dns",
    "dns_servers",
    "gateway",
    "ip_configuration",
    "mac",
    "mac_address",
    "pnp_device_id",
    "pnp_id",
}


def _redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, child in value.items():
            if key.lower() in SENSITIVE_KEYS:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = _redact_sensitive(child)
        return redacted
    if isinstance(value, list):
        return [_redact_sensitive(item) for item in value]
    return value


def redact_local_security(snapshot: Any, role: str) -> Any:
    if role == "admin":
        return snapshot
    return None


def redact_alerts(alerts: list[dict[str, Any]], role: str) -> list[dict[str, Any]]:
    if role == "viewer":
        return []
    if role == "admin":
        return alerts
    return [_redact_sensitive(deepcopy(alert)) for alert in alerts]


def redact_response_actions(actions: list[dict[str, Any]], role: str) -> list[dict[str, Any]]:
    if role != "admin":
        return []
    return actions


def redact_ws_payload(payload: dict[str, Any], role: str) -> dict[str, Any]:
    result = deepcopy(payload)
    if "alerts" in result:
        result["alerts"] = redact_alerts(result["alerts"], role)
    if "new_alerts" in result:
        result["new_alerts"] = redact_alerts(result["new_alerts"], role)
    if "local_security" in result:
        result["local_security"] = redact_local_security(result["local_security"], role)
    if role != "admin":
        result.pop("response_actions", None)
    if role == "viewer" and isinstance(result.get("detection"), dict):
        for key in ("raw_anomaly_score", "suppression_reason", "gate_evidence"):
            result["detection"].pop(key, None)
    return _redact_sensitive(result) if role != "admin" else result
