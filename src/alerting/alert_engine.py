"""
Core Alert Processing Engine
===============================
Handles alert creation, deduplication, enrichment, and routing.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from src.config.logging_config import get_logger

logger = get_logger(__name__)


class AlertSeverity(str, Enum):
    LOW = "low"
    INFO = "info"
    MEDIUM = "medium"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class AlertStatus(str, Enum):
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


@dataclass
class Alert:
    """Represents a detection alert."""
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: float = field(default_factory=time.time)
    severity: AlertSeverity = AlertSeverity.WARNING
    status: AlertStatus = AlertStatus.ACTIVE
    attack_type: str = "unknown"
    title: str = ""
    description: str = ""
    source_ips: list[str] = field(default_factory=list)
    target_ips: list[str] = field(default_factory=list)
    source_ports: list[int] = field(default_factory=list)
    target_ports: list[int] = field(default_factory=list)
    protocol: str | int | None = None
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    detection_sources: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    recommended_response: str = ""
    mitigation: dict[str, Any] = field(default_factory=dict)
    anomaly_score: float = 0.0
    confidence: float = 0.0
    packet_rate: float = 0.0
    byte_rate: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[float] = None
    resolved_at: Optional[float] = None
    correlated_alerts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "severity": self.severity.value,
            "status": self.status.value,
            "attack_type": self.attack_type,
            "title": self.title,
            "description": self.description,
            "source_ips": self.source_ips[:10],  # Limit for display
            "target_ips": self.target_ips,
            "source_ports": self.source_ports[:20],
            "target_ports": self.target_ports[:20],
            "protocol": self.protocol,
            "first_seen": self.first_seen or self.timestamp,
            "last_seen": self.last_seen or self.timestamp,
            "detection_sources": self.detection_sources,
            "evidence": self.evidence,
            "recommended_response": self.recommended_response,
            "mitigation": self.mitigation,
            "anomaly_score": round(self.anomaly_score, 4),
            "confidence": round(self.confidence, 4),
            "packet_rate": round(self.packet_rate, 0),
            "byte_rate": round(self.byte_rate, 0),
            "details": self.details,
            "acknowledged_by": self.acknowledged_by,
            "acknowledged_at": self.acknowledged_at,
            "resolved_at": self.resolved_at,
            "correlated_alerts": self.correlated_alerts,
        }


class AlertEngine:
    """
    Core alert processing engine.

    Handles:
    - Alert creation from detection results
    - Deduplication (prevents duplicate alerts for the same attack)
    - Enrichment with contextual information
    - Routing to configured integrations
    """

    def __init__(self, dedup_window_seconds: int = 300):
        self._alerts: dict[str, Alert] = {}
        self._alert_history: deque[Alert] = deque(maxlen=10000)
        self._dedup_window = dedup_window_seconds
        self._dedup_cache: dict[str, float] = {}
        self._handlers: list[Callable[[Alert], None]] = []
        self._stats = {
            "alerts_created": 0,
            "alerts_deduplicated": 0,
            "alerts_suppressed": 0,
        }

    def create_alert(self, detection_result: dict[str, Any]) -> Optional[Alert]:
        """
        Create an alert from a detection result.

        Performs deduplication and enrichment before dispatch.
        """
        if not detection_result.get("is_anomaly", False):
            return None

        # Generate dedup key
        dedup_key = self._dedup_key(detection_result)

        # Check deduplication
        if dedup_key in self._dedup_cache:
            last_seen = self._dedup_cache[dedup_key]
            if time.time() - last_seen < self._dedup_window:
                self._stats["alerts_deduplicated"] += 1
                return None

        # Create alert
        severity = AlertSeverity(self._normalize_severity(detection_result.get("severity", "warning")))
        attack_type = detection_result.get("attack_type", "unknown")
        details = detection_result.get("details", {}) if isinstance(detection_result.get("details"), dict) else {}
        expert_analysis = detection_result.get("expert_analysis", {})
        traffic_context = details.get("traffic_context", {})

        alert = Alert(
            severity=severity,
            attack_type=attack_type,
            title=f"DDoS Attack Detected: {self._format_attack_type(attack_type)}",
            description=self._generate_description(detection_result),
            source_ips=detection_result.get("source_ips", traffic_context.get("source_ips", [])),
            target_ips=detection_result.get("target_ips", traffic_context.get("target_ips", [])),
            source_ports=detection_result.get("source_ports", traffic_context.get("source_ports", [])),
            target_ports=detection_result.get("target_ports", traffic_context.get("target_ports", [])),
            protocol=detection_result.get("protocol", traffic_context.get("protocol")),
            first_seen=detection_result.get("first_seen", detection_result.get("timestamp")),
            last_seen=detection_result.get("last_seen", detection_result.get("timestamp")),
            detection_sources=detection_result.get("detection_sources", ["ml_ensemble"]),
            evidence={
                "top_features": detection_result.get("top_features", []),
                "gate_evidence": detection_result.get("gate_evidence", []),
                "traffic_context": traffic_context,
                "expert_analysis": expert_analysis,
            },
            recommended_response=expert_analysis.get("mitigation", ""),
            mitigation=detection_result.get("mitigation", {}),
            anomaly_score=detection_result.get("anomaly_score", 0),
            confidence=detection_result.get("confidence", 0),
            packet_rate=detection_result.get("packet_rate", details.get("packet_rate", 0)),
            byte_rate=detection_result.get("byte_rate", details.get("byte_rate", 0)),
            details=detection_result,
        )

        # Store alert
        self._alerts[alert.alert_id] = alert
        self._alert_history.append(alert)
        self._dedup_cache[dedup_key] = time.time()
        self._stats["alerts_created"] += 1

        # Dispatch to handlers
        for handler in self._handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error("alert_handler_error", error=str(e))

        logger.info(
            "alert_created",
            alert_id=alert.alert_id,
            severity=severity.value,
            attack_type=attack_type,
            score=round(alert.anomaly_score, 4),
        )

        return alert

    def create_security_alert(self, event: dict[str, Any]) -> Optional[Alert]:
        """Create a non-DDoS security alert from a local or integration event."""
        if not event.get("is_anomaly", True):
            return None

        dedup_key = self._security_dedup_key(event)
        if dedup_key in self._dedup_cache:
            last_seen = self._dedup_cache[dedup_key]
            if time.time() - last_seen < self._dedup_window:
                self._stats["alerts_deduplicated"] += 1
                return None

        severity = AlertSeverity(self._normalize_severity(event.get("severity", "warning")))
        attack_type = event.get("attack_type", "local_security_threat")
        details = event.get("details", {}) if isinstance(event.get("details"), dict) else {}
        evidence = event.get("evidence", {})

        alert = Alert(
            severity=severity,
            attack_type=attack_type,
            title=event.get("title", self._format_attack_type(attack_type)),
            description=event.get("description", ""),
            source_ips=event.get("source_ips", []),
            target_ips=event.get("target_ips", []),
            source_ports=event.get("source_ports", []),
            target_ports=event.get("target_ports", []),
            protocol=event.get("protocol"),
            first_seen=event.get("first_seen", event.get("timestamp")),
            last_seen=event.get("last_seen", event.get("timestamp")),
            detection_sources=event.get("detection_sources", ["security_event"]),
            evidence=evidence if isinstance(evidence, dict) else {"value": evidence},
            recommended_response=event.get("recommended_response", ""),
            mitigation=event.get("mitigation", {}),
            anomaly_score=event.get("anomaly_score", 0),
            confidence=event.get("confidence", 0),
            packet_rate=event.get("packet_rate", 0),
            byte_rate=event.get("byte_rate", 0),
            details=details or event,
        )

        self._alerts[alert.alert_id] = alert
        self._alert_history.append(alert)
        self._dedup_cache[dedup_key] = time.time()
        self._stats["alerts_created"] += 1

        for handler in self._handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error("alert_handler_error", error=str(e))

        logger.info(
            "security_alert_created",
            alert_id=alert.alert_id,
            severity=severity.value,
            attack_type=attack_type,
            score=round(alert.anomaly_score, 4),
        )

        return alert

    def acknowledge_alert(self, alert_id: str, user: str) -> bool:
        """Acknowledge an alert."""
        alert = self._alerts.get(alert_id)
        if alert and alert.status == AlertStatus.ACTIVE:
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_by = user
            alert.acknowledged_at = time.time()
            return True
        return False

    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert."""
        alert = self._alerts.get(alert_id)
        if alert and alert.status in (AlertStatus.ACTIVE, AlertStatus.ACKNOWLEDGED):
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = time.time()
            return True
        return False

    def get_active_alerts(
        self,
        *,
        severity: str | None = None,
        source: str | None = None,
        status: str | None = None,
    ) -> list[dict]:
        """Get all active alerts."""
        return self.get_alerts(severity=severity, source=source, status=status, active_only=True)

    def get_alerts(
        self,
        *,
        severity: str | None = None,
        source: str | None = None,
        status: str | None = None,
        active_only: bool = False,
        limit: int = 100,
    ) -> list[dict]:
        """Get alerts with optional severity/source/status filtering."""
        alerts = list(self._alerts.values())
        if active_only:
            alerts = [
                alert
                for alert in alerts
                if alert.status in (AlertStatus.ACTIVE, AlertStatus.ACKNOWLEDGED)
            ]
        if severity:
            severity = self._normalize_severity(severity)
            alerts = [alert for alert in alerts if alert.severity.value == severity]
        if status:
            alerts = [alert for alert in alerts if alert.status.value == status]
        if source:
            source = source.lower()
            alerts = [
                alert
                for alert in alerts
                if source in {entry.lower() for entry in alert.detection_sources}
            ]
        return [alert.to_dict() for alert in alerts[-limit:]]

    def get_alert_history(self, limit: int = 100) -> list[dict]:
        """Get recent alert history."""
        return [a.to_dict() for a in list(self._alert_history)[-limit:]]

    def on_alert(self, handler: Callable[[Alert], None]) -> None:
        """Register an alert handler."""
        self._handlers.append(handler)

    def _dedup_key(self, result: dict) -> str:
        """Generate deduplication key."""
        raw = f"{result.get('attack_type', '')}:{result.get('severity', '')}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _security_dedup_key(self, result: dict) -> str:
        raw = (
            f"security:{result.get('dedup_key', '')}:"
            f"{result.get('attack_type', '')}:{result.get('severity', '')}:"
            f"{result.get('title', '')}"
        )
        return hashlib.md5(raw.encode()).hexdigest()

    def _generate_description(self, result: dict) -> str:
        """Generate a human-readable alert description."""
        attack = result.get("attack_type", "unknown").replace("_", " ")
        score = result.get("anomaly_score", 0)
        pps = result.get("details", {}).get("packet_rate", 0)
        return (
            f"A {attack} attack has been detected with an anomaly score of {score:.2f}. "
            f"Current packet rate: {pps:.0f} pps."
        )

    @staticmethod
    def _format_attack_type(attack_type: str) -> str:
        acronyms = {"syn", "ack", "udp", "tcp", "dns", "http", "icmp", "ntp", "ssdp"}
        parts = attack_type.replace("_", " ").split()
        return " ".join(part.upper() if part.lower() in acronyms else part.title() for part in parts)

    @staticmethod
    def _normalize_severity(severity: Any) -> str:
        value = str(severity or "warning").lower()
        aliases = {
            "low": "low",
            "medium": "medium",
            "high": "high",
            "warn": "warning",
            "warning": "warning",
            "emergency": "emergency",
            "critical": "critical",
            "info": "info",
        }
        return aliases.get(value, "warning")

    @property
    def stats(self) -> dict:
        active = sum(1 for a in self._alerts.values() if a.status == AlertStatus.ACTIVE)
        return {
            **self._stats,
            "active_alerts": active,
            "total_alerts": len(self._alerts),
        }
