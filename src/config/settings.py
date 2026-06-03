"""
Central Configuration Management
=================================
Pydantic-based settings with environment variable support and multi-environment configuration.
"""

from __future__ import annotations

import os
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Environment(str, Enum):
    """Application environment."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


class CaptureSource(str, Enum):
    """Packet capture source."""

    SIMULATION = "simulation"
    TSHARK = "tshark"


class ResponseMode(str, Enum):
    """Automated response execution mode."""

    MONITOR = "monitor"
    ENFORCE = "enforce"


class AppSettings(BaseSettings):
    """Core application settings."""

    app_name: str = Field(default="ddos-detection-system", description="Application name")
    app_env: Environment = Field(default=Environment.DEVELOPMENT, description="Environment")
    debug: bool = Field(default=False, description="Debug mode")
    log_level: str = Field(default="INFO", description="Log level")
    secret_key: str = Field(default="change-me", description="Secret key for signing")

    @field_validator("debug", mode="before")
    @classmethod
    def parse_debug_mode(cls, v: object) -> object:
        if isinstance(v, str):
            normalized = v.strip().lower()
            if normalized in {"release", "prod", "production", "false", "0", "no", "off"}:
                return False
            if normalized in {"debug", "dev", "development", "true", "1", "yes", "on"}:
                return True
        return v

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


class APISettings(BaseSettings):
    """API server configuration."""

    api_host: str = Field(default="0.0.0.0", description="API host")
    api_port: int = Field(default=8000, description="API port")
    api_workers: int = Field(default=4, description="Number of worker processes")
    api_cors_origins: str = Field(
        default="http://localhost:8080,http://localhost:3000",
        description="Allowed CORS origins (comma-separated)",
    )
    require_https: bool = Field(
        default=False,
        description="Require HTTPS for non-localhost browser and API traffic",
    )

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.api_cors_origins.split(",")]

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


class WebSocketSettings(BaseSettings):
    """WebSocket server configuration."""

    ws_host: str = Field(default="0.0.0.0", description="WebSocket host")
    ws_port: int = Field(default=8001, description="WebSocket port")
    ws_heartbeat_interval: int = Field(default=30, description="Heartbeat interval in seconds")

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


class CaptureSettings(BaseSettings):
    """Packet capture configuration."""

    capture_source: CaptureSource = Field(
        default=CaptureSource.SIMULATION,
        description="Packet source: simulation or tshark",
    )
    capture_interface: str = Field(
        default="auto",
        description="TShark interface name/number, or auto for the active Windows default route",
    )
    capture_target_host: str = Field(
        default="",
        description="Protected server IP/host to filter live traffic, or all/blank for all local IP traffic",
    )
    capture_target_ports: str = Field(
        default="80,443",
        description="Comma-separated protected target ports",
    )
    tshark_path: str = Field(default="tshark", description="Path to TShark executable")
    capture_batch_size: int = Field(default=200, description="Live capture batch size")
    capture_idle_timeout_seconds: int = Field(
        default=10,
        description="Seconds without packets before live capture is reported idle",
    )

    @property
    def target_ports_list(self) -> list[int]:
        from src.ingestion.tshark_capture import parse_ports

        return parse_ports(self.capture_target_ports)

    @field_validator("capture_batch_size", "capture_idle_timeout_seconds")
    @classmethod
    def validate_batch_size(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("capture_batch_size must be greater than 0")
        return v

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


class KafkaSettings(BaseSettings):
    """Kafka cluster configuration."""

    kafka_bootstrap_servers: str = Field(
        default="localhost:9092,localhost:9093,localhost:9094",
        description="Kafka bootstrap servers",
    )
    kafka_topic_raw_packets: str = Field(default="raw-packets")
    kafka_topic_processed: str = Field(default="processed-features")
    kafka_topic_alerts: str = Field(default="detection-alerts")
    kafka_consumer_group: str = Field(default="ddos-detector")
    kafka_replication_factor: int = Field(default=3)
    kafka_num_partitions: int = Field(default=12)

    @property
    def bootstrap_servers_list(self) -> list[str]:
        return [s.strip() for s in self.kafka_bootstrap_servers.split(",")]

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


class SparkSettings(BaseSettings):
    """Spark streaming configuration."""

    spark_master: str = Field(default="local[*]", description="Spark master URL")
    spark_app_name: str = Field(default="ddos-stream-processor")
    spark_batch_interval: int = Field(default=1, description="Batch interval in seconds")
    spark_checkpoint_dir: str = Field(default="/tmp/spark-checkpoints")

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


class MLSettings(BaseSettings):
    """Machine learning model configuration."""

    model_dir: str = Field(default="./models", description="Model storage directory")
    isolation_forest_contamination: float = Field(default=0.05)
    autoencoder_latent_dim: int = Field(default=32)
    autoencoder_threshold_percentile: float = Field(default=95.0)
    ensemble_weights: str = Field(
        default="0.3,0.4,0.3",
        description="Weights for IF, GB, AE models",
    )
    training_upload_dir: str = Field(
        default="./data/uploads/cicddos2019",
        description="Temporary storage for uploaded CICDDoS CSV training datasets",
    )
    training_max_upload_bytes: int = Field(
        default=5 * 1024 * 1024 * 1024,
        description="Maximum accepted CSV upload size",
    )
    training_max_rows_per_class: int = Field(
        default=100_000,
        description="Maximum sampled BENIGN and attack rows for offline flow training",
    )

    @property
    def ensemble_weights_list(self) -> list[float]:
        return [float(w.strip()) for w in self.ensemble_weights.split(",")]

    @field_validator("isolation_forest_contamination")
    @classmethod
    def validate_contamination(cls, v: float) -> float:
        if not 0.0 < v < 0.5:
            raise ValueError("contamination must be between 0 and 0.5")
        return v

    @field_validator("training_max_upload_bytes", "training_max_rows_per_class")
    @classmethod
    def validate_training_limits(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("training upload limits must be greater than 0")
        return v

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


class AlertSettings(BaseSettings):
    """Alert system configuration."""

    alert_rate_limit: int = Field(default=100, description="Max alerts per minute")
    alert_cooldown_seconds: int = Field(default=300, description="Alert cooldown period")
    alert_escalation_timeout: int = Field(default=600, description="Escalation timeout")

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


class ResponseSettings(BaseSettings):
    """Automated response and firewall action configuration."""

    response_mode: ResponseMode = Field(
        default=ResponseMode.MONITOR,
        description="Response mode: monitor records intended actions; enforce executes firewall changes",
    )
    auto_block_enabled: bool = Field(
        default=False,
        description="Enable automatic TTL-based blocking for high-confidence alerts",
    )
    response_kill_switch: bool = Field(
        default=True,
        description="Emergency switch that rejects all new response actions",
    )
    mitigation_activation_allowed: bool = Field(
        default=False,
        description="Release gate required before enforce mode or automatic blocking can be enabled",
    )
    response_api_token: Optional[str] = Field(
        default=None,
        description="Optional token required in X-Response-Token for manual response APIs",
    )
    block_ttl_seconds: int = Field(default=1800, description="Default block TTL in seconds")
    auto_block_max_ips_per_alert: int = Field(
        default=5,
        description="Maximum source IPs to block from a single alert",
    )
    max_blocks_per_minute: int = Field(default=10, description="Rate limit for new blocks")
    max_active_blocks: int = Field(default=100, description="Maximum active enforced blocks")
    block_allowlist: str = Field(
        default=("127.0.0.1,::1,0.0.0.0,255.255.255.255," "224.0.0.0/4,ff00::/8"),
        description="Comma-separated IPs/CIDRs that must never be blocked",
    )
    firewall_backend: str = Field(
        default="auto",
        description="Firewall backend: auto, windows, or disabled",
    )

    @field_validator("block_ttl_seconds", "max_blocks_per_minute", "max_active_blocks")
    @classmethod
    def validate_positive_int(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("response numeric limits must be greater than 0")
        return v

    @field_validator("auto_block_max_ips_per_alert")
    @classmethod
    def validate_non_negative_int(cls, v: int) -> int:
        if v < 0:
            raise ValueError("auto_block_max_ips_per_alert cannot be negative")
        return v

    @property
    def allowlist_entries(self) -> list[str]:
        return [entry.strip() for entry in self.block_allowlist.split(",") if entry.strip()]

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


class LocalThreatSettings(BaseSettings):
    """Local Wi-Fi, captive portal, and USB network gadget protection."""

    local_threat_monitor_enabled: bool = Field(
        default=True,
        description="Enable local Wi-Fi/USB threat monitoring",
    )
    local_threat_scan_interval_seconds: int = Field(
        default=30,
        description="Seconds between local threat scans",
    )
    local_threat_response_mode: ResponseMode = Field(
        default=ResponseMode.MONITOR,
        description="Local threat response mode: monitor or enforce",
    )
    local_threat_auto_disconnect: bool = Field(
        default=False,
        description="Disconnect Wi-Fi automatically for high-confidence local findings in enforce mode",
    )
    local_threat_auto_disable_adapters: bool = Field(
        default=False,
        description="Disable suspicious USB network adapters automatically in enforce mode",
    )
    local_threat_enforcement_allowed: bool = Field(
        default=False,
        description="Release gate required before local Wi-Fi or adapter enforcement can be enabled",
    )
    trusted_wifi_ssids: str = Field(
        default="",
        description="Comma-separated trusted SSIDs for Evil Twin checks",
    )
    trusted_wifi_bssids: str = Field(
        default="",
        description="SSID=BSSID1,BSSID2;OtherSSID=BSSID3 map for trusted access points",
    )
    trusted_usb_adapter_keywords: str = Field(
        default="",
        description="Comma-separated adapter description keywords to allowlist",
    )
    captive_portal_check_enabled: bool = Field(
        default=True,
        description="Check for captive portal or HTTP connectivity interception",
    )
    captive_portal_test_url: str = Field(
        default="http://www.msftconnecttest.com/connecttest.txt",
        description="HTTP URL used for captive portal detection",
    )
    captive_portal_expected_text: str = Field(
        default="Microsoft Connect Test",
        description="Expected response text for the captive portal test URL",
    )
    wireless_intelligence_enabled: bool = Field(
        default=True,
        description="Enable Enterprise passive wireless intelligence in local threat scans",
    )
    wireless_oui_database_path: str = Field(
        default="./data/enterprise_oui.txt",
        description="Local IEEE OUI database for Enterprise wireless intelligence",
    )
    wireless_suspicious_ouis: str = Field(
        default="00:13:37,D8:EB:46,00:C0:CA,00:8F:DF,6C:E8:73",
        description="Comma-separated OUI prefixes monitored as wireless review signals",
    )
    wireless_suspicious_ssid_patterns: str = Field(
        default="Pineapple,Free Public WiFi,HACKED,Pwned,evil_twin,karma",
        description="Comma-separated SSID name fragments monitored by wireless intelligence",
    )
    wireless_multi_ssid_threshold: int = Field(
        default=3,
        description="Distinct SSIDs on one BSSID before a wireless signal is emitted",
    )

    @field_validator("local_threat_scan_interval_seconds")
    @classmethod
    def validate_scan_interval(cls, v: int) -> int:
        if v < 5:
            raise ValueError("local_threat_scan_interval_seconds must be at least 5")
        return v

    @field_validator("wireless_multi_ssid_threshold")
    @classmethod
    def validate_wireless_multi_ssid_threshold(cls, v: int) -> int:
        if v < 2:
            raise ValueError("wireless_multi_ssid_threshold must be at least 2")
        return v

    @property
    def trusted_wifi_ssids_list(self) -> list[str]:
        return [ssid.strip() for ssid in self.trusted_wifi_ssids.split(",") if ssid.strip()]

    @property
    def trusted_usb_adapter_keywords_list(self) -> list[str]:
        return [
            keyword.strip()
            for keyword in self.trusted_usb_adapter_keywords.split(",")
            if keyword.strip()
        ]

    @property
    def wireless_suspicious_ouis_list(self) -> list[str]:
        return [
            value.strip() for value in self.wireless_suspicious_ouis.split(",") if value.strip()
        ]

    @property
    def wireless_suspicious_ssid_patterns_list(self) -> list[str]:
        return [
            value.strip()
            for value in self.wireless_suspicious_ssid_patterns.split(",")
            if value.strip()
        ]

    @property
    def trusted_wifi_bssids_map(self) -> dict[str, set[str]]:
        result: dict[str, set[str]] = {}
        for raw_entry in self.trusted_wifi_bssids.split(";"):
            if "=" not in raw_entry:
                continue
            ssid, raw_bssids = raw_entry.split("=", 1)
            ssid = ssid.strip()
            if not ssid:
                continue
            result[ssid] = {
                bssid.strip().lower().replace("-", ":")
                for bssid in raw_bssids.split(",")
                if bssid.strip()
            }
        return result

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


class IntegrationSettings(BaseSettings):
    """External integration configuration."""

    pagerduty_api_key: Optional[str] = Field(default=None)
    pagerduty_service_id: Optional[str] = Field(default=None)
    slack_webhook_url: Optional[str] = Field(default=None)
    slack_channel: str = Field(default="#security-alerts")
    siem_host: Optional[str] = Field(default=None)
    siem_port: int = Field(default=514)
    email_smtp_host: str = Field(default="smtp.gmail.com")
    email_smtp_port: int = Field(default=587)
    email_username: Optional[str] = Field(default=None)
    email_password: Optional[str] = Field(default=None)
    email_from: str = Field(default="ddos-alerts@example.com")
    jira_url: Optional[str] = Field(default=None)
    jira_username: Optional[str] = Field(default=None)
    jira_api_token: Optional[str] = Field(default=None)
    jira_project_key: str = Field(default="SEC")

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


class JWTSettings(BaseSettings):
    """JWT authentication settings."""

    jwt_secret_key: str = Field(default="change-me-to-a-jwt-secret")
    jwt_algorithm: str = Field(default="HS256")
    jwt_expiration_minutes: int = Field(default=60)

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


class DatabaseSettings(BaseSettings):
    """Database configuration."""

    database_url: str = Field(default="sqlite:///./ddos_detection.db")

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}


class Settings:
    """Aggregated application settings."""

    def __init__(self) -> None:
        self.app = AppSettings()
        self.api = APISettings()
        self.websocket = WebSocketSettings()
        self.capture = CaptureSettings()
        self.kafka = KafkaSettings()
        self.spark = SparkSettings()
        self.ml = MLSettings()
        self.alert = AlertSettings()
        self.response = ResponseSettings()
        self.local_threat = LocalThreatSettings()
        self.integrations = IntegrationSettings()
        self.jwt = JWTSettings()
        self.database = DatabaseSettings()

    @property
    def is_production(self) -> bool:
        return self.app.app_env == Environment.PRODUCTION

    @property
    def is_development(self) -> bool:
        return self.app.app_env == Environment.DEVELOPMENT

    def validate_runtime_safety(self) -> None:
        """Reject unsafe active configuration unless an explicit release gate permits it."""
        violations: list[str] = []
        if not self.response.mitigation_activation_allowed:
            if self.response.response_mode == ResponseMode.ENFORCE:
                violations.append(
                    "RESPONSE_MODE=enforce requires MITIGATION_ACTIVATION_ALLOWED=true"
                )
            if self.response.auto_block_enabled:
                violations.append(
                    "AUTO_BLOCK_ENABLED=true requires MITIGATION_ACTIVATION_ALLOWED=true"
                )
        if not self.local_threat.local_threat_enforcement_allowed:
            if self.local_threat.local_threat_response_mode == ResponseMode.ENFORCE:
                violations.append(
                    "LOCAL_THREAT_RESPONSE_MODE=enforce requires LOCAL_THREAT_ENFORCEMENT_ALLOWED=true"
                )
            if self.local_threat.local_threat_auto_disconnect:
                violations.append(
                    "LOCAL_THREAT_AUTO_DISCONNECT=true requires LOCAL_THREAT_ENFORCEMENT_ALLOWED=true"
                )
            if self.local_threat.local_threat_auto_disable_adapters:
                violations.append(
                    "LOCAL_THREAT_AUTO_DISABLE_ADAPTERS=true requires LOCAL_THREAT_ENFORCEMENT_ALLOWED=true"
                )
        if violations:
            raise RuntimeError("Unsafe runtime configuration rejected: " + "; ".join(violations))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Get cached application settings singleton."""
    return Settings()
