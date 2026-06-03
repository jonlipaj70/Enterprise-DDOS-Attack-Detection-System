"""
Local Wi-Fi and USB network threat guard.

Detects defensive signals associated with rogue USB network gadgets, Evil Twin
Wi-Fi access points, and captive portal interception. The guard is intentionally
passive by default; enforcement is opt-in through settings.
"""

from __future__ import annotations

import json
import platform
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from src.config.logging_config import get_logger
from src.local_security.wireless_intelligence import EnterpriseWirelessAnalyzer, WirelessSignal

logger = get_logger(__name__)

CommandRunner = Callable[[list[str], float], str]
HttpGetter = Callable[[str, float], tuple[int, str, str]]


SEVERITY_SCORE = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "warning": 3,
    "high": 4,
    "critical": 5,
    "emergency": 6,
}

USB_NETWORK_KEYWORDS = (
    "rndis",
    "remote ndis",
    "usb ethernet",
    "usb network",
    "ethernet gadget",
    "cdc ethernet",
    "linux usb ethernet",
    "linux foundation",
    "ecm",
    "ncm",
)

WIRELESS_KEYWORDS = ("wi-fi", "wifi", "wireless", "802.11", "wlan")
PINEAPPLE_DEFAULT_NETWORKS = ("172.16.42.", "172.16.43.")


@dataclass
class LocalThreatFinding:
    """One defensive local security finding."""

    category: str
    severity: str
    title: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommended_response: str = ""
    confidence: float = 0.7
    enforceable: bool = False
    timestamp: float = field(default_factory=time.time)

    @property
    def dedup_key(self) -> str:
        key_parts = [self.category, self.title]
        for field_name in ("ssid", "bssid", "adapter_name", "interface_alias"):
            value = self.evidence.get(field_name)
            if value:
                key_parts.append(str(value))
        return ":".join(key_parts).lower()

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommended_response": self.recommended_response,
            "confidence": self.confidence,
            "enforceable": self.enforceable,
            "dedup_key": self.dedup_key,
        }

    def to_alert_payload(self) -> dict[str, Any]:
        detection_sources = ["local_threat_guard"]
        if self.evidence.get("detector") == "enterprise_wireless":
            detection_sources.append("enterprise_wireless_analyzer")
        return {
            "is_anomaly": True,
            "attack_type": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "detection_sources": detection_sources,
            "evidence": self.evidence,
            "recommended_response": self.recommended_response,
            "anomaly_score": min(1.0, 0.45 + SEVERITY_SCORE.get(self.severity, 3) * 0.08),
            "confidence": self.confidence,
            "details": self.to_dict(),
            "dedup_key": self.dedup_key,
        }


@dataclass
class LocalSecuritySnapshot:
    """Latest local security scan result."""

    timestamp: float
    platform: str
    wifi_interface: dict[str, str]
    wifi_networks: list[dict[str, Any]]
    network_adapters: list[dict[str, Any]]
    ip_configurations: list[dict[str, Any]]
    findings: list[LocalThreatFinding]
    wireless_sensor: dict[str, Any] = field(default_factory=dict)
    response_actions: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "platform": self.platform,
            "wifi_interface": self.wifi_interface,
            "wifi_networks": self.wifi_networks,
            "network_adapters": self.network_adapters,
            "ip_configurations": self.ip_configurations,
            "findings": [finding.to_dict() for finding in self.findings],
            "wireless_sensor": self.wireless_sensor,
            "response_actions": self.response_actions,
            "errors": self.errors,
            "highest_severity": highest_severity(self.findings),
        }


class LocalThreatGuard:
    """Passive local Wi-Fi/USB threat detector with optional Wi-Fi disconnect."""

    def __init__(
        self,
        *,
        trusted_wifi_ssids: list[str] | None = None,
        trusted_wifi_bssids: dict[str, set[str]] | None = None,
        allowed_usb_adapter_keywords: list[str] | None = None,
        captive_portal_check_enabled: bool = True,
        captive_portal_test_url: str = "http://www.msftconnecttest.com/connecttest.txt",
        captive_portal_expected_text: str = "Microsoft Connect Test",
        response_mode: str = "monitor",
        auto_disconnect: bool = False,
        auto_disable_adapters: bool = False,
        wireless_intelligence_enabled: bool = True,
        wireless_analyzer: EnterpriseWirelessAnalyzer | None = None,
        command_runner: CommandRunner | None = None,
        http_getter: HttpGetter | None = None,
    ) -> None:
        self.trusted_wifi_ssids = {ssid.strip() for ssid in trusted_wifi_ssids or [] if ssid.strip()}
        self.trusted_wifi_bssids = {
            ssid: {normalize_bssid(bssid) for bssid in bssids if bssid.strip()}
            for ssid, bssids in (trusted_wifi_bssids or {}).items()
        }
        self.allowed_usb_adapter_keywords = [
            keyword.strip().lower()
            for keyword in allowed_usb_adapter_keywords or []
            if keyword.strip()
        ]
        self.captive_portal_check_enabled = captive_portal_check_enabled
        self.captive_portal_test_url = captive_portal_test_url
        self.captive_portal_expected_text = captive_portal_expected_text
        self.response_mode = response_mode
        self.auto_disconnect = auto_disconnect
        self.auto_disable_adapters = auto_disable_adapters
        self.wireless_intelligence_enabled = wireless_intelligence_enabled
        self.wireless_analyzer = wireless_analyzer
        self.command_runner = command_runner or run_command
        self.http_getter = http_getter or http_get

    @classmethod
    def from_settings(cls, settings: Any) -> "LocalThreatGuard":
        return cls(
            trusted_wifi_ssids=settings.trusted_wifi_ssids_list,
            trusted_wifi_bssids=settings.trusted_wifi_bssids_map,
            allowed_usb_adapter_keywords=settings.trusted_usb_adapter_keywords_list,
            captive_portal_check_enabled=settings.captive_portal_check_enabled,
            captive_portal_test_url=settings.captive_portal_test_url,
            captive_portal_expected_text=settings.captive_portal_expected_text,
            response_mode=settings.local_threat_response_mode.value,
            auto_disconnect=settings.local_threat_auto_disconnect,
            auto_disable_adapters=settings.local_threat_auto_disable_adapters,
            wireless_intelligence_enabled=settings.wireless_intelligence_enabled,
            wireless_analyzer=EnterpriseWirelessAnalyzer(
                oui_database_path=settings.wireless_oui_database_path,
                suspicious_ouis=settings.wireless_suspicious_ouis_list,
                suspicious_ssid_patterns=settings.wireless_suspicious_ssid_patterns_list,
                multi_ssid_threshold=settings.wireless_multi_ssid_threshold,
            )
            if settings.wireless_intelligence_enabled
            else None,
        )

    def scan(self) -> LocalSecuritySnapshot:
        errors: list[str] = []
        wifi_interface: dict[str, str] = {}
        wifi_networks: list[dict[str, Any]] = []
        network_adapters: list[dict[str, Any]] = []
        ip_configurations: list[dict[str, Any]] = []
        wireless_sensor: dict[str, Any] = {
            "enabled": self.wireless_intelligence_enabled,
            "mode": "disabled",
        }

        if platform.system().lower() == "windows":
            wifi_interface = self._safe_command(
                ["netsh", "wlan", "show", "interfaces"],
                parse_netsh_wlan_interfaces,
                errors,
            ) or {}
            wifi_networks = self._safe_command(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                parse_netsh_wlan_networks,
                errors,
            ) or []
            network_adapters = self._safe_command(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    (
                        "Get-CimInstance Win32_NetworkAdapter | "
                        "Where-Object { $_.PhysicalAdapter -eq $true -or $_.NetEnabled -eq $true } | "
                        "Select-Object Name,NetConnectionID,Description,PNPDeviceID,ServiceName,"
                        "MACAddress,NetEnabled,PhysicalAdapter | ConvertTo-Json -Compress"
                    ),
                ],
                parse_json_objects,
                errors,
            ) or []
            ip_configurations = self._safe_command(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    (
                        "Get-NetIPConfiguration | Select-Object InterfaceAlias,InterfaceDescription,"
                        "IPv4Address,IPv4DefaultGateway,DNSServer | ConvertTo-Json -Compress"
                    ),
                ],
                parse_json_objects,
                errors,
            ) or []
        else:
            errors.append("local threat guard currently supports Windows network inspection")

        findings = []
        findings.extend(self.detect_usb_network_gadgets(network_adapters, ip_configurations))
        findings.extend(self.detect_evil_twin(wifi_interface, wifi_networks))
        if self.wireless_intelligence_enabled and self.wireless_analyzer:
            wifi_networks = self.wireless_analyzer.enrich_networks(wifi_networks)
            wireless_sensor = self.wireless_analyzer.status()
            findings.extend(self.detect_wireless_signals(wifi_interface, wifi_networks))

        if self.captive_portal_check_enabled and wifi_interface.get("ssid"):
            captive_finding = self.detect_captive_portal(wifi_interface)
            if captive_finding:
                findings.append(captive_finding)

        actions = self.enforce(findings)

        return LocalSecuritySnapshot(
            timestamp=time.time(),
            platform=platform.platform(),
            wifi_interface=wifi_interface,
            wifi_networks=wifi_networks,
            network_adapters=network_adapters,
            ip_configurations=ip_configurations,
            findings=findings,
            wireless_sensor=wireless_sensor,
            response_actions=actions,
            errors=errors,
        )

    def detect_usb_network_gadgets(
        self,
        adapters: list[dict[str, Any]],
        ip_configurations: list[dict[str, Any]],
    ) -> list[LocalThreatFinding]:
        findings: list[LocalThreatFinding] = []
        ip_by_alias = {
            str(config.get("InterfaceAlias", "")).lower(): config for config in ip_configurations
        }

        for adapter in adapters:
            haystack = " ".join(
                str(adapter.get(key, ""))
                for key in ("Name", "NetConnectionID", "Description", "PNPDeviceID", "ServiceName")
            ).lower()
            if any(keyword in haystack for keyword in self.allowed_usb_adapter_keywords):
                continue

            pnp_id = str(adapter.get("PNPDeviceID", ""))
            is_usb = "usb" in pnp_id.lower() or "usb" in haystack
            is_wireless = any(keyword in haystack for keyword in WIRELESS_KEYWORDS)
            is_usb_network = any(keyword in haystack for keyword in USB_NETWORK_KEYWORDS)
            if not is_usb:
                continue

            alias = str(adapter.get("NetConnectionID") or adapter.get("Name") or "")
            ip_config = ip_by_alias.get(alias.lower(), {})
            ip_text = json.dumps(ip_config, default=str).lower()
            pineapple_default = any(prefix in ip_text for prefix in PINEAPPLE_DEFAULT_NETWORKS)

            if pineapple_default:
                findings.append(
                    LocalThreatFinding(
                        category="rogue_usb_network_gadget",
                        severity="critical",
                        title="Suspicious USB network gadget with Pineapple-like network",
                        description=(
                            "A USB network adapter is using an address range commonly associated "
                            "with Wi-Fi Pineapple style management networks."
                        ),
                        evidence={
                            "adapter": adapter,
                            "ip_configuration": ip_config,
                            "adapter_name": alias,
                        },
                        recommended_response=(
                            "Unplug the device, disable the adapter, and inspect USB devices before "
                            "using trusted networks."
                        ),
                        confidence=0.92,
                        enforceable=True,
                    )
                )
            elif is_usb_network and not is_wireless:
                findings.append(
                    LocalThreatFinding(
                        category="rogue_usb_network_gadget",
                        severity="high",
                        title="Suspicious USB Ethernet/RNDIS adapter detected",
                        description=(
                            "A USB network adapter looks like an Ethernet/RNDIS gadget. These are "
                            "commonly used by small attack devices that impersonate ordinary USB hardware."
                        ),
                        evidence={
                            "adapter": adapter,
                            "ip_configuration": ip_config,
                            "adapter_name": alias,
                        },
                        recommended_response=(
                            "If this adapter was not expected, unplug it and disable the adapter from "
                            "Windows Network Connections."
                        ),
                        confidence=0.82,
                        enforceable=True,
                    )
                )
            elif is_usb_network:
                findings.append(
                    LocalThreatFinding(
                        category="usb_network_adapter_review",
                        severity="medium",
                        title="USB network adapter needs review",
                        description="A USB network-capable adapter is active and should be verified.",
                        evidence={
                            "adapter": adapter,
                            "ip_configuration": ip_config,
                            "adapter_name": alias,
                        },
                        recommended_response="Confirm the adapter is yours or add it to the trusted adapter list.",
                        confidence=0.62,
                    )
                )

        return findings

    def detect_wireless_signals(
        self,
        current_wifi: dict[str, str],
        nearby_networks: list[dict[str, Any]],
    ) -> list[LocalThreatFinding]:
        """Translate Enterprise wireless indicators into control-plane findings."""
        if not self.wireless_analyzer:
            return []
        signals = self.wireless_analyzer.analyze(current_wifi, nearby_networks)
        return [self._from_wireless_signal(signal) for signal in signals]

    @staticmethod
    def _from_wireless_signal(signal: WirelessSignal) -> LocalThreatFinding:
        return LocalThreatFinding(
            category=signal.category,
            severity=signal.severity,
            title=signal.title,
            description=signal.description,
            evidence=signal.evidence,
            recommended_response=signal.recommended_response,
            confidence=signal.confidence,
        )

    def detect_evil_twin(
        self,
        current_wifi: dict[str, str],
        nearby_networks: list[dict[str, Any]],
    ) -> list[LocalThreatFinding]:
        findings: list[LocalThreatFinding] = []
        ssid = current_wifi.get("ssid", "").strip()
        if not ssid:
            return findings

        bssid = normalize_bssid(current_wifi.get("bssid", ""))
        auth = current_wifi.get("authentication", "").lower()
        cipher = current_wifi.get("cipher", "").lower()
        trusted_bssids = self.trusted_wifi_bssids.get(ssid, set())
        is_trusted_ssid = ssid in self.trusted_wifi_ssids or bool(trusted_bssids)

        if is_trusted_ssid and auth in {"open", "none", ""}:
            findings.append(
                LocalThreatFinding(
                    category="evil_twin_wifi",
                    severity="critical",
                    title="Trusted SSID is using open authentication",
                    description=(
                        "The connected Wi-Fi name matches a trusted SSID, but the authentication "
                        "mode is open or missing. This is a strong Evil Twin indicator."
                    ),
                    evidence={"ssid": ssid, "bssid": bssid, "authentication": auth, "cipher": cipher},
                    recommended_response="Disconnect immediately and forget the suspicious network profile.",
                    confidence=0.93,
                    enforceable=True,
                )
            )

        if trusted_bssids and bssid and bssid not in trusted_bssids:
            findings.append(
                LocalThreatFinding(
                    category="evil_twin_wifi",
                    severity="high",
                    title="Connected BSSID is not in trusted list",
                    description=(
                        "The SSID is trusted, but the access point hardware address is not one of "
                        "the expected BSSIDs."
                    ),
                    evidence={
                        "ssid": ssid,
                        "bssid": bssid,
                        "trusted_bssids": sorted(trusted_bssids),
                        "authentication": auth,
                        "cipher": cipher,
                    },
                    recommended_response=(
                        "Disconnect, verify the router/AP MAC address, and update TRUSTED_WIFI_BSSIDS "
                        "only after confirming the AP is legitimate."
                    ),
                    confidence=0.87,
                    enforceable=True,
                )
            )

        same_ssid_networks = [network for network in nearby_networks if network.get("ssid") == ssid]
        security_profiles = {
            (
                str(network.get("authentication", "")).lower(),
                str(network.get("encryption", "")).lower(),
            )
            for network in same_ssid_networks
        }
        if len(security_profiles) > 1:
            findings.append(
                LocalThreatFinding(
                    category="evil_twin_wifi",
                    severity="high" if is_trusted_ssid else "warning",
                    title="Same SSID advertised with conflicting security",
                    description=(
                        "Nearby access points advertise the same Wi-Fi name with different security "
                        "settings, which is a common Evil Twin pattern."
                    ),
                    evidence={
                        "ssid": ssid,
                        "connected_bssid": bssid,
                        "security_profiles": sorted(list(security_profiles)),
                        "nearby_bssids": [
                            network.get("bssid") for network in same_ssid_networks if network.get("bssid")
                        ],
                    },
                    recommended_response=(
                        "Do not enter passwords or portal credentials. Disconnect and reconnect only "
                        "after validating the correct AP."
                    ),
                    confidence=0.78,
                    enforceable=is_trusted_ssid,
                )
            )

        return findings

    def detect_captive_portal(self, current_wifi: dict[str, str]) -> LocalThreatFinding | None:
        try:
            status, final_url, body = self.http_getter(self.captive_portal_test_url, 4.0)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            logger.warning("captive_portal_check_failed", error=str(exc))
            return None

        redirected = final_url.rstrip("/") != self.captive_portal_test_url.rstrip("/")
        body_mismatch = self.captive_portal_expected_text not in body
        if status in {301, 302, 303, 307, 308} or redirected or body_mismatch:
            ssid = current_wifi.get("ssid", "")
            is_trusted_wifi = ssid in self.trusted_wifi_ssids or ssid in self.trusted_wifi_bssids
            return LocalThreatFinding(
                category="captive_portal_interception",
                severity="high" if is_trusted_wifi else "warning",
                title="Captive portal or HTTP interception detected",
                description=(
                    "The connectivity check was redirected or modified. This may be a normal captive "
                    "portal, but on an unexpected Wi-Fi network it can indicate a credential-harvesting portal."
                ),
                evidence={
                    "ssid": ssid,
                    "bssid": normalize_bssid(current_wifi.get("bssid", "")),
                    "status": status,
                    "final_url": final_url,
                    "expected_url": self.captive_portal_test_url,
                },
                recommended_response=(
                    "Avoid entering credentials into the portal until the network is verified. Prefer "
                    "mobile hotspot or a known trusted network."
                ),
                confidence=0.82 if is_trusted_wifi else 0.66,
                enforceable=is_trusted_wifi,
            )
        return None

    def enforce(self, findings: list[LocalThreatFinding]) -> list[dict[str, Any]]:
        if self.response_mode != "enforce":
            return []

        actions: list[dict[str, Any]] = []
        should_disconnect_wifi = self.auto_disconnect and any(
            finding.enforceable
            and finding.category in {"evil_twin_wifi", "captive_portal_interception"}
            and SEVERITY_SCORE.get(finding.severity, 0) >= SEVERITY_SCORE["high"]
            for finding in findings
        )

        if should_disconnect_wifi:
            try:
                output = self.command_runner(["netsh", "wlan", "disconnect"], 8.0)
                actions.append(
                    {
                        "timestamp": time.time(),
                        "action": "wifi_disconnect",
                        "status": "executed",
                        "output": output[-500:],
                    }
                )
            except Exception as exc:
                actions.append(
                    {
                        "timestamp": time.time(),
                        "action": "wifi_disconnect",
                        "status": "failed",
                        "error": str(exc),
                    }
                )

        if self.auto_disable_adapters:
            disabled_adapters: set[str] = set()
            for finding in findings:
                if (
                    finding.category != "rogue_usb_network_gadget"
                    or not finding.enforceable
                    or SEVERITY_SCORE.get(finding.severity, 0) < SEVERITY_SCORE["high"]
                ):
                    continue

                adapter_name = self._adapter_name_from_finding(finding)
                if not adapter_name or adapter_name in disabled_adapters:
                    continue

                disabled_adapters.add(adapter_name)
                try:
                    output = self._disable_network_adapter(adapter_name)
                    actions.append(
                        {
                            "timestamp": time.time(),
                            "action": "disable_network_adapter",
                            "adapter_name": adapter_name,
                            "status": "executed",
                            "output": output[-500:],
                        }
                    )
                except Exception as exc:
                    actions.append(
                        {
                            "timestamp": time.time(),
                            "action": "disable_network_adapter",
                            "adapter_name": adapter_name,
                            "status": "failed",
                            "error": str(exc),
                        }
                    )

        return actions

    def _adapter_name_from_finding(self, finding: LocalThreatFinding) -> str:
        adapter = finding.evidence.get("adapter", {})
        if isinstance(adapter, dict):
            return str(
                finding.evidence.get("adapter_name")
                or adapter.get("NetConnectionID")
                or adapter.get("Name")
                or ""
            ).strip()
        return str(finding.evidence.get("adapter_name", "")).strip()

    def _disable_network_adapter(self, adapter_name: str) -> str:
        return self.command_runner(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                (
                    "$AdapterName = $args[0]; "
                    "Disable-NetAdapter -Name $AdapterName -Confirm:$false -ErrorAction Stop"
                ),
                adapter_name,
            ],
            12.0,
        )

    def _safe_command(
        self,
        command: list[str],
        parser: Callable[[str], Any],
        errors: list[str],
    ) -> Any:
        try:
            return parser(self.command_runner(command, 10.0))
        except Exception as exc:
            errors.append(f"{command[0]} failed: {exc}")
            logger.warning("local_security_command_failed", command=command[0], error=str(exc))
            return None


def run_command(command: list[str], timeout: float) -> str:
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout or "").strip())
    return completed.stdout


class NoRedirectHandler(HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):  # noqa: N802
        raise HTTPError(req.full_url, code, msg, headers, fp)

    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302
    http_error_308 = http_error_302


def http_get(url: str, timeout: float) -> tuple[int, str, str]:
    opener = build_opener(NoRedirectHandler())
    request = Request(url, headers={"User-Agent": "ddos-detection-local-guard/1.0"})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(512).decode("utf-8", errors="replace")
            return int(response.status), response.geturl(), body
    except HTTPError as exc:
        location = exc.headers.get("Location", url) if exc.headers else url
        return int(exc.code), location, ""


def parse_netsh_wlan_interfaces(output: str) -> dict[str, str]:
    sections: list[dict[str, str]] = []
    fields: dict[str, str] = {}
    key_map = {
        "name": "name",
        "description": "description",
        "guid": "guid",
        "physical address": "mac_address",
        "state": "state",
        "ssid": "ssid",
        "bssid": "bssid",
        "ap bssid": "bssid",
        "network type": "network_type",
        "radio type": "radio_type",
        "authentication": "authentication",
        "cipher": "cipher",
        "channel": "channel",
        "receive rate (mbps)": "receive_rate_mbps",
        "transmit rate (mbps)": "transmit_rate_mbps",
        "signal": "signal",
        "profile": "profile",
    }
    for raw_line in output.splitlines():
        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        normalized = re.sub(r"\s+", " ", key.strip().lower())
        if normalized == "name" and fields:
            sections.append(fields)
            fields = {}
        if normalized == "ssid" and "bssid" in fields:
            continue
        mapped_key = key_map.get(normalized)
        if mapped_key:
            fields[mapped_key] = value.strip()

    if fields:
        sections.append(fields)

    for section in sections:
        if "bssid" in section:
            section["bssid"] = normalize_bssid(section["bssid"])

    connected = [
        section
        for section in sections
        if section.get("state", "").lower() == "connected" and section.get("ssid")
    ]
    if connected:
        return connected[0]

    with_ssid = [section for section in sections if section.get("ssid")]
    if with_ssid:
        return with_ssid[0]

    return sections[0] if sections else {}


def parse_netsh_wlan_networks(output: str) -> list[dict[str, Any]]:
    networks: list[dict[str, Any]] = []
    current_ssid = ""
    current_auth = ""
    current_encryption = ""

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = re.sub(r"\s+", " ", key.strip().lower())
        value = value.strip()

        if key.startswith("ssid "):
            current_ssid = value
            current_auth = ""
            current_encryption = ""
        elif key == "authentication":
            current_auth = value
        elif key == "encryption":
            current_encryption = value
        elif key.startswith("bssid "):
            networks.append(
                {
                    "ssid": current_ssid,
                    "bssid": normalize_bssid(value),
                    "authentication": current_auth,
                    "encryption": current_encryption,
                }
            )
        elif key == "signal" and networks:
            networks[-1]["signal"] = value
        elif key == "channel" and networks:
            networks[-1]["channel"] = value
        elif key == "radio type" and networks:
            networks[-1]["radio_type"] = value

    return networks


def parse_json_objects(output: str) -> list[dict[str, Any]]:
    text = output.strip()
    if not text:
        return []
    data = json.loads(text)
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [entry for entry in data if isinstance(entry, dict)]
    return []


def normalize_bssid(value: str) -> str:
    value = value.strip().lower().replace("-", ":")
    parts = [part.zfill(2) for part in value.split(":") if part]
    if len(parts) == 6:
        return ":".join(parts)
    return value


def highest_severity(findings: list[LocalThreatFinding]) -> str:
    if not findings:
        return "info"
    return max(findings, key=lambda finding: SEVERITY_SCORE.get(finding.severity, 0)).severity
