"""
Enterprise wireless intelligence for the Enterprise DDoS control plane.

This module consumes passive nearby-network observations already collected on
Windows. It intentionally does not claim 802.11 monitor-mode features such as
deauthentication-frame capture when the platform cannot expose those frames.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_PLAIN_OUI = re.compile(r"^([0-9A-Fa-f]{6})\s+(.+)$")
_IEEE_OUI = re.compile(
    r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$"
)


@dataclass
class WirelessSignal:
    """One passive wireless indicator detected from observed access points."""

    category: str
    severity: str
    title: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommended_response: str = ""
    confidence: float = 0.6


class OUIDatabase:
    """Small in-memory IEEE OUI lookup for passive wireless observations."""

    def __init__(self, path: str = "") -> None:
        self.path = Path(path) if path else None
        self._vendors: dict[str, str] = {}
        self.loaded = False
        self.load_error: str | None = None
        self._load()

    def _load(self) -> None:
        if not self.path:
            self.load_error = "OUI database path is not configured"
            return
        if not self.path.is_file():
            self.load_error = f"OUI database not found: {self.path}"
            return

        try:
            with self.path.open("r", encoding="utf-8", errors="replace") as source:
                for line in source:
                    parsed = self._parse_line(line)
                    if parsed:
                        oui, vendor = parsed
                        self._vendors[oui] = vendor
            self.loaded = True
        except OSError as error:
            self.load_error = str(error)

    @staticmethod
    def _parse_line(line: str) -> tuple[str, str] | None:
        text = line.rstrip()
        match = _PLAIN_OUI.match(text)
        if match and "(hex)" not in text and "(base 16)" not in text:
            return match.group(1).upper(), match.group(2).strip()
        match = _IEEE_OUI.match(text)
        if match:
            return match.group(1).replace("-", "").upper(), match.group(2).strip()
        return None

    def lookup(self, mac_address: str) -> str:
        compact = re.sub(r"[^0-9A-Fa-f]", "", mac_address).upper()
        if len(compact) < 6:
            return "Unknown"
        return self._vendors.get(compact[:6], "Unknown")

    @property
    def entry_count(self) -> int:
        return len(self._vendors)

    def status(self) -> dict[str, Any]:
        return {
            "loaded": self.loaded,
            "entry_count": self.entry_count,
            "source": str(self.path) if self.path else None,
            "error": self.load_error,
        }


class EnterpriseWirelessAnalyzer:
    """
    Run wireless intelligence signals using Windows-visible passive observations.

    Full deauthentication/Karma frame analysis is not represented here because
    it requires a monitor-mode 802.11 capture source, which the current Windows
    production sensor does not supply reliably.
    """

    def __init__(
        self,
        *,
        oui_database_path: str = "",
        suspicious_ouis: list[str] | None = None,
        suspicious_ssid_patterns: list[str] | None = None,
        multi_ssid_threshold: int = 3,
    ) -> None:
        self.oui_database = OUIDatabase(oui_database_path)
        self.suspicious_ouis = {
            self._normalize_oui(oui)
            for oui in (suspicious_ouis or [])
            if self._normalize_oui(oui)
        }
        self.suspicious_ssid_patterns = [
            pattern.strip().lower()
            for pattern in (suspicious_ssid_patterns or [])
            if pattern.strip()
        ]
        self.multi_ssid_threshold = max(2, multi_ssid_threshold)

    @staticmethod
    def _normalize_oui(value: str) -> str:
        return re.sub(r"[^0-9A-Fa-f]", "", value).upper()[:6]

    def enrich_networks(self, networks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        enriched: list[dict[str, Any]] = []
        for network in networks:
            item = dict(network)
            bssid = str(item.get("bssid", ""))
            oui = self._normalize_oui(bssid)
            item["vendor"] = self.oui_database.lookup(bssid)
            item["oui"] = oui
            item["wireless_suspicious_oui"] = bool(oui and oui in self.suspicious_ouis)
            enriched.append(item)
        return enriched

    def analyze(
        self,
        current_wifi: dict[str, str],
        nearby_networks: list[dict[str, Any]],
    ) -> list[WirelessSignal]:
        findings: list[WirelessSignal] = []
        findings.extend(self._find_suspicious_ouis(nearby_networks))
        findings.extend(self._find_suspicious_ssids(nearby_networks))
        findings.extend(self._find_multi_ssid_access_points(current_wifi, nearby_networks))
        return findings

    def _find_suspicious_ouis(self, networks: list[dict[str, Any]]) -> list[WirelessSignal]:
        findings: list[WirelessSignal] = []
        emitted: set[str] = set()
        for network in networks:
            if not network.get("wireless_suspicious_oui"):
                continue
            bssid = str(network.get("bssid", ""))
            if bssid in emitted:
                continue
            emitted.add(bssid)
            findings.append(
                WirelessSignal(
                    category="wireless_suspicious_access_point",
                    severity="warning",
                    title="Enterprise Wireless: access point matches monitored device OUI",
                    description=(
                        "A nearby access point matches a monitored wireless-device vendor prefix. "
                        "An OUI match is an indicator for review, not proof of an attack."
                    ),
                    evidence={
                        "detector": "enterprise_wireless",
                        "ssid": network.get("ssid", ""),
                        "bssid": bssid,
                        "oui": network.get("oui", ""),
                        "vendor": network.get("vendor", "Unknown"),
                    },
                    recommended_response=(
                        "Compare this access point with the expected router inventory and inspect "
                        "for duplicate SSIDs or security-profile changes."
                    ),
                    confidence=0.62,
                )
            )
        return findings

    def _find_suspicious_ssids(self, networks: list[dict[str, Any]]) -> list[WirelessSignal]:
        findings: list[WirelessSignal] = []
        emitted: set[tuple[str, str]] = set()
        for network in networks:
            ssid = str(network.get("ssid", ""))
            bssid = str(network.get("bssid", ""))
            matched = next(
                (pattern for pattern in self.suspicious_ssid_patterns if pattern in ssid.lower()),
                None,
            )
            if not matched or (ssid, bssid) in emitted:
                continue
            emitted.add((ssid, bssid))
            findings.append(
                WirelessSignal(
                    category="wireless_suspicious_ssid",
                    severity="warning",
                    title="Enterprise Wireless: suspicious wireless network name observed",
                    description=(
                        "A nearby SSID matches a lure or rogue-access-point naming pattern monitored "
                        "by the wireless sensor."
                    ),
                    evidence={
                        "detector": "enterprise_wireless",
                        "ssid": ssid,
                        "bssid": bssid,
                        "vendor": network.get("vendor", "Unknown"),
                        "matched_pattern": matched,
                    },
                    recommended_response="Do not connect to this network unless its ownership is verified.",
                    confidence=0.58,
                )
            )
        return findings

    def _find_multi_ssid_access_points(
        self,
        current_wifi: dict[str, str],
        networks: list[dict[str, Any]],
    ) -> list[WirelessSignal]:
        ssids_by_bssid: defaultdict[str, set[str]] = defaultdict(set)
        network_by_bssid: dict[str, dict[str, Any]] = {}
        for network in networks:
            bssid = str(network.get("bssid", ""))
            ssid = str(network.get("ssid", "")).strip()
            if bssid and ssid:
                ssids_by_bssid[bssid].add(ssid)
                network_by_bssid[bssid] = network

        current_bssid = str(current_wifi.get("bssid", "")).lower()
        findings: list[WirelessSignal] = []
        for bssid, ssids in ssids_by_bssid.items():
            if len(ssids) < self.multi_ssid_threshold:
                continue
            network = network_by_bssid[bssid]
            connected = bool(current_bssid and bssid.lower() == current_bssid)
            findings.append(
                WirelessSignal(
                    category="wireless_multi_ssid_access_point",
                    severity="high" if connected else "warning",
                    title="Enterprise Wireless: one access point advertises multiple SSIDs",
                    description=(
                        "One observed BSSID is advertising multiple distinct network names. This can "
                        "be legitimate, but is also consistent with rogue AP or Karma-style behavior."
                    ),
                    evidence={
                        "detector": "enterprise_wireless",
                        "bssid": bssid,
                        "vendor": network.get("vendor", "Unknown"),
                        "ssid_count": len(ssids),
                        "ssids": sorted(ssids),
                        "connected_bssid": connected,
                    },
                    recommended_response=(
                        "Verify the access point against known infrastructure before trusting any "
                        "of its advertised networks."
                    ),
                    confidence=0.76 if connected else 0.6,
                )
            )
        return findings

    def status(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "mode": "windows_passive_network_inventory",
            "capabilities": [
                "oui_vendor_lookup",
                "suspicious_oui_monitoring",
                "suspicious_ssid_monitoring",
                "multi_ssid_access_point_detection",
            ],
            "unavailable_without_monitor_mode": [
                "deauthentication_frame_detection",
                "karma_probe_response_detection",
            ],
            "oui_database": self.oui_database.status(),
        }
