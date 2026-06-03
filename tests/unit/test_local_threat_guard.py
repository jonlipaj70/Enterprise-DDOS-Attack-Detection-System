"""Unit tests for local Wi-Fi/USB threat guard."""

from src.local_security.wireless_intelligence import EnterpriseWirelessAnalyzer
from src.local_security.wifi_guard import (
    LocalThreatFinding,
    LocalThreatGuard,
    parse_netsh_wlan_interfaces,
    parse_netsh_wlan_networks,
)


NETSH_INTERFACES = """
There are 2 interfaces on the system:

    Name                   : Wi-Fi
    Description            : Realtek 8852BE Wireless LAN WiFi 6 PCI-E NIC
    State                  : connected
    SSID                   : Tectigon Ipko 5G
    AP BSSID               : 56:c2:50:cb:1f:69
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Channel                : 64

    Name                   : Wi-Fi 2
    Description            : TP-Link Wireless USB Adapter
    State                  : disconnected
"""


NETSH_NETWORKS = """
SSID 1 : Tectigon Ipko 5G
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 56:c2:50:cb:1f:69
         Signal             : 100%
         Channel            : 64

SSID 2 : Tectigon Ipko 5G
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Signal             : 91%
         Channel            : 6
"""


def test_parse_connected_wifi_interface_ignores_disconnected_second_adapter():
    interface = parse_netsh_wlan_interfaces(NETSH_INTERFACES)

    assert interface["name"] == "Wi-Fi"
    assert interface["ssid"] == "Tectigon Ipko 5G"
    assert interface["bssid"] == "56:c2:50:cb:1f:69"
    assert interface["state"] == "connected"


def test_parse_nearby_networks_keeps_security_per_bssid():
    networks = parse_netsh_wlan_networks(NETSH_NETWORKS)

    assert len(networks) == 2
    assert networks[0]["authentication"] == "WPA2-Personal"
    assert networks[1]["authentication"] == "Open"
    assert networks[1]["bssid"] == "aa:bb:cc:dd:ee:ff"


def test_evil_twin_detects_untrusted_bssid_for_trusted_ssid():
    guard = LocalThreatGuard(
        trusted_wifi_bssids={"Tectigon Ipko 5G": {"56:c2:50:cb:1f:69"}},
        captive_portal_check_enabled=False,
    )
    current = {
        "ssid": "Tectigon Ipko 5G",
        "bssid": "aa:bb:cc:dd:ee:ff",
        "authentication": "WPA2-Personal",
        "cipher": "CCMP",
    }

    findings = guard.detect_evil_twin(current, [])

    assert any(finding.category == "evil_twin_wifi" for finding in findings)
    assert any(finding.severity == "high" for finding in findings)


def test_evil_twin_detects_conflicting_security_for_same_ssid():
    guard = LocalThreatGuard(
        trusted_wifi_ssids=["Tectigon Ipko 5G"],
        captive_portal_check_enabled=False,
    )
    current = parse_netsh_wlan_interfaces(NETSH_INTERFACES)
    nearby = parse_netsh_wlan_networks(NETSH_NETWORKS)

    findings = guard.detect_evil_twin(current, nearby)

    assert any(
        finding.title == "Same SSID advertised with conflicting security"
        for finding in findings
    )


def test_usb_rndis_adapter_on_pineapple_range_is_critical():
    guard = LocalThreatGuard(captive_portal_check_enabled=False)
    adapters = [
        {
            "Name": "Remote NDIS Compatible Device",
            "NetConnectionID": "Ethernet 3",
            "Description": "USB Ethernet/RNDIS Gadget",
            "PNPDeviceID": "USB\\VID_1D6B&PID_0104\\123",
            "ServiceName": "usb_rndisx",
        }
    ]
    ip_configs = [
        {
            "InterfaceAlias": "Ethernet 3",
            "IPv4Address": [{"IPAddress": "172.16.42.2"}],
            "IPv4DefaultGateway": {"NextHop": "172.16.42.1"},
        }
    ]

    findings = guard.detect_usb_network_gadgets(adapters, ip_configs)

    assert len(findings) == 1
    assert findings[0].category == "rogue_usb_network_gadget"
    assert findings[0].severity == "critical"
    assert findings[0].enforceable is True


def test_enforce_disconnects_wifi_for_high_confidence_evil_twin():
    commands = []

    def fake_runner(command, timeout):
        commands.append(command)
        return "disconnected"

    guard = LocalThreatGuard(
        response_mode="enforce",
        auto_disconnect=True,
        captive_portal_check_enabled=False,
        command_runner=fake_runner,
    )
    finding = LocalThreatFinding(
        category="evil_twin_wifi",
        severity="high",
        title="Connected BSSID is not in trusted list",
        description="",
        enforceable=True,
    )

    actions = guard.enforce([finding])

    assert actions[0]["action"] == "wifi_disconnect"
    assert actions[0]["status"] == "executed"
    assert commands[0] == ["netsh", "wlan", "disconnect"]


def test_enforce_disables_high_confidence_usb_network_adapter():
    commands = []

    def fake_runner(command, timeout):
        commands.append(command)
        return "disabled"

    guard = LocalThreatGuard(
        response_mode="enforce",
        auto_disable_adapters=True,
        captive_portal_check_enabled=False,
        command_runner=fake_runner,
    )
    finding = LocalThreatFinding(
        category="rogue_usb_network_gadget",
        severity="critical",
        title="Suspicious USB Ethernet/RNDIS adapter detected",
        description="",
        evidence={"adapter": {"NetConnectionID": "Ethernet 3"}},
        enforceable=True,
    )

    actions = guard.enforce([finding])

    assert actions[0]["action"] == "disable_network_adapter"
    assert actions[0]["adapter_name"] == "Ethernet 3"
    assert actions[0]["status"] == "executed"
    assert commands[0][0] == "powershell.exe"
    assert "Disable-NetAdapter" in commands[0][5]
    assert commands[0][-1] == "Ethernet 3"


def test_enforce_does_not_disable_medium_review_findings():
    commands = []

    def fake_runner(command, timeout):
        commands.append(command)
        return "should not run"

    guard = LocalThreatGuard(
        response_mode="enforce",
        auto_disable_adapters=True,
        captive_portal_check_enabled=False,
        command_runner=fake_runner,
    )
    finding = LocalThreatFinding(
        category="usb_network_adapter_review",
        severity="medium",
        title="USB network adapter needs review",
        description="",
        evidence={"adapter": {"NetConnectionID": "Wi-Fi 2"}},
        enforceable=False,
    )

    assert guard.enforce([finding]) == []
    assert commands == []


def test_wireless_findings_are_labeled_and_not_enforceable(tmp_path):
    oui_path = tmp_path / "oui.txt"
    oui_path.write_text("001337 Hak5 LLC\n", encoding="utf-8")
    analyzer = EnterpriseWirelessAnalyzer(
        oui_database_path=str(oui_path),
        suspicious_ouis=["00:13:37"],
    )
    guard = LocalThreatGuard(
        captive_portal_check_enabled=False,
        wireless_analyzer=analyzer,
    )
    networks = analyzer.enrich_networks(
        [{"ssid": "Guest", "bssid": "00:13:37:aa:bb:cc"}]
    )

    findings = guard.detect_wireless_signals({}, networks)
    payload = findings[0].to_alert_payload()

    assert findings[0].enforceable is False
    assert "enterprise_wireless_analyzer" in payload["detection_sources"]
    assert guard.enforce(findings) == []
