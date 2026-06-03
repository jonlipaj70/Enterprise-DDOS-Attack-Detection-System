"""Unit tests for integrated Enterprise passive wireless signals."""

from pathlib import Path

from src.local_security.wireless_intelligence import EnterpriseWirelessAnalyzer, OUIDatabase


def make_analyzer(tmp_path: Path) -> EnterpriseWirelessAnalyzer:
    oui_path = tmp_path / "oui.txt"
    oui_path.write_text("001337 Hak5 LLC\nAABBCC Expected Networks\n", encoding="utf-8")
    return EnterpriseWirelessAnalyzer(
        oui_database_path=str(oui_path),
        suspicious_ouis=["00:13:37"],
        suspicious_ssid_patterns=["Pineapple"],
        multi_ssid_threshold=3,
    )


def test_oui_database_loads_plain_format(tmp_path: Path):
    oui_path = tmp_path / "oui.txt"
    oui_path.write_text("001337 Hak5 LLC\n", encoding="utf-8")

    database = OUIDatabase(str(oui_path))

    assert database.loaded is True
    assert database.entry_count == 1
    assert database.lookup("00:13:37:aa:bb:cc") == "Hak5 LLC"


def test_suspicious_oui_network_is_enriched_and_flagged(tmp_path: Path):
    analyzer = make_analyzer(tmp_path)
    networks = analyzer.enrich_networks(
        [{"ssid": "Guest", "bssid": "00:13:37:aa:bb:cc"}]
    )

    signals = analyzer.analyze({}, networks)

    assert networks[0]["vendor"] == "Hak5 LLC"
    assert networks[0]["wireless_suspicious_oui"] is True
    assert signals[0].category == "wireless_suspicious_access_point"
    assert signals[0].severity == "warning"


def test_multi_ssid_on_connected_access_point_is_high_severity(tmp_path: Path):
    analyzer = make_analyzer(tmp_path)
    networks = analyzer.enrich_networks(
        [
            {"ssid": "Office", "bssid": "aa:bb:cc:dd:ee:ff"},
            {"ssid": "Guest", "bssid": "aa:bb:cc:dd:ee:ff"},
            {"ssid": "Public", "bssid": "aa:bb:cc:dd:ee:ff"},
        ]
    )

    signals = analyzer.analyze({"bssid": "aa:bb:cc:dd:ee:ff"}, networks)
    multi_ssid = next(
        signal for signal in signals if signal.category == "wireless_multi_ssid_access_point"
    )

    assert multi_ssid.severity == "high"
    assert multi_ssid.evidence["ssid_count"] == 3
