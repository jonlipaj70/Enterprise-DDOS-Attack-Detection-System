"""Unit tests for live TShark capture parsing."""

import asyncio
import time

import pytest

from src.ingestion import tshark_capture
from src.ingestion.packet_capture import Protocol
from src.ingestion.tshark_capture import (
    TSHARK_FIELDS,
    TSharkCaptureAgent,
    TSharkConfigurationError,
    TSharkInterfaceChanged,
    build_capture_filter,
    build_tshark_command,
    parse_tshark_line,
    parse_tshark_interfaces,
    resolve_capture_interface,
    resolve_tshark_path,
)
from src.processing.window_aggregator import WindowAggregator


def _line(**values):
    row = {field: "" for field in TSHARK_FIELDS}
    row.update(values)
    return "\t".join(row[field] for field in TSHARK_FIELDS)


def test_parse_tcp_syn_packet():
    packet = parse_tshark_line(
        _line(
            **{
                "frame.time_epoch": "1710000000.5",
                "ip.src": "203.0.113.10",
                "ip.dst": "10.0.1.100",
                "ip.proto": "6",
                "frame.len": "60",
                "ip.ttl": "64",
                "tcp.srcport": "51432",
                "tcp.dstport": "80",
                "tcp.flags": "0x0002",
                "tcp.seq": "100",
                "tcp.ack": "0",
                "tcp.window_size_value": "1024",
                "tcp.len": "0",
            }
        )
    )

    assert packet is not None
    assert packet.protocol == int(Protocol.TCP)
    assert packet.src_port == 51432
    assert packet.dst_port == 80
    assert packet.flags == 0x02
    assert packet.payload_size == 0
    assert packet.sequence_number == 100
    assert packet.window_size == 1024


def test_parse_legacy_backslash_separated_packet():
    packet = parse_tshark_line(
        "\\".join(
            [
                "1710000000.5",
                "203.0.113.10",
                "10.0.1.100",
                "6",
                "60",
                "64",
                "51432",
                "80",
                "0x0002",
                "100",
                "0",
                "1024",
                "0",
                "",
                "",
                "",
                "",
                "",
                "0",
            ]
        )
    )

    assert packet is not None
    assert packet.protocol == int(Protocol.TCP)
    assert packet.src_ip == "203.0.113.10"
    assert packet.dst_ip == "10.0.1.100"
    assert packet.flags == 0x02


def test_parse_dns_udp_packet_normalizes_protocol():
    packet = parse_tshark_line(
        _line(
            **{
                "frame.time_epoch": "1710000001.0",
                "ip.src": "198.51.100.53",
                "ip.dst": "10.0.1.100",
                "ip.proto": "17",
                "frame.len": "96",
                "ip.ttl": "128",
                "udp.srcport": "53000",
                "udp.dstport": "53",
                "udp.length": "76",
            }
        )
    )

    assert packet is not None
    assert packet.protocol == int(Protocol.DNS)
    assert packet.src_port == 53000
    assert packet.dst_port == 53
    assert packet.payload_size == 68
    assert packet.flags == 0


def test_parse_icmp_packet_uses_zero_ports_and_flags():
    packet = parse_tshark_line(
        _line(
            **{
                "frame.time_epoch": "1710000002.0",
                "ip.src": "198.51.100.20",
                "ip.dst": "10.0.1.100",
                "ip.proto": "1",
                "frame.len": "84",
                "ip.ttl": "255",
                "icmp.type": "8",
                "icmp.code": "0",
            }
        )
    )

    assert packet is not None
    assert packet.protocol == int(Protocol.ICMP)
    assert packet.src_port == 0
    assert packet.dst_port == 0
    assert packet.flags == 0
    assert packet.payload_size == 56


def test_parse_ipv6_tcp_packet():
    packet = parse_tshark_line(
        _line(
            **{
                "frame.time_epoch": "1710000002.5",
                "frame.len": "74",
                "tcp.srcport": "51515",
                "tcp.dstport": "443",
                "tcp.flags": "0x0010",
                "tcp.seq": "10",
                "tcp.ack": "20",
                "tcp.window_size_value": "4096",
                "tcp.len": "0",
                "ipv6.src": "2001:db8::10",
                "ipv6.dst": "2001:db8::20",
                "ipv6.nxt": "6",
                "ipv6.hlim": "64",
            }
        )
    )

    assert packet is not None
    assert packet.protocol == int(Protocol.TCP)
    assert packet.src_ip == "2001:db8::10"
    assert packet.dst_ip == "2001:db8::20"
    assert packet.src_port == 51515
    assert packet.dst_port == 443
    assert packet.ttl == 64


def test_parse_fragmented_packet():
    packet = parse_tshark_line(
        _line(
            **{
                "frame.time_epoch": "1710000003.0",
                "ip.src": "198.51.100.30",
                "ip.dst": "10.0.1.100",
                "ip.proto": "17",
                "frame.len": "1500",
                "ip.ttl": "64",
                "udp.srcport": "44444",
                "udp.dstport": "443",
                "udp.length": "1480",
                "ip.frag_offset": "1480",
            }
        )
    )

    assert packet is not None
    assert packet.fragment_offset == 1480


def test_parse_missing_optional_fields_uses_safe_defaults():
    packet = parse_tshark_line(
        _line(
            **{
                "frame.time_epoch": "1710000004.0",
                "ip.src": "198.51.100.40",
                "ip.dst": "10.0.1.100",
                "ip.proto": "6",
                "frame.len": "54",
            }
        )
    )

    assert packet is not None
    assert packet.ttl == 0
    assert packet.src_port == 0
    assert packet.dst_port == 0
    assert packet.flags == 0
    assert packet.window_size == 65535


def test_parse_non_ip_row_is_skipped():
    assert parse_tshark_line(_line(**{"frame.time_epoch": "1710000005.0"})) is None


def test_build_capture_filter_for_target_host_and_ports():
    capture_filter = build_capture_filter("10.0.1.100", [80, 443])
    assert capture_filter == "host 10.0.1.100 and (tcp port 80 or tcp port 443)"


def test_build_capture_filter_adds_udp_for_dns_port():
    capture_filter = build_capture_filter("10.0.1.100", [53])
    assert capture_filter == "host 10.0.1.100 and (tcp port 53 or udp port 53)"


def test_build_capture_filter_all_traffic_when_target_empty():
    assert build_capture_filter("", [80]) == "ip or ip6"


def test_build_capture_filter_all_traffic_when_target_is_all():
    assert build_capture_filter("all", [80, 443]) == "ip or ip6"


def test_build_tshark_command_contains_fields_and_filter():
    command = build_tshark_command(
        tshark_path="tshark",
        interface="1",
        capture_filter="host 10.0.1.100 and tcp port 443",
    )

    assert command[:6] == ["tshark", "-i", "1", "-l", "-T", "fields"]
    assert "-f" in command
    assert "host 10.0.1.100 and tcp port 443" in command
    for field_name in TSHARK_FIELDS:
        assert field_name in command


def test_parse_tshark_interfaces_extracts_windows_friendly_names():
    interfaces = parse_tshark_interfaces(
        "\n".join(
            [
                r"1. \Device\NPF_{11111111-1111-1111-1111-111111111111} (Ethernet)",
                r"2. \Device\NPF_{22222222-2222-2222-2222-222222222222} (Wi-Fi)",
                "3. randpkt (Random packet generator)",
            ]
        )
    )

    assert [interface.index for interface in interfaces] == [1, 2, 3]
    assert [interface.name for interface in interfaces] == [
        "Ethernet",
        "Wi-Fi",
        "Random packet generator",
    ]
    assert interfaces[1].display_name.endswith("(Wi-Fi)")


def test_resolve_tshark_path_uses_windows_default_install(monkeypatch):
    monkeypatch.setattr(tshark_capture.platform, "system", lambda: "Windows")
    monkeypatch.setattr(tshark_capture.shutil, "which", lambda _path: None)
    monkeypatch.setattr(
        tshark_capture.Path,
        "exists",
        lambda self: str(self).replace("\\", "/") == "C:/Program Files/Wireshark/tshark.exe",
    )

    assert resolve_tshark_path("tshark").replace("\\", "/") == (
        "C:/Program Files/Wireshark/tshark.exe"
    )


def test_explicit_capture_interface_is_not_auto_resolved(monkeypatch):
    monkeypatch.setattr(
        tshark_capture,
        "_windows_default_route_interfaces",
        lambda: pytest.fail("explicit interfaces must not inspect routes"),
    )

    assert resolve_capture_interface("5", "tshark") == "5"


def test_auto_capture_interface_selects_windows_default_route(monkeypatch):
    monkeypatch.setattr(tshark_capture.platform, "system", lambda: "Windows")
    monkeypatch.setattr(tshark_capture, "_windows_default_route_interfaces", lambda: ["Wi-Fi"])
    monkeypatch.setattr(
        tshark_capture,
        "_list_tshark_interface_names",
        lambda _path: ["Bluetooth Network Connection", "Wi-Fi"],
    )

    assert resolve_capture_interface("auto", "tshark") == "Wi-Fi"


def test_auto_capture_interface_rejects_route_not_exposed_by_tshark(monkeypatch):
    monkeypatch.setattr(tshark_capture.platform, "system", lambda: "Windows")
    monkeypatch.setattr(tshark_capture, "_windows_default_route_interfaces", lambda: ["Wi-Fi"])
    monkeypatch.setattr(
        tshark_capture,
        "_list_tshark_interface_names",
        lambda _path: ["Ethernet"],
    )

    with pytest.raises(TSharkConfigurationError, match="none are available in TShark"):
        resolve_capture_interface("auto", "tshark")


def test_auto_configuration_validation_does_not_require_a_current_route(monkeypatch):
    agent = TSharkCaptureAgent("auto", "all", [], tshark_path="tshark")
    monkeypatch.setattr(agent, "_resolve_tshark_path", lambda: "tshark")
    monkeypatch.setattr(
        tshark_capture,
        "resolve_capture_interface",
        lambda *_args: pytest.fail("static validation must not require a live route"),
    )

    agent.validate_configuration()


@pytest.mark.asyncio
async def test_auto_capture_requests_restart_when_default_route_changes(monkeypatch):
    class IdleStdout:
        async def readline(self):
            await asyncio.sleep(1)
            return b""

    class RunningProcess:
        stdout = IdleStdout()

    agent = TSharkCaptureAgent("auto", "all", [])
    agent.active_interface = "Wi-Fi"
    agent._process = RunningProcess()
    agent._running = True
    monkeypatch.setattr(agent, "_resolve_tshark_path", lambda: "tshark")
    monkeypatch.setattr(tshark_capture, "resolve_capture_interface", lambda *_args: "Ethernet")

    iterator = agent.capture_packets(flush_interval=0.01, interface_check_interval=0)
    with pytest.raises(TSharkInterfaceChanged, match="Wi-Fi to Ethernet"):
        await asyncio.wait_for(iterator.__anext__(), timeout=0.2)


def test_fake_tshark_rows_feed_window_aggregator():
    now = time.time()
    rows = [
        _line(
            **{
                "frame.time_epoch": str(now),
                "ip.src": "203.0.113.10",
                "ip.dst": "10.0.1.100",
                "ip.proto": "6",
                "frame.len": "60",
                "ip.ttl": "64",
                "tcp.srcport": "51432",
                "tcp.dstport": "80",
                "tcp.flags": "0x0002",
                "tcp.window_size_value": "1024",
            }
        ),
        _line(
            **{
                "frame.time_epoch": str(now + 0.1),
                "ip.src": "198.51.100.53",
                "ip.dst": "10.0.1.100",
                "ip.proto": "17",
                "frame.len": "96",
                "ip.ttl": "128",
                "udp.srcport": "53000",
                "udp.dstport": "53",
                "udp.length": "76",
            }
        ),
    ]
    packets = [parse_tshark_line(row) for row in rows]
    packet_dicts = [packet.to_dict() for packet in packets if packet is not None]

    features = WindowAggregator().ingest(packet_dicts)
    feature_array = features["1s"].to_feature_array()

    assert len(feature_array) == 30
    assert features["1s"].packet_count == 2
    assert features["1s"].dns_ratio == 0.5


@pytest.mark.asyncio
async def test_continuous_traffic_flushes_before_batch_size():
    row = _line(
        **{
            "frame.time_epoch": str(time.time()),
            "ip.src": "203.0.113.10",
            "ip.dst": "10.0.1.100",
            "ip.proto": "6",
            "frame.len": "60",
            "tcp.srcport": "51432",
            "tcp.dstport": "443",
        }
    ).encode("utf-8")

    class ContinuousStdout:
        async def readline(self):
            await asyncio.sleep(0.02)
            return row

    class ContinuousProcess:
        stdout = ContinuousStdout()

    agent = TSharkCaptureAgent("1", "all", [], batch_size=100)
    agent._process = ContinuousProcess()
    agent._running = True
    iterator = agent.capture_packets(flush_interval=0.05)

    batch = await asyncio.wait_for(iterator.__anext__(), timeout=0.2)

    assert 2 <= len(batch) < 100
    agent._running = False
