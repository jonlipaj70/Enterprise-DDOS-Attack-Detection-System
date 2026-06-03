"""
Live TShark packet capture integration.

Converts line-buffered Wireshark/TShark field output into the RawPacket shape
consumed by the existing feature pipeline.
"""

from __future__ import annotations

import asyncio
import platform
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import AsyncIterator, Iterable, Sequence

from src.config.logging_config import get_logger
from src.ingestion.packet_capture import Protocol, RawPacket

logger = get_logger(__name__)


TSHARK_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "frame.len",
    "ip.ttl",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "tcp.seq",
    "tcp.ack",
    "tcp.window_size_value",
    "tcp.len",
    "udp.srcport",
    "udp.dstport",
    "udp.length",
    "icmp.type",
    "icmp.code",
    "ip.frag_offset",
    "ipv6.src",
    "ipv6.dst",
    "ipv6.nxt",
    "ipv6.hlim",
]

_UDP_SERVICE_PORTS = {53, 123, 161, 500, 514, 1900}
_ALL_TRAFFIC_TARGETS = {"", "*", "all", "any", "0.0.0.0/0", "::/0"}
_ALL_IP_TRAFFIC_FILTER = "ip or ip6"
_AUTO_INTERFACES = {"auto", "default"}


class TSharkConfigurationError(RuntimeError):
    """Raised when live TShark capture cannot be configured safely."""


class TSharkInterfaceChanged(RuntimeError):
    """Raised when automatic capture should move to a different active adapter."""


@dataclass(frozen=True)
class TSharkInterface:
    """One capture interface reported by ``tshark -D``."""

    index: int
    name: str
    display_name: str

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


def parse_ports(value: str | Iterable[int]) -> list[int]:
    """Parse a comma-separated port list and discard invalid/empty values."""
    if isinstance(value, str):
        raw_values: Iterable[str | int] = value.split(",")
    else:
        raw_values = value

    ports: list[int] = []
    for raw in raw_values:
        text = str(raw).strip()
        if not text:
            continue
        port = int(text)
        if not 0 < port <= 65535:
            raise ValueError(f"invalid port: {port}")
        ports.append(port)
    return ports


def build_capture_filter(target_host: str, target_ports: Sequence[int]) -> str:
    """
    Build a conservative libpcap capture filter.

    When target_host is empty/all/any, capture all local IP traffic on the
    selected interface. Otherwise, TCP is included for every configured port,
    and UDP is included for well-known UDP services when explicitly configured.
    """
    target_host = target_host.strip()
    if target_host.lower() in _ALL_TRAFFIC_TARGETS:
        return _ALL_IP_TRAFFIC_FILTER

    port_terms: list[str] = []
    for port in target_ports:
        port_terms.append(f"tcp port {port}")
        if port in _UDP_SERVICE_PORTS:
            port_terms.append(f"udp port {port}")

    if not port_terms:
        return f"host {target_host}"

    return f"host {target_host} and ({' or '.join(port_terms)})"


def build_tshark_command(
    tshark_path: str,
    interface: str,
    capture_filter: str,
) -> list[str]:
    """Build a TShark command that emits tab-separated packet fields."""
    if not interface.strip():
        raise TSharkConfigurationError("CAPTURE_INTERFACE is required for TShark capture")

    command = [
        tshark_path,
        "-i",
        interface,
        "-l",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
    ]

    if capture_filter:
        command.extend(["-f", capture_filter])

    for field_name in TSHARK_FIELDS:
        command.extend(["-e", field_name])

    return command


def resolve_capture_interface(configured_interface: str, tshark_path: str) -> str:
    """
    Resolve an automatic capture target to the adapter carrying default-route traffic.

    Live capture is currently deployed on Windows. Interface numbers from ``tshark -D``
    change when adapters are installed or removed, so ``auto`` selects the stable
    Windows interface alias associated with the active default route.
    """
    interface = configured_interface.strip()
    if interface.lower() not in _AUTO_INTERFACES:
        return interface

    if platform.system().lower() != "windows":
        raise TSharkConfigurationError(
            "CAPTURE_INTERFACE=auto currently requires Windows; set an explicit TShark interface"
        )

    default_route_interfaces = _windows_default_route_interfaces()
    if not default_route_interfaces:
        raise TSharkConfigurationError(
            "CAPTURE_INTERFACE=auto could not find an active Windows default-route adapter"
        )

    tshark_interfaces = _list_tshark_interface_names(tshark_path)
    available = {name.casefold(): name for name in tshark_interfaces}
    for interface_alias in default_route_interfaces:
        selected = available.get(interface_alias.casefold())
        if selected:
            return selected

    raise TSharkConfigurationError(
        "CAPTURE_INTERFACE=auto found default-route adapter(s) "
        f"{', '.join(default_route_interfaces)}, but none are available in TShark"
    )


def _windows_default_route_interfaces() -> list[str]:
    """Return active Windows interface aliases ordered by default route priority."""
    command = (
        "$routes = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
        "-ErrorAction SilentlyContinue | "
        "Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.State -ne 'Invalid' } | "
        "Sort-Object RouteMetric; "
        "$routes | Select-Object -ExpandProperty InterfaceAlias -Unique"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TSharkConfigurationError(
            f"CAPTURE_INTERFACE=auto failed to inspect Windows routes: {error}"
        ) from error

    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip() or "unknown PowerShell error"
        raise TSharkConfigurationError(
            f"CAPTURE_INTERFACE=auto failed to inspect Windows routes: {error}"
        )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def resolve_tshark_path(configured_path: str) -> str:
    """Resolve TShark from explicit path, PATH, or common Windows install locations."""
    configured = configured_path.strip() or "tshark"
    has_path_separator = "/" in configured or "\\" in configured
    if has_path_separator or Path(configured).is_absolute():
        if Path(configured).exists():
            return configured
        raise TSharkConfigurationError(f"TShark executable not found: {configured}")

    resolved = shutil.which(configured)
    if resolved:
        return resolved

    if platform.system().lower() == "windows":
        for candidate in (
            Path("C:/Program Files/Wireshark/tshark.exe"),
            Path("C:/Program Files (x86)/Wireshark/tshark.exe"),
        ):
            if candidate.exists():
                return str(candidate)

    raise TSharkConfigurationError(
        f"TShark executable '{configured}' was not found. Install Wireshark with Npcap "
        "or set TSHARK_PATH to the full tshark.exe path."
    )


def parse_tshark_interfaces(output: str) -> list[TSharkInterface]:
    """Parse ``tshark -D`` output into stable interface metadata."""
    interfaces: list[TSharkInterface] = []
    for line in output.splitlines():
        index_text, separator, description = line.partition(". ")
        if not separator:
            continue
        try:
            index = int(index_text.strip())
        except ValueError:
            continue

        display_name = description.strip()
        if not display_name:
            continue

        name = display_name
        if display_name.endswith(")") and " (" in display_name:
            name = display_name.rsplit(" (", 1)[1][:-1]

        interfaces.append(
            TSharkInterface(index=index, name=name.strip(), display_name=display_name)
        )
    return interfaces


def list_tshark_interfaces(tshark_path: str) -> list[TSharkInterface]:
    """Return capture interfaces reported by TShark."""
    try:
        result = subprocess.run(
            [tshark_path, "-D"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TSharkConfigurationError(f"Unable to list TShark interfaces: {error}") from error

    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip() or "unknown TShark error"
        raise TSharkConfigurationError(f"Unable to list TShark interfaces: {error}")

    return parse_tshark_interfaces(result.stdout)


def _list_tshark_interface_names(tshark_path: str) -> list[str]:
    """Return user-facing interface aliases reported by TShark."""
    return [interface.name for interface in list_tshark_interfaces(tshark_path)]


def parse_tshark_line(line: str) -> RawPacket | None:
    """Parse one TShark fields line into a RawPacket, skipping non-IP rows."""
    stripped = line.rstrip("\r\n")
    values = stripped.split("\t")
    if len(values) == 1 and "\\" in stripped:
        values = stripped.split("\\")
    if len(values) < len(TSHARK_FIELDS):
        values.extend([""] * (len(TSHARK_FIELDS) - len(values)))

    row = dict(zip(TSHARK_FIELDS, values, strict=False))
    src_ip = row["ip.src"].strip() or row["ipv6.src"].strip()
    dst_ip = row["ip.dst"].strip() or row["ipv6.dst"].strip()
    if not src_ip or not dst_ip:
        return None

    protocol = _parse_int(row["ip.proto"], default=0) or _parse_int(row["ipv6.nxt"], default=0)
    packet_size = _parse_int(row["frame.len"], default=0)
    ttl = _parse_int(row["ip.ttl"], default=0) or _parse_int(row["ipv6.hlim"], default=0)

    tcp_src_port = _parse_int(row["tcp.srcport"], default=0)
    tcp_dst_port = _parse_int(row["tcp.dstport"], default=0)
    udp_src_port = _parse_int(row["udp.srcport"], default=0)
    udp_dst_port = _parse_int(row["udp.dstport"], default=0)

    if protocol == int(Protocol.TCP):
        src_port = tcp_src_port
        dst_port = tcp_dst_port
        flags = _parse_int(row["tcp.flags"], default=0)
        payload_size = _parse_int(row["tcp.len"], default=0)
        sequence_number = _parse_int(row["tcp.seq"], default=0)
        ack_number = _parse_int(row["tcp.ack"], default=0)
        window_size = _parse_int(row["tcp.window_size_value"], default=65535)
    elif protocol == int(Protocol.UDP):
        src_port = udp_src_port
        dst_port = udp_dst_port
        flags = 0
        udp_length = _parse_int(row["udp.length"], default=0)
        payload_size = max(0, udp_length - 8) if udp_length else 0
        sequence_number = 0
        ack_number = 0
        window_size = 0
    elif protocol == int(Protocol.ICMP):
        src_port = 0
        dst_port = 0
        flags = 0
        payload_size = max(0, packet_size - 28) if packet_size else 0
        sequence_number = 0
        ack_number = 0
        window_size = 0
    else:
        src_port = tcp_src_port or udp_src_port
        dst_port = tcp_dst_port or udp_dst_port
        flags = _parse_int(row["tcp.flags"], default=0)
        payload_size = max(0, packet_size - 40) if packet_size else 0
        sequence_number = _parse_int(row["tcp.seq"], default=0)
        ack_number = _parse_int(row["tcp.ack"], default=0)
        window_size = _parse_int(row["tcp.window_size_value"], default=0)

    if src_port == 53 or dst_port == 53:
        protocol = int(Protocol.DNS)

    return RawPacket(
        timestamp=_parse_float(row["frame.time_epoch"], default=time.time()),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packet_size=packet_size,
        ttl=ttl,
        flags=flags,
        payload_size=payload_size,
        fragment_offset=_parse_int(row["ip.frag_offset"], default=0),
        sequence_number=sequence_number,
        ack_number=ack_number,
        window_size=window_size,
    )


class TSharkCaptureAgent:
    """Async live capture wrapper around the local TShark executable."""

    def __init__(
        self,
        interface: str,
        target_host: str,
        target_ports: Sequence[int],
        tshark_path: str = "tshark",
        batch_size: int = 200,
    ) -> None:
        self.interface = interface
        self.target_host = target_host
        self.target_ports = list(target_ports)
        self.tshark_path = tshark_path
        self.batch_size = batch_size
        self.capture_filter = build_capture_filter(target_host, self.target_ports)
        self.active_interface: str | None = None
        self._process: asyncio.subprocess.Process | None = None
        self._running = False
        self._packet_count = 0
        self._start_time = 0.0

    def validate_configuration(self) -> None:
        """Validate static configuration without requiring a live network route."""
        if self.batch_size <= 0:
            raise TSharkConfigurationError("CAPTURE_BATCH_SIZE must be greater than 0")
        resolved_tshark = self._resolve_tshark_path()
        build_tshark_command(resolved_tshark, self.interface, self.capture_filter)

    async def start(self) -> None:
        """Start the TShark subprocess."""
        self.validate_configuration()
        resolved_tshark = self._resolve_tshark_path()
        self.active_interface = resolve_capture_interface(self.interface, resolved_tshark)
        command = build_tshark_command(resolved_tshark, self.active_interface, self.capture_filter)

        self._process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        self._running = True
        self._start_time = time.time()
        logger.info(
            "tshark_capture_started",
            configured_interface=self.interface,
            active_interface=self.active_interface,
            capture_filter=self.capture_filter,
            batch_size=self.batch_size,
        )

    async def stop(self) -> None:
        """Stop the TShark subprocess."""
        self._running = False
        process = self._process
        self._process = None
        if process and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()

        elapsed = time.time() - self._start_time if self._start_time else 0
        logger.info(
            "tshark_capture_stopped",
            packets_captured=self._packet_count,
            elapsed_seconds=round(elapsed, 2),
        )

    async def capture_packets(
        self,
        flush_interval: float = 0.25,
        interface_check_interval: float = 5.0,
    ) -> AsyncIterator[list[RawPacket]]:
        """Yield parsed live packet batches from TShark output."""
        if self._process is None or self._process.stdout is None:
            await self.start()

        assert self._process is not None
        assert self._process.stdout is not None

        batch: list[RawPacket] = []
        batch_started_at = time.monotonic()
        next_interface_check = time.monotonic() + max(0.0, interface_check_interval)
        while self._running:
            if (
                self.interface.strip().lower() in _AUTO_INTERFACES
                and time.monotonic() >= next_interface_check
            ):
                await self._raise_if_interface_changed()
                next_interface_check = time.monotonic() + max(0.0, interface_check_interval)

            try:
                raw_line = await asyncio.wait_for(
                    self._process.stdout.readline(),
                    timeout=flush_interval,
                )
            except asyncio.TimeoutError:
                if batch:
                    yield batch
                    batch = []
                batch_started_at = time.monotonic()
                continue

            if not raw_line:
                if batch:
                    yield batch
                return_code = await self._process.wait()
                raise RuntimeError(f"TShark exited unexpectedly with code {return_code}")

            packet = parse_tshark_line(raw_line.decode("utf-8", errors="replace"))
            if packet is None:
                continue

            if not batch:
                batch_started_at = time.monotonic()
            batch.append(packet)
            self._packet_count += 1
            if len(batch) >= self.batch_size or time.monotonic() - batch_started_at >= flush_interval:
                yield batch
                batch = []
                batch_started_at = time.monotonic()

    @property
    def stats(self) -> dict:
        elapsed = time.time() - self._start_time if self._start_time else 0
        return {
            "packets_captured": self._packet_count,
            "elapsed_seconds": round(elapsed, 2),
            "avg_pps": round(self._packet_count / max(elapsed, 1), 2),
            "running": self._running,
            "configured_interface": self.interface,
            "active_interface": self.active_interface,
            "capture_filter": self.capture_filter,
        }

    async def _raise_if_interface_changed(self) -> None:
        """Interrupt capture when automatic adapter resolution has moved."""
        if self.active_interface is None:
            return
        resolved_tshark = self._resolve_tshark_path()
        selected_interface = await asyncio.to_thread(
            resolve_capture_interface,
            self.interface,
            resolved_tshark,
        )
        if selected_interface.casefold() != self.active_interface.casefold():
            raise TSharkInterfaceChanged(
                f"Active capture interface changed from {self.active_interface} "
                f"to {selected_interface}"
            )

    def _resolve_tshark_path(self) -> str:
        return resolve_tshark_path(self.tshark_path)


def _parse_int(value: str, default: int = 0) -> int:
    text = value.strip()
    if not text:
        return default
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(float(text))
        except ValueError:
            return default


def _parse_float(value: str, default: float = 0.0) -> float:
    text = value.strip()
    if not text:
        return default
    try:
        return float(text)
    except ValueError:
        return default
