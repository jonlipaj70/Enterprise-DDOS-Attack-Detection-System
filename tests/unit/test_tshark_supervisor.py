"""Tests for self-healing live capture supervision."""

import pytest

from src.api import server
from src.ingestion.tshark_capture import TSharkInterfaceChanged


@pytest.mark.asyncio
async def test_live_capture_restarts_after_automatic_interface_change(monkeypatch):
    captures = []

    class FakeCapture:
        def __init__(self, switch_interface: bool) -> None:
            self.switch_interface = switch_interface
            self.started = False
            self.stopped = False

        async def start(self) -> None:
            self.started = True

        async def capture_packets(self):
            if self.switch_interface:
                raise TSharkInterfaceChanged("Active capture interface changed from Wi-Fi to Ethernet")
            server.state.is_running = False
            if False:
                yield []

        async def stop(self) -> None:
            self.stopped = True

    def create_capture():
        capture = FakeCapture(switch_interface=not captures)
        captures.append(capture)
        return capture

    monkeypatch.setattr(server.state, "is_running", True)
    monkeypatch.setattr(server.state, "create_tshark_capture", create_capture)
    monkeypatch.setattr(server.state, "metrics", {"capture_restarts": 0})
    monkeypatch.setattr(server.state, "last_capture_error", "previous error")

    await server._run_tshark_detection_loop()

    assert len(captures) == 2
    assert all(capture.started and capture.stopped for capture in captures)
    assert server.state.metrics["capture_restarts"] == 1
    assert server.state.last_capture_error is None

