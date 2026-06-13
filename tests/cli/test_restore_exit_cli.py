import pytest
from typer.testing import CliRunner

from pymobiledevice3 import __main__
from pymobiledevice3.cli import restore
from pymobiledevice3.exceptions import IRecvNoDeviceConnectedError, NotTrustedError


class NoIRecvDevice:
    def __init__(self, *args, **kwargs):
        raise IRecvNoDeviceConnectedError("no recovery device")


class FakeMuxDevice:
    serial = "fake-sensitive-serial"
    connection_type = "USB"


def test_restore_exit_help_exposes_wait_options():
    result = CliRunner().invoke(__main__.app, ["restore", "exit", "--help"])

    assert result.exit_code == 0
    assert "--wait" in result.output
    assert "--timeout" in result.output
    assert "--poll-interval" in result.output
    assert "--json" in result.output


@pytest.mark.asyncio
async def test_wait_for_restore_exit_state_times_out_without_device(monkeypatch):
    async def fake_list_devices():
        return []

    monkeypatch.setattr(restore, "IRecv", NoIRecvDevice)
    monkeypatch.setattr(restore.usbmux, "list_devices", fake_list_devices)

    state = await restore.wait_for_restore_exit_state(timeout=0.01, poll_interval=0.01)

    assert state["state"] == "not_seen_timeout"
    assert state["last_probe"] == {"state": "not_seen", "usb_device_count": 0}


@pytest.mark.asyncio
async def test_detect_restore_exit_state_reports_restored_without_identifiers(monkeypatch):
    async def fake_list_devices():
        return [FakeMuxDevice()]

    async def fake_create_using_usbmux(**kwargs):
        raise NotTrustedError()

    class FakeRestoredService:
        async def start(self):
            return None

        async def send_recv_plist(self, request):
            assert request == {"Request": "QueryType"}
            return {"Type": "com.apple.mobile.restored", "RestoreProtocolVersion": 15}

        async def close(self):
            return None

    async def fake_create_restored_service(*args, **kwargs):
        return FakeRestoredService()

    monkeypatch.setattr(restore, "IRecv", NoIRecvDevice)
    monkeypatch.setattr(restore.usbmux, "list_devices", fake_list_devices)
    monkeypatch.setattr(restore, "create_using_usbmux", fake_create_using_usbmux)
    monkeypatch.setattr(restore.ServiceConnection, "create_using_usbmux", fake_create_restored_service)

    state = await restore.detect_restore_exit_state()

    assert state == {"state": "restored", "restore_protocol_version": 15}
    assert "fake-sensitive-serial" not in repr(state)


@pytest.mark.asyncio
async def test_detect_restore_exit_state_reports_normal_when_lockdown_enrichment_fails(monkeypatch):
    async def fake_list_devices():
        return [FakeMuxDevice()]

    async def fake_create_using_usbmux(**kwargs):
        raise NotTrustedError()

    class FakeLockdownService:
        async def start(self):
            return None

        async def send_recv_plist(self, request):
            assert request == {"Request": "QueryType"}
            return {"Type": "com.apple.mobile.lockdown"}

        async def close(self):
            return None

    async def fake_create_lockdown_service(*args, **kwargs):
        return FakeLockdownService()

    monkeypatch.setattr(restore, "IRecv", NoIRecvDevice)
    monkeypatch.setattr(restore.usbmux, "list_devices", fake_list_devices)
    monkeypatch.setattr(restore, "create_using_usbmux", fake_create_using_usbmux)
    monkeypatch.setattr(restore.ServiceConnection, "create_using_usbmux", fake_create_lockdown_service)

    state = await restore.detect_restore_exit_state()

    assert state == {
        "state": "normal",
        "lockdown_available": False,
        "reason": "lockdown_error:NotTrustedError",
    }
    assert "fake-sensitive-serial" not in repr(state)
