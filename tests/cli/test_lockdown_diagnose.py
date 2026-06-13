import plistlib

import pytest

from pymobiledevice3.cli import lockdown as lockdown_module


class _FakeService:
    async def close(self) -> None:
        pass


class _FakeServiceConnection:
    @staticmethod
    async def create_using_tcp(host: str, port: int):
        return _FakeService()


def test_pair_record_diagnostic_does_not_expose_secret_values() -> None:
    pair_record = {
        "HostID": "host-id",
        "HostPrivateKey": b"private-key",
        "WiFiMACAddress": "00:11:22:33:44:55",
        "EscrowBag": b"escrow",
    }

    diagnostic = lockdown_module._pair_record_diagnostic("local", pair_record)

    assert diagnostic == {
        "found": True,
        "source": "local",
        "keys": ["EscrowBag", "HostID", "HostPrivateKey", "WiFiMACAddress"],
        "has_escrow_bag": True,
        "has_host_private_key": True,
        "has_wifi_mac_address": True,
    }


@pytest.mark.asyncio
async def test_diagnose_tcp_lockdown_reports_udid_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lockdown_module, "ServiceConnection", _FakeServiceConnection)

    diagnostic = await lockdown_module.diagnose_tcp_lockdown("192.0.2.1")

    assert diagnostic["transport"] == "tcp"
    assert diagnostic["tcp_connect"] == {"ok": True}
    assert diagnostic["pair_record"] == {
        "found": False,
        "source": None,
        "required": True,
        "error": "--udid is required",
    }
    assert diagnostic["query_type"] is None


@pytest.mark.asyncio
async def test_diagnose_tcp_lockdown_reports_pair_validation(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    captured_client_kwargs = {}
    pair_record = {"HostID": "host-id", "SystemBUID": "system-buid", "HostPrivateKey": b"private-key"}

    async def fake_find_pair_record(*args, **kwargs):
        return "local", pair_record

    class FakeTcpLockdownClient:
        def __init__(self, service, **kwargs) -> None:
            captured_client_kwargs.update(kwargs)

        async def query_type(self) -> str:
            return "com.apple.mobile.lockdown"

        async def get_value(self) -> dict:
            return {"DeviceClass": "iPhone", "ProductType": "iPhone", "ProductVersion": "1.0"}

        async def validate_pairing(self) -> bool:
            return True

        async def close(self) -> None:
            pass

    monkeypatch.setattr(lockdown_module, "_find_pair_record", fake_find_pair_record)
    monkeypatch.setattr(lockdown_module, "ServiceConnection", _FakeServiceConnection)
    monkeypatch.setattr(lockdown_module, "TcpLockdownClient", FakeTcpLockdownClient)

    diagnostic = await lockdown_module.diagnose_tcp_lockdown(
        "192.0.2.1", udid="device-udid", pairing_records_cache_folder=tmp_path
    )

    assert captured_client_kwargs["hostname"] == "192.0.2.1"
    assert captured_client_kwargs["identifier"] == "device-udid"
    assert captured_client_kwargs["pair_record"] == pair_record
    assert diagnostic["query_type"] == {"ok": True, "type": "com.apple.mobile.lockdown"}
    assert diagnostic["device_info"] == {
        "ok": True,
        "device_class": "iPhone",
        "product_type": "iPhone",
        "product_version": "1.0",
    }
    assert diagnostic["pair_validation"] == {"ok": True}


@pytest.mark.asyncio
async def test_diagnose_tcp_lockdown_uses_pair_record_file(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    captured_client_kwargs = {}
    pair_record = {"HostID": "host-id", "SystemBUID": "system-buid", "HostPrivateKey": b"private-key"}
    pair_record_file = tmp_path / "pair-record.plist"
    pair_record_file.write_bytes(plistlib.dumps(pair_record))

    async def fake_find_pair_record(*args, **kwargs):
        pytest.fail("_find_pair_record should not be used with an explicit pair record file")

    class FakeTcpLockdownClient:
        def __init__(self, service, **kwargs) -> None:
            captured_client_kwargs.update(kwargs)

        async def query_type(self) -> str:
            return "com.apple.mobile.lockdown"

        async def get_value(self) -> dict:
            return {"DeviceClass": "iPhone", "ProductType": "iPhone", "ProductVersion": "1.0"}

        async def validate_pairing(self) -> bool:
            return True

        async def close(self) -> None:
            pass

    monkeypatch.setattr(lockdown_module, "_find_pair_record", fake_find_pair_record)
    monkeypatch.setattr(lockdown_module, "ServiceConnection", _FakeServiceConnection)
    monkeypatch.setattr(lockdown_module, "TcpLockdownClient", FakeTcpLockdownClient)

    diagnostic = await lockdown_module.diagnose_tcp_lockdown("192.0.2.1", pair_record_file=pair_record_file)

    assert captured_client_kwargs["hostname"] == "192.0.2.1"
    assert captured_client_kwargs["identifier"] is None
    assert captured_client_kwargs["pair_record"] == pair_record
    assert diagnostic["pair_record"] == {
        "found": True,
        "source": "file",
        "keys": ["HostID", "HostPrivateKey", "SystemBUID"],
        "has_escrow_bag": False,
        "has_host_private_key": True,
        "has_wifi_mac_address": False,
    }
    assert diagnostic["pair_validation"] == {"ok": True}


@pytest.mark.asyncio
async def test_diagnose_tcp_lockdown_reports_pair_record_file_error(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    pair_record_file = tmp_path / "pair-record.plist"
    pair_record_file.write_bytes(b"not a plist")

    monkeypatch.setattr(lockdown_module, "ServiceConnection", _FakeServiceConnection)

    diagnostic = await lockdown_module.diagnose_tcp_lockdown("192.0.2.1", pair_record_file=pair_record_file)

    assert diagnostic["tcp_connect"] == {"ok": True}
    assert diagnostic["pair_record"]["source"] == "file"
    assert diagnostic["pair_record"]["ok"] is False
    assert diagnostic["pair_record"]["error_type"] == "UsageError"
    assert diagnostic["query_type"] is None
