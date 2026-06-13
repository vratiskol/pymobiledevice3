import plistlib

import pytest
from click import UsageError

from pymobiledevice3.cli import cli_common
from pymobiledevice3.lockdown import DEFAULT_LABEL, SERVICE_PORT, TcpLockdownClient


class _FakeService:
    async def close(self) -> None:
        pass


def test_tcp_lockdown_client_preserves_explicit_identifier() -> None:
    client = TcpLockdownClient(
        _FakeService(),
        host_id="host-id",
        hostname="192.0.2.1",
        identifier="device-udid",
        label=DEFAULT_LABEL,
    )

    assert client.hostname == "192.0.2.1"
    assert client.identifier == "device-udid"


def test_tcp_lockdown_client_uses_hostname_as_default_identifier() -> None:
    client = TcpLockdownClient(
        _FakeService(),
        host_id="host-id",
        hostname="192.0.2.1",
        label=DEFAULT_LABEL,
    )

    assert client.hostname == "192.0.2.1"
    assert client.identifier == "192.0.2.1"


def test_service_provider_dependency_uses_explicit_tcp_host(monkeypatch: pytest.MonkeyPatch) -> None:
    marker = object()
    captured = {}

    async def fake_create_using_tcp(**kwargs):
        captured.update(kwargs)
        return marker

    monkeypatch.setattr(cli_common, "create_using_tcp", fake_create_using_tcp)

    result = cli_common.any_service_provider_dependency(host="192.0.2.1", port=12345, udid="device-udid")

    assert result is marker
    assert captured == {
        "hostname": "192.0.2.1",
        "port": 12345,
        "identifier": "device-udid",
        "autopair": False,
    }


def test_no_autopair_dependency_uses_explicit_tcp_host(monkeypatch: pytest.MonkeyPatch) -> None:
    marker = object()
    captured = {}

    async def fake_create_using_tcp(**kwargs):
        captured.update(kwargs)
        return marker

    monkeypatch.setattr(cli_common, "create_using_tcp", fake_create_using_tcp)

    result = cli_common.no_autopair_service_provider_dependency(host="192.0.2.1", port=SERVICE_PORT, udid="device-udid")

    assert result is marker
    assert captured == {
        "hostname": "192.0.2.1",
        "port": SERVICE_PORT,
        "identifier": "device-udid",
        "autopair": False,
    }


def test_service_provider_dependency_uses_explicit_pair_record_file(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    marker = object()
    captured = {}
    pair_record = {"HostID": "host-id", "SystemBUID": "system-buid"}
    pair_record_file = tmp_path / "pair-record.plist"
    pair_record_file.write_bytes(plistlib.dumps(pair_record))

    async def fake_create_using_tcp(**kwargs):
        captured.update(kwargs)
        return marker

    monkeypatch.setattr(cli_common, "create_using_tcp", fake_create_using_tcp)

    result = cli_common.any_service_provider_dependency(host="192.0.2.1", pair_record_file=pair_record_file)

    assert result is marker
    assert captured == {
        "hostname": "192.0.2.1",
        "port": SERVICE_PORT,
        "identifier": None,
        "autopair": False,
        "pair_record": pair_record,
    }


def test_no_autopair_dependency_uses_explicit_pair_record_file(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    marker = object()
    captured = {}
    pair_record = {"HostID": "host-id", "SystemBUID": "system-buid"}
    pair_record_file = tmp_path / "pair-record.plist"
    pair_record_file.write_bytes(plistlib.dumps(pair_record))

    async def fake_create_using_tcp(**kwargs):
        captured.update(kwargs)
        return marker

    monkeypatch.setattr(cli_common, "create_using_tcp", fake_create_using_tcp)

    result = cli_common.no_autopair_service_provider_dependency(host="192.0.2.1", pair_record_file=pair_record_file)

    assert result is marker
    assert captured == {
        "hostname": "192.0.2.1",
        "port": SERVICE_PORT,
        "identifier": None,
        "autopair": False,
        "pair_record": pair_record,
    }


def test_explicit_tcp_host_requires_udid() -> None:
    with pytest.raises(UsageError, match="--host requires --udid or --pair-record"):
        cli_common.any_service_provider_dependency(host="192.0.2.1")


def test_pair_record_file_requires_host(tmp_path) -> None:
    with pytest.raises(UsageError, match="--pair-record requires --host"):
        cli_common.any_service_provider_dependency(pair_record_file=tmp_path / "pair-record.plist")


def test_pair_record_file_rejects_missing_file(tmp_path) -> None:
    with pytest.raises(UsageError, match="Pair record file not found"):
        cli_common.any_service_provider_dependency(host="192.0.2.1", pair_record_file=tmp_path / "missing.plist")


def test_pair_record_file_must_be_plist_dictionary(tmp_path) -> None:
    pair_record_file = tmp_path / "pair-record.plist"
    pair_record_file.write_bytes(plistlib.dumps(["not", "a", "dict"]))

    with pytest.raises(UsageError, match="plist dictionary"):
        cli_common.any_service_provider_dependency(host="192.0.2.1", pair_record_file=pair_record_file)


def test_explicit_tcp_port_requires_host() -> None:
    with pytest.raises(UsageError, match="--port requires --host"):
        cli_common.any_service_provider_dependency(port=12345)


def test_explicit_tcp_host_is_mutually_exclusive_with_mobdev2() -> None:
    with pytest.raises(UsageError, match="--host is mutually exclusive with --mobdev2"):
        cli_common.any_service_provider_dependency(host="192.0.2.1", udid="device-udid", mobdev2=True)
