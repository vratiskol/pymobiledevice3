import pytest

from pymobiledevice3.bonjour import REMOTEPAIRING_SERVICE_NAME, REMOTED_SERVICE_NAME
from pymobiledevice3.cli import remote
from pymobiledevice3.exceptions import NoDeviceConnectedError
from pymobiledevice3.remote.common import ConnectionType
from pymobiledevice3.remote.remote_service_discovery import build_rsd_service_inventory


def test_build_rsd_service_inventory_classifies_firmware_backed_services():
    inventory = build_rsd_service_inventory({
        "Services": {
            "com.apple.coredevice.displayservice": {"Port": 1},
            "com.apple.coredevice.hid.universalhidservice": {"Port": 2},
            "com.apple.internal.dt.coredevice.untrusted.tunnelservice": {"Port": 3},
            "com.apple.mobile.lockdown.remote.trusted": {"Port": 4},
            "com.apple.remoted.compute-platform": {"Port": 5},
            "com.apple.remoted.identity": {"Port": 6},
            "com.apple.remoted.watchdog": {"Port": 7},
            "com.apple.RemoteServiceDiscovery": {"Port": 8},
        },
    })

    assert inventory["service_count"] == 8
    assert inventory["capabilities"]["coredevice"] is True
    assert inventory["capabilities"]["developer_tunnel"] is True
    assert inventory["capabilities"]["display"] is True
    assert inventory["capabilities"]["hid"] is True
    assert inventory["capabilities"]["lockdown_trusted"] is True
    assert inventory["capabilities"]["compute"] is True
    assert inventory["capabilities"]["identity"] is True
    assert inventory["capabilities"]["watchdog"] is True
    assert inventory["capabilities"]["remote_service_discovery"] is True
    assert inventory["categories"]["compute"] == ["com.apple.remoted.compute-platform"]


@pytest.mark.asyncio
async def test_browse_rsd_includes_service_inventory(monkeypatch):
    class FakeRsd:
        service = type("Service", (), {"address": ("example.invalid", 0)})()
        peer_info = {
            "Properties": {
                "UniqueDeviceID": "redacted",
                "ProductType": "iPhone",
                "OSVersion": "27.0",
            },
            "Services": {
                "com.apple.coredevice.displayservice": {"Port": 1},
                "com.apple.mobile.lockdown.remote.untrusted": {"Port": 2},
            },
        }

    async def get_rsds(timeout):
        return [FakeRsd()]

    monkeypatch.setattr(remote, "get_rsds", get_rsds)

    devices = await remote.browse_rsd(timeout=0.01)

    assert devices[0]["bonjour_service"] == REMOTED_SERVICE_NAME
    assert devices[0]["service_inventory"]["capabilities"]["display"] is True
    assert devices[0]["service_inventory"]["capabilities"]["lockdown_untrusted"] is True


@pytest.mark.asyncio
async def test_browse_remotepairing_includes_transport_inventory(monkeypatch):
    class FakeRemotePairing:
        hostname = "example.invalid"
        port = 1234
        remote_identifier = "redacted"

    async def get_remote_pairing_tunnel_services(timeout):
        return [FakeRemotePairing()]

    monkeypatch.setattr(remote, "get_remote_pairing_tunnel_services", get_remote_pairing_tunnel_services)

    devices = await remote.browse_remotepairing(timeout=0.01)

    assert devices[0]["bonjour_service"] == REMOTEPAIRING_SERVICE_NAME
    assert devices[0]["service_inventory"] == {
        "transport": "RemotePairing",
        "capabilities": {
            "coredevice_tunnel": True,
            "remote_pairing": True,
        },
    }


@pytest.mark.asyncio
async def test_start_tunnel_task_retries_empty_discovery(monkeypatch):
    service = object()
    discoveries = iter(([], [service]))
    tunnel_services_calls = 0
    tunnel_task_service = None

    async def get_tunnel_services(udid=None):
        nonlocal tunnel_services_calls
        tunnel_services_calls += 1
        return next(discoveries)

    async def tunnel_task(selected_service, **kwargs):
        nonlocal tunnel_task_service
        tunnel_task_service = selected_service

    monkeypatch.setattr(remote, "get_core_device_tunnel_services", get_tunnel_services)
    monkeypatch.setattr(remote, "tunnel_task", tunnel_task)

    await remote.start_tunnel_task(ConnectionType.USB, secrets=None)

    assert tunnel_services_calls == 2
    assert tunnel_task_service is service


@pytest.mark.asyncio
async def test_start_tunnel_task_raises_after_discovery_retries(monkeypatch):
    tunnel_services_calls = 0

    async def get_tunnel_services(udid=None):
        nonlocal tunnel_services_calls
        tunnel_services_calls += 1
        return []

    monkeypatch.setattr(remote, "get_core_device_tunnel_services", get_tunnel_services)

    with pytest.raises(NoDeviceConnectedError):
        await remote.start_tunnel_task(ConnectionType.USB, secrets=None)

    assert tunnel_services_calls == remote.TUNNEL_SERVICE_DISCOVERY_ATTEMPTS
