import pytest
from typer.testing import CliRunner

from pymobiledevice3.cli.developer import core_device
from pymobiledevice3.remote.core_device.app_service import AppServiceService
from pymobiledevice3.remote.core_device.device_info import DeviceInfoService
from pymobiledevice3.remote.core_device.display_service import DisplayService
from pymobiledevice3.remote.core_device.file_service import FileServiceService
from pymobiledevice3.remote.core_device.hid_service import IndigoHIDService, UniversalHIDServiceService


def service(port: int, uses_remote_xpc: bool = True) -> dict:
    return {
        "Port": port,
        "Properties": {
            "UsesRemoteXPC": uses_remote_xpc,
        },
    }


class FakeRemoteService:
    def __init__(self) -> None:
        self.connected = False
        self.closed = False

    async def connect(self) -> None:
        self.connected = True

    async def close(self) -> None:
        self.closed = True


class FakeRemoteXPCConnection:
    def __init__(self, rsd: "FakeRSD", name: str) -> None:
        self.rsd = rsd
        self.name = name
        self.closed = False

    async def connect(self) -> None:
        if self.name in self.rsd.failing_services:
            raise RuntimeError("connect failed")

    async def close(self) -> None:
        self.closed = True

    async def send_receive_request(self, request: dict) -> dict:
        if request.get("payload", {}).get("connectedServices") == {}:
            return self.rsd.connected_hid_services

        feature = request["CoreDevice.featureIdentifier"]
        if feature in self.rsd.failing_features:
            raise RuntimeError("feature failed")
        return {"CoreDevice.output": self.rsd.feature_responses[feature]}


class FakeRSD:
    def __init__(
        self,
        services: dict,
        failing_services: set[str] | None = None,
        failing_features: set[str] | None = None,
    ) -> None:
        self.name = "test-tunnel"
        self.service = type("FakeConnection", (), {"address": ("fd00::1", 58783)})()
        self.lockdown = object()
        self.all_values = {}
        self.peer_info = {
            "Properties": {
                "UniqueDeviceID": "test-udid",
                "ProductType": "iPhone99,9",
                "OSVersion": "27.0",
                "BuildVersion": "24A000",
                "UniqueChipID": 123,
            },
            "Services": services,
        }
        self.failing_services = failing_services or set()
        self.failing_features = failing_features or set()
        self.connected_hid_services = {
            "payload": {
                "connectedServices": [
                    {"_ServiceID": 257, "Name": "mainTouchscreen"},
                    {"_ServiceID": 1281, "Name": "touchscreenGesture"},
                ]
            }
        }
        self.feature_responses = {
            "com.apple.coredevice.feature.getdisplayinfo": {"displays": [{"displayID": 1}]},
            "com.apple.coredevice.feature.getlockstate": {"lockState": "unlocked"},
            "com.apple.coredevice.feature.getmediasupportinfo": {"supportedMediaStreamTypes": ["video", "audio"]},
            "com.apple.coredevice.feature.getmediastreamserverstatus": {
                "mediaStreamServerRunning": True,
                "activeSessions": [],
            },
        }

    async def start_service(self, name: str) -> FakeRemoteService:
        if name in self.failing_services:
            raise RuntimeError("probe failed")
        return FakeRemoteService()

    def start_remote_service(self, name: str) -> FakeRemoteXPCConnection:
        return FakeRemoteXPCConnection(self, name)


@pytest.mark.asyncio
async def test_core_device_diagnose_reports_missing_services_without_probe() -> None:
    rsd = FakeRSD({
        DeviceInfoService.SERVICE_NAME: service(61000),
        AppServiceService.SERVICE_NAME: service(61001),
        FileServiceService.CTRL_SERVICE_NAME: service(61002),
    })

    payload = await core_device.build_core_device_diagnose_payload(rsd, probe=False, inspect=False)

    assert payload["rsd"]["peer"]["UniqueDeviceID"] == "test-udid"
    assert payload["summary"]["probe"] is False
    assert payload["summary"]["known_core_device_services_advertised"] == 3
    assert payload["summary"]["known_core_device_services_connectable"] is None
    assert payload["capabilities"]["core"]["ready"] is True
    assert payload["capabilities"]["file_service"]["ready"] is False
    assert payload["capabilities"]["remote_control"]["ready"] is False

    services = {service["name"]: service for service in payload["services"]}
    assert services[DeviceInfoService.SERVICE_NAME]["advertised"] is True
    assert services[DeviceInfoService.SERVICE_NAME]["connectable"] is None
    assert services[DisplayService.SERVICE_NAME]["advertised"] is False


@pytest.mark.asyncio
async def test_core_device_diagnose_probes_advertised_services() -> None:
    rsd = FakeRSD(
        {
            DeviceInfoService.SERVICE_NAME: service(61000),
            DisplayService.SERVICE_NAME: service(61001),
            IndigoHIDService.SERVICE_NAME: service(61002),
        },
        failing_services={DisplayService.SERVICE_NAME},
    )

    payload = await core_device.build_core_device_diagnose_payload(rsd, probe=True, inspect=False, timeout=0.1)

    assert payload["summary"]["known_core_device_services_connectable"] == 2
    assert payload["summary"]["known_core_device_service_probe_failures"] == 1
    assert payload["summary"]["ok"] is False

    services = {service["name"]: service for service in payload["services"]}
    assert services[DeviceInfoService.SERVICE_NAME]["connectable"] is True
    assert services[DisplayService.SERVICE_NAME]["connectable"] is False
    assert services[DisplayService.SERVICE_NAME]["error"]["type"] == "RuntimeError"


@pytest.mark.asyncio
async def test_core_device_diagnose_inspects_read_only_remote_control_state() -> None:
    rsd = FakeRSD({
        DeviceInfoService.SERVICE_NAME: service(61000),
        DisplayService.SERVICE_NAME: service(61001),
        UniversalHIDServiceService.SERVICE_NAME: service(61002),
    })

    payload = await core_device.build_core_device_diagnose_payload(rsd, probe=False, inspect=True, timeout=0.1)

    assert payload["summary"]["inspect"] is True
    inspections = payload["inspections"]
    assert inspections["device_info"]["display_info"]["ok"] is True
    assert inspections["device_info"]["display_info"]["value"]["displays"][0]["displayID"] == 1
    assert inspections["device_info"]["lockstate"]["value"]["lockState"] == "unlocked"
    assert inspections["display"]["media_support_info"]["value"]["supportedMediaStreamTypes"] == ["video", "audio"]
    assert inspections["display"]["media_stream_server_status"]["value"]["mediaStreamServerRunning"] is True
    assert (
        inspections["universal_hid"]["connected_services"]["value"]["payload"]["connectedServices"][0]["_ServiceID"]
        == 257
    )
    assert inspections["universal_hid"]["known_static_surfaces"]["main_touchscreen"] == 257


@pytest.mark.asyncio
async def test_core_device_diagnose_inspection_reports_per_service_errors() -> None:
    rsd = FakeRSD(
        {
            DisplayService.SERVICE_NAME: service(61001),
            UniversalHIDServiceService.SERVICE_NAME: service(61002),
        },
        failing_features={"com.apple.coredevice.feature.getmediastreamserverstatus"},
    )

    payload = await core_device.build_core_device_diagnose_payload(rsd, probe=False, inspect=True, timeout=0.1)

    inspections = payload["inspections"]
    assert inspections["display"]["media_support_info"]["ok"] is True
    assert inspections["display"]["media_stream_server_status"]["ok"] is False
    assert inspections["display"]["media_stream_server_status"]["error"]["type"] == "RuntimeError"
    assert inspections["universal_hid"]["connected_services"]["ok"] is True
    assert inspections["hints"]


def test_core_device_diagnose_help() -> None:
    result = CliRunner().invoke(core_device.cli, ["diagnose", "--help"])

    assert result.exit_code == 0
    assert "--probe" in result.output
    assert "--no-probe" in result.output
    assert "--inspect" in result.output
    assert "--no-inspect" in result.output
    assert "--timeout" in result.output
