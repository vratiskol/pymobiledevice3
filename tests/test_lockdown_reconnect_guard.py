import pytest

from pymobiledevice3.exceptions import ConnectionTerminatedError, InvalidConnectionError
from pymobiledevice3.lockdown import DEFAULT_LABEL, SERVICE_PORT, DeviceClass, LockdownClient


class _FakeService:
    def __init__(self, responses: list[dict | Exception]) -> None:
        self._responses = responses
        self.requests: list[dict] = []
        self.closed = False

    async def send_recv_plist(self, message: dict) -> dict:
        self.requests.append(message)
        if not self._responses:
            raise AssertionError("unexpected request")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    async def close(self) -> None:
        self.closed = True


class _UnitLockdownClient(LockdownClient):
    def __init__(self, service: _FakeService, reconnect_services: list[_FakeService]) -> None:
        super().__init__(
            service,
            host_id="host-id",
            identifier="udid",
            label=DEFAULT_LABEL,
            pair_record={"HostID": "host-id", "SystemBUID": "system-buid"},
        )
        self.all_values = {"ProductVersion": "17.0", "DeviceClass": DeviceClass.IPHONE.value}
        self.reconnect_services = reconnect_services
        self.reconnect_count = 0

    async def create_service_connection(self, port: int) -> _FakeService:
        assert port == SERVICE_PORT
        self.reconnect_count += 1
        if not self.reconnect_services:
            raise AssertionError("unexpected reconnect")
        return self.reconnect_services.pop(0)


@pytest.mark.asyncio
async def test_reconnect_validation_does_not_recurse_on_connection_termination() -> None:
    client = _UnitLockdownClient(
        _FakeService([ConnectionTerminatedError()]),
        [_FakeService([ConnectionTerminatedError()])],
    )

    with pytest.raises(ConnectionTerminatedError):
        await client._request("GetValue")

    assert client.reconnect_count == 1


@pytest.mark.asyncio
async def test_reconnect_validation_does_not_recurse_on_invalid_connection_response() -> None:
    client = _UnitLockdownClient(
        _FakeService([ConnectionTerminatedError()]),
        [
            _FakeService([
                {"Request": "StartSession", "SessionID": "session-id", "EnableSessionSSL": False},
                {"Request": "GetValue", "Error": "InvalidConnection"},
            ])
        ],
    )

    with pytest.raises(InvalidConnectionError):
        await client._request("GetValue")

    assert client.reconnect_count == 1
