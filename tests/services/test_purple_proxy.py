import plistlib
import struct

import pytest

from pymobiledevice3.restore import purple_proxy
from pymobiledevice3.restore.purple_proxy import (
    PURPLE_PROXY_CONTROL_PORT,
    PURPLE_PROXY_NOTIFY_PORT,
    PURPLE_PROXY_SOCKS_PORT,
    PurpleProxyClient,
    PurpleProxyCommand,
    probe_purple_proxy_hello,
    sanitize_purple_proxy_response,
)


class FakeService:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.sent = []
        self.closed = False

    async def recv_plist(self, endianity=">"):
        assert endianity == ">"
        return self.responses.pop(0)

    async def send_plist(self, message, endianity=">", fmt=plistlib.FMT_XML):
        assert endianity == ">"
        assert fmt == plistlib.FMT_XML
        self.sent.append(message)

    async def close(self):
        self.closed = True


class FakePurpleProxyClient:
    def __init__(self, response):
        self.response = response
        self.closed = False

    async def hello_control(self, protocol_version=1):
        assert protocol_version == 2
        return self.response

    async def close(self):
        self.closed = True


def parse_prefixed_plist(data: bytes):
    size = struct.unpack(">L", data[:4])[0]
    return plistlib.loads(data[4 : 4 + size])


@pytest.mark.asyncio
async def test_read_dictionary_rejects_non_dictionary_response():
    client = PurpleProxyClient(FakeService(responses=[["not", "a", "dict"]]))

    with pytest.raises(TypeError, match="expected PurpleReverseProxy dictionary"):
        await client.read_dictionary()


@pytest.mark.asyncio
async def test_write_dictionary_uses_service_plist_framing():
    service = FakeService()
    client = PurpleProxyClient(service)

    await client.write_dictionary({"Command": "HelloCtrl", "CtrlProtoVersion": 1})

    assert service.sent == [{"Command": "HelloCtrl", "CtrlProtoVersion": 1}]


@pytest.mark.asyncio
async def test_hello_control_sends_command_and_reads_response():
    service = FakeService(responses=[{"Status": "OK", "CtrlProtoVersion": 1}])
    client = PurpleProxyClient(service)

    response = await client.hello_control(HostSupportsDeprecatedProtocol=True)

    assert response == {"Status": "OK", "CtrlProtoVersion": 1}
    assert service.sent == [
        {
            "Command": "HelloCtrl",
            "CtrlProtoVersion": 1,
            "HostSupportsDeprecatedProtocol": True,
        }
    ]


@pytest.mark.asyncio
async def test_control_command_helpers_use_firmware_command_names():
    service = FakeService(responses=[{"Status": "OK"}, {"SocketReady": True}, {"Pong": True}])
    client = PurpleProxyClient(service)

    assert await client.begin_control(CtrlConn=True) == {"Status": "OK"}
    assert await client.wait_socket(ConnPort=1081) == {"SocketReady": True}
    assert await client.send_ping() == {"Pong": True}

    assert service.sent == [
        {"Command": "BeginCtrl", "CtrlConn": True},
        {"Command": "WaitSocket", "ConnPort": 1081},
        {"Command": "Ping"},
    ]


@pytest.mark.asyncio
async def test_send_control_message_accepts_enum_command():
    service = FakeService()
    client = PurpleProxyClient(service)

    await client.send_control_message(PurpleProxyCommand.WAIT_SOCKET, ConnPort=1082)

    assert service.sent == [{"Command": "WaitSocket", "ConnPort": 1082}]


@pytest.mark.asyncio
async def test_close_delegates_to_service():
    service = FakeService()
    client = PurpleProxyClient(service)

    await client.close()

    assert service.closed is True


@pytest.mark.asyncio
async def test_connect_helpers_use_expected_ports(monkeypatch):
    calls = []

    async def fake_create_using_usbmux(udid, port, connection_type=None, usbmux_address=None):
        calls.append({
            "udid": udid,
            "port": port,
            "connection_type": connection_type,
            "usbmux_address": usbmux_address,
        })
        return FakeService()

    monkeypatch.setattr(purple_proxy.ServiceConnection, "create_using_usbmux", fake_create_using_usbmux)

    await PurpleProxyClient.connect_control("serial", usbmux_address="/tmp/usbmux")
    await PurpleProxyClient.connect_socks("serial", connection_type="Network")
    await PurpleProxyClient.connect_notify("serial")

    assert calls == [
        {
            "udid": "serial",
            "port": PURPLE_PROXY_CONTROL_PORT,
            "connection_type": "USB",
            "usbmux_address": "/tmp/usbmux",
        },
        {
            "udid": "serial",
            "port": PURPLE_PROXY_SOCKS_PORT,
            "connection_type": "Network",
            "usbmux_address": None,
        },
        {
            "udid": "serial",
            "port": PURPLE_PROXY_NOTIFY_PORT,
            "connection_type": "USB",
            "usbmux_address": None,
        },
    ]


def test_service_connection_prefixed_plist_shape_is_compatible():
    payload = plistlib.dumps({"Command": "HelloCtrl", "CtrlProtoVersion": 1}, fmt=plistlib.FMT_XML)
    frame = struct.pack(">L", len(payload)) + payload

    assert parse_prefixed_plist(frame) == {"Command": "HelloCtrl", "CtrlProtoVersion": 1}


def test_sanitize_purple_proxy_response_redacts_identifier_keys():
    response = {
        "Status": "OK",
        "SerialNumber": "sensitive",
        "Nested": {"UniqueChipID": 1234},
        "Items": [{"UDID": "sensitive"}],
    }

    assert sanitize_purple_proxy_response(response) == {
        "Status": "OK",
        "SerialNumber": "<redacted>",
        "Nested": {"UniqueChipID": "<redacted>"},
        "Items": [{"UDID": "<redacted>"}],
    }


@pytest.mark.asyncio
async def test_probe_purple_proxy_hello_returns_sanitized_response(monkeypatch):
    fake_client = FakePurpleProxyClient({
        "Status": "OK",
        "SerialNumber": "sensitive",
        "CtrlProtoVersion": 2,
    })
    calls = []

    async def fake_connect_control(udid=None, **kwargs):
        calls.append({"udid": udid, **kwargs})
        return fake_client

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_control", staticmethod(fake_connect_control))

    result = await probe_purple_proxy_hello(
        udid="sensitive-udid",
        usbmux_address="/tmp/usbmux",
        timeout=0.1,
        port=1234,
        protocol_version=2,
        include_response=True,
    )

    assert result == {
        "checked": True,
        "experimental": True,
        "command": "HelloCtrl",
        "port": 1234,
        "protocol_version": 2,
        "include_response": True,
        "reachable": True,
        "response_keys": ["CtrlProtoVersion", "SerialNumber", "Status"],
        "response": {
            "Status": "OK",
            "SerialNumber": "<redacted>",
            "CtrlProtoVersion": 2,
        },
    }
    assert calls == [
        {
            "udid": "sensitive-udid",
            "connection_type": "USB",
            "usbmux_address": "/tmp/usbmux",
            "port": 1234,
        }
    ]
    assert fake_client.closed is True
    assert "sensitive" not in repr(result)


@pytest.mark.asyncio
async def test_probe_purple_proxy_hello_reports_connect_error(monkeypatch):
    async def fake_connect_control(udid=None, **kwargs):
        raise OSError("closed")

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_control", staticmethod(fake_connect_control))

    result = await probe_purple_proxy_hello(timeout=0.1)

    assert result == {
        "checked": True,
        "experimental": True,
        "command": "HelloCtrl",
        "port": PURPLE_PROXY_CONTROL_PORT,
        "protocol_version": 1,
        "include_response": False,
        "reachable": False,
        "error_type": "OSError",
    }
