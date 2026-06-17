import plistlib
import struct

import pytest

from pymobiledevice3.exceptions import ConnectionTerminatedError
from pymobiledevice3.restore import purple_proxy
from pymobiledevice3.restore.restore_options import (
    summarize_restore_message,
    summarize_restore_message_details,
    summarize_restore_message_type,
    summarize_restore_options,
)
from pymobiledevice3.restore.purple import collect_live_purple_usb_inventory
from pymobiledevice3.restore.purple_proxy import (
    PURPLE_PROXY_CONTROL_PORT,
    PURPLE_PROXY_NOTIFY_PORT,
    PURPLE_PROXY_SOCKS_PORT,
    PurpleProxyClient,
    PurpleProxyCommand,
    build_purple_proxy_dictionary,
    classify_purple_proxy_notify_message,
    is_purple_proxy_pong_response,
    probe_purple_proxy_conn,
    probe_purple_proxy_hello,
    run_purple_proxy_control_command,
    run_purple_proxy_notify_command,
    run_purple_proxy_session,
    run_purple_proxy_socks_probe,
    sanitize_purple_proxy_response,
    summarize_purple_proxy_notify_messages,
)


class FakeService:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.sent = []
        self.closed = False

    async def recv_plist(self, endianity=">"):
        assert endianity in (">", "<")
        return self.responses.pop(0)

    async def send_plist(self, message, endianity=">", fmt=plistlib.FMT_XML):
        assert endianity in (">", "<")
        assert fmt in (plistlib.FMT_XML, plistlib.FMT_BINARY)
        self.sent.append(message)

    async def recvall(self, size):
        response = self.responses.pop(0)
        assert len(response) == size
        return response

    async def sendall(self, payload):
        self.sent.append(payload)

    async def close(self):
        self.closed = True


class FakeUsbEndpoint:
    def __init__(self, address, attributes=2, max_packet_size=512):
        self.bEndpointAddress = address
        self.bmAttributes = attributes
        self.wMaxPacketSize = max_packet_size


class FakeUsbInterface:
    def __init__(self, interface_number, alternate_setting, interface_class, interface_subclass, interface_protocol, iinterface, endpoints):
        self.bInterfaceNumber = interface_number
        self.bAlternateSetting = alternate_setting
        self.bInterfaceClass = interface_class
        self.bInterfaceSubClass = interface_subclass
        self.bInterfaceProtocol = interface_protocol
        self.iInterface = iinterface
        self._endpoints = list(endpoints)

    def endpoints(self):
        return list(self._endpoints)


class FakeUsbConfiguration:
    def __init__(self, interfaces):
        self.bConfigurationValue = 1
        self.bNumInterfaces = 2
        self.wTotalLength = 0x39
        self._interfaces = list(interfaces)

    def __iter__(self):
        return iter(self._interfaces)


class FakeUsbDevice:
    idVendor = 0x05AC
    idProduct = 0x1281
    speed = 3
    iSerialNumber = 4
    iManufacturer = 2
    iProduct = 3

    def __init__(self):
        self._configuration = FakeUsbConfiguration(
            [
                FakeUsbInterface(0, 0, 0xFE, 0x01, 0x02, 0, [FakeUsbEndpoint(0x04)]),
                FakeUsbInterface(1, 0, 0xFF, 0xFF, 0x51, 0, []),
                FakeUsbInterface(1, 1, 0xFF, 0xFF, 0x51, 6, [FakeUsbEndpoint(0x81), FakeUsbEndpoint(0x02)]),
            ]
        )

    def get_active_configuration(self):
        return self._configuration


class FakePurpleProxyClient:
    def __init__(self, response=None, messages=None, sync_response=None):
        self.response = response or {}
        self.messages = list(messages or [])
        self.sync_response = sync_response or {
            "Command": "ControlSync",
            "message": 1,
            "message_name": "sync",
            "sync": True,
            "payload_hex": "0100",
            "payload_size": 2,
        }
        self.sent = []
        self.closed = False

    async def hello_control(self, protocol_version=1, **fields):
        assert protocol_version in (1, 2)
        return self.response

    async def hello_conn(self, protocol_version=1, **fields):
        assert protocol_version in (1, 2)
        return self.response

    async def begin_control(self, protocol_version=1, **fields):
        assert protocol_version in (1, 2)
        return self.response

    async def wait_socket(self, conn_port=PURPLE_PROXY_SOCKS_PORT):
        assert conn_port == 4321
        return self.response

    async def send_ping(self):
        return self.response

    async def register_notify(self):
        self.sent.append({"Command": "RegisterNotify"})

    async def set_log_level(self, level):
        self.sent.append({"Command": "SetLogLevel", "Level": level})

    async def read_dictionary(self):
        return self.messages.pop(0)

    async def read_control_sync_message(self):
        return self.sync_response

    async def close(self):
        self.closed = True


def parse_prefixed_plist(data: bytes, endianity: str = ">"):
    size = struct.unpack(f"{endianity}L", data[:4])[0]
    return plistlib.loads(data[4 : 4 + size])


def parse_command_frame(data: bytes, preamble: bytes, endianity: str = "<"):
    assert data.startswith(preamble)
    return parse_prefixed_plist(data[len(preamble) :], endianity=endianity)


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
async def test_client_trace_records_plist_io_with_sanitized_responses():
    trace = []
    service = FakeService(responses=[{"Command": "Pong", "SerialNumber": "sensitive"}])
    client = PurpleProxyClient(service, trace=trace, trace_channel="control")

    response = await client.send_recv_command_message(PurpleProxyCommand.PING)

    assert response == {"Command": "Pong", "SerialNumber": "sensitive"}
    assert [event["event"] for event in trace] == ["send_plist", "recv_plist"]
    assert trace[0]["channel"] == "control"
    assert trace[0]["message"] == {"Command": "Ping"}
    assert trace[1]["response"] == {"Command": "Pong", "SerialNumber": "<redacted>"}


@pytest.mark.asyncio
async def test_hello_control_sends_command_and_reads_response():
    service = FakeService(responses=[purple_proxy.PURPLE_PROXY_HELLO_CONTROL_PREAMBLE, b"\xe1\x10"])
    client = PurpleProxyClient(service)

    response = await client.hello_control(HostSupportsDeprecatedProtocol=True)

    assert response == {
        "Command": "HelloCtrl",
        "CtrlProtoVersion": 1,
        "ConnPort": 4321,
        "DeprecatedProtocol": True,
        "RequestedCtrlProtoVersion": 2,
        "IgnoredRequestFields": ["HostSupportsDeprecatedProtocol"],
    }
    assert service.sent == [purple_proxy.PURPLE_PROXY_HELLO_CONTROL_PREAMBLE]


@pytest.mark.asyncio
async def test_control_command_helpers_use_firmware_command_names():
    service = FakeService(responses=[{"Status": "OK"}, {"Pong": True}])
    client = PurpleProxyClient(service, endianity="<")

    assert await client.begin_control(protocol_version=2, CtrlConn=True) == {"Status": "OK"}
    with pytest.raises(RuntimeError, match="WaitSocket is an internal firmware accept helper"):
        await client.wait_socket(conn_port=1081)
    assert await client.send_ping() == {"Pong": True}

    assert parse_command_frame(service.sent[0], purple_proxy.PURPLE_PROXY_BEGIN_CONTROL_PREAMBLE) == {
        "Command": "BeginCtrl",
        "CtrlProtoVersion": 2,
        "CtrlConn": True,
    }
    assert service.sent[1:] == [{"Command": "Ping"}]


@pytest.mark.asyncio
async def test_control_command_helpers_support_legacy_protocol_version_one():
    service = FakeService(responses=[purple_proxy.PURPLE_PROXY_HELLO_CONTROL_PREAMBLE, b"\xe1\x10", {"Status": "OK"}])
    client = PurpleProxyClient(service, endianity="<")

    assert await client.hello_control(protocol_version=1) == {
        "Command": "HelloCtrl",
        "CtrlProtoVersion": 1,
        "ConnPort": 4321,
        "DeprecatedProtocol": True,
        "RequestedCtrlProtoVersion": 1,
    }
    assert await client.begin_control(protocol_version=1) == {"Status": "OK"}

    assert service.sent[0] == purple_proxy.PURPLE_PROXY_HELLO_CONTROL_PREAMBLE
    assert parse_command_frame(service.sent[1], purple_proxy.PURPLE_PROXY_BEGIN_CONTROL_PREAMBLE) == {
        "Command": "BeginCtrl",
        "CtrlProtoVersion": 1,
    }


@pytest.mark.asyncio
async def test_conn_command_helpers_use_firmware_command_names():
    service = FakeService(responses=[{"Identifier": "device-id", "ConnProtoVersion": 2}])
    client = PurpleProxyClient(service, endianity="<")

    assert await client.hello_conn(protocol_version=2) == {"Identifier": "device-id", "ConnProtoVersion": 2}
    assert parse_command_frame(service.sent[0], purple_proxy.PURPLE_PROXY_HELLO_CONN_PREAMBLE) == {
        "Command": "HelloConn",
        "ConnProtoVersion": 2,
    }


@pytest.mark.asyncio
async def test_conn_command_helpers_support_legacy_protocol_version_one():
    service = FakeService(responses=[purple_proxy.PURPLE_PROXY_HELLO_CONN_PREAMBLE])
    client = PurpleProxyClient(service, endianity="<")

    assert await client.hello_conn(protocol_version=1) == {
        "Command": "HelloConn",
        "ConnProtoVersion": 1,
        "DeprecatedProtocol": True,
    }
    assert service.sent[0] == purple_proxy.PURPLE_PROXY_HELLO_CONN_PREAMBLE


@pytest.mark.asyncio
async def test_notify_command_helpers_use_firmware_command_names():
    service = FakeService()
    client = PurpleProxyClient(service)

    await client.register_notify()
    await client.set_log_level(7)

    assert service.sent == [
        {"Command": "RegisterNotify"},
        {"Command": "SetLogLevel", "Level": 7},
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


def test_classify_purple_proxy_notify_message_recognizes_known_shapes():
    assert classify_purple_proxy_notify_message({"Event": "ProxyOnline"}) == "proxy_online"
    assert classify_purple_proxy_notify_message({"Name": "com.apple.PurpleReverseProxy.ProxyOnline"}) == "proxy_online"
    assert classify_purple_proxy_notify_message({"Error": "connection failed"}) == "error"
    assert classify_purple_proxy_notify_message({"Level": 7, "Message": "verbose"}) == "log"
    assert classify_purple_proxy_notify_message({"Status": "Ready"}) == "status"
    assert classify_purple_proxy_notify_message({"Message": "opaque"}) == "unknown"


def test_summarize_purple_proxy_notify_messages_counts_classifications():
    summary = summarize_purple_proxy_notify_messages([
        {"Event": "ProxyOnline"},
        {"Error": "connection failed"},
        {"Level": 7},
        {"Message": "opaque"},
    ])

    assert summary == {
        "classified": True,
        "message_count": 4,
        "observed_events": ["error", "log", "proxy_online", "unknown"],
        "event_counts": {
            "error": 1,
            "log": 1,
            "proxy_online": 1,
            "unknown": 1,
        },
        "proxy_online": True,
        "error_count": 1,
        "unknown_count": 1,
    }


def test_build_purple_proxy_dictionary_matches_firmware_strings():
    assert build_purple_proxy_dictionary(
        url="https://example.test/path",
        host="127.0.0.1",
        socks_port=4321,
        test_reachability=False,
    ) == {
        "checked": True,
        "source": "libReverseProxyDevice",
        "function": "CopyProxyDictionaryWithOptions",
        "url": "https://example.test/path",
        "test_reachability": False,
        "proxy_url": "socks://127.0.0.1:4321/",
        "proxy_dictionary": {
            "SOCKSProxyHost": "127.0.0.1",
            "SOCKSProxyPort": 4321,
        },
        "requires_ping": True,
    }


def test_is_purple_proxy_pong_response_accepts_known_shapes():
    assert is_purple_proxy_pong_response({"Command": "Pong"}) is True
    assert is_purple_proxy_pong_response({"Pong": True}) is True
    assert is_purple_proxy_pong_response({"Command": "Error"}) is False


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
async def test_probe_purple_proxy_conn_returns_sanitized_response(monkeypatch):
    fake_client = FakePurpleProxyClient({
        "Identifier": "sensitive",
        "ConnProtoVersion": 2,
    })
    calls = []

    async def fake_connect_socks(udid=None, **kwargs):
        calls.append({"udid": udid, **kwargs})
        return fake_client

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_socks", staticmethod(fake_connect_socks))

    result = await probe_purple_proxy_conn(
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
        "command": "HelloConn",
        "port": 1234,
        "protocol_version": 2,
        "include_response": True,
        "reachable": True,
        "response_keys": ["ConnProtoVersion", "Identifier"],
        "identifier": "<redacted>",
        "response": {
            "Identifier": "<redacted>",
            "ConnProtoVersion": 2,
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


@pytest.mark.asyncio
async def test_run_purple_proxy_control_command_begin_returns_sanitized_response(monkeypatch):
    fake_client = FakePurpleProxyClient({
        "Status": "OK",
        "SerialNumber": "sensitive",
        "CtrlProtoVersion": 2,
    })

    async def fake_connect_control(udid=None, **kwargs):
        return fake_client

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_control", staticmethod(fake_connect_control))

    result = await run_purple_proxy_control_command(
        PurpleProxyCommand.BEGIN_CONTROL,
        timeout=0.1,
        protocol_version=2,
        include_response=True,
    )

    assert result == {
        "checked": True,
        "experimental": True,
        "command": "BeginCtrl",
        "port": PURPLE_PROXY_CONTROL_PORT,
        "include_response": True,
        "protocol_version": 2,
        "reachable": True,
        "response_keys": ["CtrlProtoVersion", "SerialNumber", "Status"],
        "response": {
            "Status": "OK",
            "SerialNumber": "<redacted>",
            "CtrlProtoVersion": 2,
        },
    }
    assert fake_client.closed is True
    assert "sensitive" not in repr(result)


@pytest.mark.asyncio
async def test_run_purple_proxy_control_command_wait_socket_reports_internal_helper():
    result = await run_purple_proxy_control_command(
        PurpleProxyCommand.WAIT_SOCKET,
        timeout=0.1,
        conn_port=4321,
        include_response=True,
    )

    assert result == {
        "checked": True,
        "experimental": True,
        "command": "WaitSocket",
        "port": PURPLE_PROXY_CONTROL_PORT,
        "include_response": True,
        "conn_port": 4321,
        "firmware_internal": True,
        "reachable": False,
        "reason": "WaitSocket is an internal firmware accept helper, not a host wire command.",
    }


@pytest.mark.asyncio
async def test_run_purple_proxy_control_command_ping_marks_pong(monkeypatch):
    fake_client = FakePurpleProxyClient({"Command": "Pong"})

    async def fake_connect_control(udid=None, **kwargs):
        return fake_client

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_control", staticmethod(fake_connect_control))

    result = await run_purple_proxy_control_command(
        PurpleProxyCommand.PING,
        timeout=0.1,
        include_response=True,
    )

    assert result == {
        "checked": True,
        "experimental": True,
        "command": "Ping",
        "port": PURPLE_PROXY_CONTROL_PORT,
        "include_response": True,
        "reachable": True,
        "response_keys": ["Command"],
        "pong": True,
        "response": {"Command": "Pong"},
    }
    assert fake_client.closed is True


@pytest.mark.asyncio
async def test_run_purple_proxy_notify_command_register_collects_sanitized_messages(monkeypatch):
    fake_client = FakePurpleProxyClient(
        messages=[
            {
                "Event": "ProxyOnline",
                "SerialNumber": "sensitive",
            }
        ]
    )
    calls = []

    async def fake_connect_notify(udid=None, **kwargs):
        calls.append({"udid": udid, **kwargs})
        return fake_client

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_notify", staticmethod(fake_connect_notify))

    result = await run_purple_proxy_notify_command(
        PurpleProxyCommand.REGISTER_NOTIFY,
        udid="sensitive-udid",
        usbmux_address="/tmp/usbmux",
        timeout=0.1,
        port=1234,
        include_response=True,
        listen_timeout=0.1,
        max_messages=1,
    )

    assert result == {
        "checked": True,
        "experimental": True,
        "command": "RegisterNotify",
        "port": 1234,
        "include_response": True,
        "expect_response": False,
        "listen_timeout": 0.1,
        "max_messages": 1,
        "reachable": True,
        "sent": True,
        "message_count": 1,
        "message_keys": [["Event", "SerialNumber"]],
        "notify_summary": {
            "classified": True,
            "message_count": 1,
            "observed_events": ["proxy_online"],
            "event_counts": {"proxy_online": 1},
            "proxy_online": True,
            "error_count": 0,
            "unknown_count": 0,
        },
        "messages": [{"Event": "ProxyOnline", "SerialNumber": "<redacted>"}],
    }
    assert fake_client.sent == [{"Command": "RegisterNotify"}]
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
async def test_run_purple_proxy_notify_command_keeps_sent_success_when_listen_closes(monkeypatch):
    class ClosingNotifyClient(FakePurpleProxyClient):
        async def read_dictionary(self):
            raise ConnectionTerminatedError()

    fake_client = ClosingNotifyClient()

    async def fake_connect_notify(udid=None, **kwargs):
        return fake_client

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_notify", staticmethod(fake_connect_notify))

    result = await run_purple_proxy_notify_command(
        PurpleProxyCommand.REGISTER_NOTIFY,
        timeout=0.1,
        listen_timeout=0.1,
        max_messages=1,
    )

    assert result["reachable"] is True
    assert result["sent"] is True
    assert result["message_error_type"] == "ConnectionTerminatedError"
    assert fake_client.sent == [{"Command": "RegisterNotify"}]


@pytest.mark.asyncio
async def test_run_purple_proxy_notify_command_set_log_level_sends_level(monkeypatch):
    fake_client = FakePurpleProxyClient()

    async def fake_connect_notify(udid=None, **kwargs):
        return fake_client

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_notify", staticmethod(fake_connect_notify))

    result = await run_purple_proxy_notify_command(
        PurpleProxyCommand.SET_LOG_LEVEL,
        level=7,
        timeout=0.1,
    )

    assert result == {
        "checked": True,
        "experimental": True,
        "command": "SetLogLevel",
        "port": PURPLE_PROXY_NOTIFY_PORT,
        "include_response": False,
        "expect_response": False,
        "level": 7,
        "reachable": True,
        "sent": True,
    }
    assert fake_client.sent == [{"Command": "SetLogLevel", "Level": 7}]
    assert fake_client.closed is True


@pytest.mark.asyncio
async def test_run_purple_proxy_notify_command_requires_level_for_set_log_level():
    with pytest.raises(ValueError, match="level is required"):
        await run_purple_proxy_notify_command(PurpleProxyCommand.SET_LOG_LEVEL)


@pytest.mark.asyncio
async def test_run_purple_proxy_notify_command_reports_connect_error(monkeypatch):
    async def fake_connect_notify(udid=None, **kwargs):
        raise OSError("closed")

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_notify", staticmethod(fake_connect_notify))

    result = await run_purple_proxy_notify_command(PurpleProxyCommand.REGISTER_NOTIFY, timeout=0.1)

    assert result == {
        "checked": True,
        "experimental": True,
        "command": "RegisterNotify",
        "port": PURPLE_PROXY_NOTIFY_PORT,
        "include_response": False,
        "expect_response": False,
        "reachable": False,
        "error_type": "OSError",
    }


@pytest.mark.asyncio
async def test_run_purple_proxy_socks_probe_accepts_no_auth_handshake(monkeypatch):
    service = FakeService(responses=[b"\x05\x00"])
    calls = []

    async def fake_connect_socks(udid=None, **kwargs):
        calls.append({"udid": udid, **kwargs})
        return PurpleProxyClient(service, endianity="<")

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_socks", staticmethod(fake_connect_socks))

    result = await run_purple_proxy_socks_probe(
        udid="sensitive-udid",
        usbmux_address="/tmp/usbmux",
        timeout=0.1,
        include_response=True,
    )

    assert result == {
        "checked": True,
        "experimental": True,
            "protocol": "SOCKS5",
            "port": PURPLE_PROXY_SOCKS_PORT,
            "include_response": True,
            "requires_control_connection": True,
            "reachable": True,
            "handshake": {
                "sent": True,
            "version": 5,
            "method": 0,
            "method_name": "no_authentication_required",
            "accepted": True,
            "response_hex": "0500",
        },
        "connect": {
            "checked": False,
            "reason": "--connect-host was not provided.",
        },
        "summary": {
            "handshake_ok": True,
            "connect_succeeded": None,
            "ok": True,
        },
    }
    assert service.sent[0] == b"\x05\x01\x00"
    assert service.closed is True
    assert calls == [
        {
            "udid": "sensitive-udid",
            "connection_type": "USB",
            "usbmux_address": "/tmp/usbmux",
            "port": PURPLE_PROXY_SOCKS_PORT,
        }
    ]
    assert "sensitive" not in repr(result)


@pytest.mark.asyncio
async def test_run_purple_proxy_socks_probe_sends_connect_request(monkeypatch):
    service = FakeService(
        responses=[
            b"\x05\x00",
            b"\x05\x00\x00\x01",
            b"\x00\x00\x00\x00",
            b"\x04\xd2",
        ]
    )

    async def fake_connect_socks(udid=None, **kwargs):
        return PurpleProxyClient(service, endianity="<")

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_socks", staticmethod(fake_connect_socks))

    result = await run_purple_proxy_socks_probe(
        timeout=0.1,
        connect_host="example.test",
        connect_port=443,
        include_response=True,
    )

    assert result["connect"] == {
        "checked": True,
        "target_address_type": "domain",
        "target_port": 443,
        "sent": True,
        "version": 5,
        "reply": 0,
        "reply_name": "succeeded",
        "reserved": 0,
        "bound_address_type": "ipv4",
        "bound_address_length": 4,
        "bound_port": 1234,
        "succeeded": True,
        "response_hex": "050000010000000004d2",
    }
    assert result["summary"] == {
        "handshake_ok": True,
        "connect_succeeded": True,
        "ok": True,
    }
    assert service.sent[0] == b"\x05\x01\x00"
    assert service.sent[1] == b"\x05\x01\x00\x03\x0cexample.test\x01\xbb"
    assert service.closed is True


@pytest.mark.asyncio
async def test_run_purple_proxy_socks_probe_reports_connect_error(monkeypatch):
    async def fake_connect_socks(udid=None, **kwargs):
        raise OSError("closed")

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_socks", staticmethod(fake_connect_socks))

    result = await run_purple_proxy_socks_probe(timeout=0.1)

    assert result == {
        "checked": True,
        "experimental": True,
        "protocol": "SOCKS5",
        "port": PURPLE_PROXY_SOCKS_PORT,
        "include_response": False,
        "requires_control_connection": True,
        "reachable": False,
        "error_type": "OSError",
        "summary": {
            "handshake_ok": False,
            "connect_succeeded": None,
            "ok": False,
        },
    }


@pytest.mark.asyncio
async def test_run_purple_proxy_session_keeps_notify_open_during_control_sequence(monkeypatch):
    notify_client = FakePurpleProxyClient(messages=[{"Event": "ProxyOnline", "SerialNumber": "sensitive"}])
    control_client = FakePurpleProxyClient({"Command": "Pong", "SerialNumber": "sensitive"})
    conn_client = FakePurpleProxyClient({"Command": "HelloConn", "Identifier": "sensitive"})
    calls = []

    async def fake_connect_notify(udid=None, **kwargs):
        calls.append({"kind": "notify", "udid": udid, **kwargs})
        return notify_client

    async def fake_connect_control(udid=None, **kwargs):
        calls.append({"kind": "control", "udid": udid, **kwargs})
        return control_client

    async def fake_connect_socks(udid=None, **kwargs):
        calls.append({"kind": "conn", "udid": udid, **kwargs})
        return conn_client

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_notify", staticmethod(fake_connect_notify))
    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_control", staticmethod(fake_connect_control))
    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_socks", staticmethod(fake_connect_socks))

    result = await run_purple_proxy_session(
        udid="sensitive-udid",
        usbmux_address="/tmp/usbmux",
        timeout=0.1,
        control_port=1234,
        notify_port=1235,
        protocol_version=2,
        conn_port=4321,
        log_level=7,
        include_response=True,
        listen_timeout=0.1,
        max_messages=1,
    )

    phases = result["phases"]
    assert result["summary"] == {
        "hello_control_reachable": False,
        "hello_conn_reachable": True,
        "control_reachable": True,
        "control_sync_received": True,
        "ping_pong": False,
        "wait_socket_reachable": False,
        "notify_registered": True,
        "set_log_level_sent": True,
        "socks_probe_ok": None,
        "proxy_dictionary_ready": True,
        "ok": True,
    }
    assert phases["set_log_level"]["sent"] is True
    assert phases["register_notify"]["notify_summary"] == {
        "classified": True,
        "message_count": 1,
        "observed_events": ["proxy_online"],
        "event_counts": {"proxy_online": 1},
        "proxy_online": True,
        "error_count": 0,
        "unknown_count": 0,
    }
    assert phases["register_notify"]["messages"] == [{"Event": "ProxyOnline", "SerialNumber": "<redacted>"}]
    assert phases["hello_control"] == {
        "checked": False,
        "reason": "Not part of the default purple-session flow.",
    }
    assert phases["begin_control"]["response"] == {"Command": "Pong", "SerialNumber": "<redacted>"}
    assert phases["control_sync"]["sync"] is True
    assert phases["hello_conn"]["reachable"] is True
    assert phases["ping"] == {
        "checked": False,
        "reason": "Not part of the BeginCtrl/ControlSync negotiation flow.",
    }
    assert phases["wait_socket"] == {
        "checked": False,
        "reason": "WaitSocket is an internal firmware accept helper, not a host wire command.",
    }
    assert phases["proxy_dictionary"]["proxy_url"] == "socks://127.0.0.1:4321/"
    assert phases["socks_probe"] == {
        "checked": False,
        "reason": "--probe-socks was not provided.",
    }
    assert notify_client.sent == [
        {"Command": "SetLogLevel", "Level": 7},
        {"Command": "RegisterNotify"},
    ]
    assert calls == [
        {
            "kind": "notify",
            "udid": "sensitive-udid",
            "connection_type": "USB",
            "usbmux_address": "/tmp/usbmux",
            "port": 1235,
        },
        {
            "kind": "control",
            "udid": "sensitive-udid",
            "connection_type": "USB",
            "usbmux_address": "/tmp/usbmux",
            "port": 1234,
        },
        {
            "kind": "conn",
            "udid": "sensitive-udid",
            "connection_type": "USB",
            "usbmux_address": "/tmp/usbmux",
            "port": 4321,
        },
    ]
    assert notify_client.closed is True
    assert control_client.closed is True
    assert conn_client.closed is True
    assert "sensitive" not in repr(result)


@pytest.mark.asyncio
async def test_run_purple_proxy_session_connects_conn_after_control_sync(monkeypatch):
    notify_client = FakePurpleProxyClient()
    control_client = FakePurpleProxyClient({"Pong": True, "ConnPort": 4321})
    conn_client = FakePurpleProxyClient({"Command": "HelloConn", "Identifier": "sensitive"})
    calls = []

    async def fake_connect_notify(udid=None, **kwargs):
        calls.append({"kind": "notify", "port": kwargs["port"]})
        return notify_client

    async def fake_connect_control(udid=None, **kwargs):
        calls.append({"kind": "control", "port": kwargs["port"]})
        return control_client

    async def fake_connect_socks(udid=None, **kwargs):
        calls.append({"kind": "conn", "port": kwargs["port"]})
        return conn_client

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_notify", staticmethod(fake_connect_notify))
    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_control", staticmethod(fake_connect_control))
    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_socks", staticmethod(fake_connect_socks))

    result = await run_purple_proxy_session(
        timeout=0.1,
        protocol_version=2,
        listen_timeout=0.0,
        conn_port=4321,
    )

    assert result["summary"] == {
        "hello_control_reachable": False,
        "hello_conn_reachable": True,
        "control_reachable": True,
        "control_sync_received": True,
        "ping_pong": False,
        "wait_socket_reachable": False,
        "notify_registered": True,
        "set_log_level_sent": None,
        "socks_probe_ok": None,
        "proxy_dictionary_ready": True,
        "ok": True,
    }
    assert [call["port"] for call in calls if call["kind"] == "conn"] == [4321]
    assert result["phases"]["control_sync"]["sync"] is True
    assert result["phases"]["hello_conn"]["reachable"] is True
    assert conn_client.closed is True


@pytest.mark.asyncio
async def test_run_purple_proxy_session_can_include_identifiers(monkeypatch):
    notify_client = FakePurpleProxyClient(messages=[{"Event": "ProxyOnline", "SerialNumber": "sensitive"}])
    control_client = FakePurpleProxyClient({"Command": "Pong", "SerialNumber": "sensitive"})
    conn_client = FakePurpleProxyClient({"Command": "HelloConn", "Identifier": "sensitive"})

    async def fake_connect_notify(udid=None, **kwargs):
        return notify_client

    async def fake_connect_control(udid=None, **kwargs):
        return control_client

    async def fake_connect_socks(udid=None, **kwargs):
        return conn_client

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_notify", staticmethod(fake_connect_notify))
    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_control", staticmethod(fake_connect_control))
    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_socks", staticmethod(fake_connect_socks))

    result = await run_purple_proxy_session(
        timeout=0.1,
        control_port=1234,
        notify_port=1235,
        protocol_version=2,
        conn_port=4321,
        log_level=7,
        include_response=True,
        include_identifiers=True,
        listen_timeout=0.1,
        max_messages=1,
    )

    assert result["include_identifiers"] is True
    assert result["phases"]["register_notify"]["messages"] == [{"Event": "ProxyOnline", "SerialNumber": "sensitive"}]
    assert result["phases"]["hello_conn"]["response"] == {"Command": "HelloConn", "Identifier": "sensitive"}
    assert result["phases"]["begin_control"]["response"] == {"Command": "Pong", "SerialNumber": "sensitive"}


@pytest.mark.asyncio
async def test_run_purple_proxy_session_trace_records_phase_and_plist_events(monkeypatch):
    notify_service = FakeService(responses=[{"Event": "ProxyOnline", "SerialNumber": "sensitive"}])
    control_service = FakeService(
        responses=[
            {"Command": "BeginAck", "SerialNumber": "sensitive"},
            b"\x01\x00",
        ]
    )
    conn_service = FakeService(responses=[{"Command": "HelloConn", "Identifier": "sensitive"}])

    async def fake_connect_notify(udid=None, **kwargs):
        return PurpleProxyClient(
            notify_service,
            trace=kwargs["trace"],
            trace_channel="notify",
            include_identifiers=kwargs.get("include_identifiers", False),
        )

    async def fake_connect_control(udid=None, **kwargs):
        return PurpleProxyClient(
            control_service,
            trace=kwargs["trace"],
            trace_channel="control",
            include_identifiers=kwargs.get("include_identifiers", False),
        )

    async def fake_connect_socks(udid=None, **kwargs):
        return PurpleProxyClient(
            conn_service,
            trace=kwargs["trace"],
            trace_channel="socks",
            include_identifiers=kwargs.get("include_identifiers", False),
        )

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_notify", staticmethod(fake_connect_notify))
    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_control", staticmethod(fake_connect_control))
    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_socks", staticmethod(fake_connect_socks))

    result = await run_purple_proxy_session(
        timeout=0.1,
        protocol_version=2,
        conn_port=4321,
        log_level=7,
        include_response=True,
        listen_timeout=0.1,
        max_messages=1,
        trace=True,
    )

    events = result["trace"]["events"]
    assert result["trace"]["enabled"] is True
    assert result["trace"]["event_count"] == len(events)
    assert "trace_timing" in result["phases"]["begin_control"]
    assert "trace_timing" in result["phases"]["hello_conn"]
    assert "send_plist" in [event["event"] for event in events]
    assert "recv_plist" in [event["event"] for event in events]
    assert {"Command": "BeginAck", "SerialNumber": "<redacted>"} in [
        event.get("response") for event in events if event["event"] == "recv_plist"
    ]


@pytest.mark.asyncio
async def test_run_purple_proxy_session_can_require_socks_probe(monkeypatch):
    notify_client = FakePurpleProxyClient()
    control_client = FakePurpleProxyClient({"Command": "Pong"})
    conn_client = FakePurpleProxyClient({"Command": "HelloConn", "Identifier": "sensitive"})
    socks_calls = []

    async def fake_connect_notify(udid=None, **kwargs):
        return notify_client

    async def fake_connect_control(udid=None, **kwargs):
        return control_client

    async def fake_connect_socks(udid=None, **kwargs):
        return conn_client

    async def fake_run_purple_proxy_socks_probe(**kwargs):
        socks_calls.append(kwargs)
        return {
            "checked": True,
            "experimental": True,
            "protocol": "SOCKS5",
            "port": 4321,
            "reachable": True,
            "summary": {
                "handshake_ok": True,
                "connect_succeeded": True,
                "ok": True,
            },
        }

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_notify", staticmethod(fake_connect_notify))
    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_control", staticmethod(fake_connect_control))
    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_socks", staticmethod(fake_connect_socks))
    monkeypatch.setattr(purple_proxy, "run_purple_proxy_socks_probe", fake_run_purple_proxy_socks_probe)

    result = await run_purple_proxy_session(
        udid="sensitive-udid",
        usbmux_address="/tmp/usbmux",
        timeout=0.1,
        protocol_version=2,
        conn_port=4321,
        probe_socks=True,
        socks_connect_host="example.test",
        socks_connect_port=443,
        listen_timeout=0.0,
    )

    assert result["summary"]["socks_probe_ok"] is True
    assert result["summary"]["ok"] is True
    assert result["phases"]["socks_probe"]["summary"]["connect_succeeded"] is True
    assert socks_calls == [
        {
            "udid": "sensitive-udid",
            "usbmux_address": "/tmp/usbmux",
            "timeout": 0.1,
            "port": 4321,
            "conn_protocol_version": 2,
            "connect_host": "example.test",
            "connect_port": 443,
            "connection_type": "USB",
            "include_response": False,
        }
    ]
    assert conn_client.closed is True
    assert "sensitive" not in repr(result)


@pytest.mark.asyncio
async def test_run_purple_proxy_session_summarizes_unreachable_control(monkeypatch):
    async def fake_connect_notify(udid=None, **kwargs):
        return FakePurpleProxyClient()

    async def fake_connect_control(udid=None, **kwargs):
        raise OSError("closed")

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_notify", staticmethod(fake_connect_notify))
    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_control", staticmethod(fake_connect_control))

    result = await run_purple_proxy_session(timeout=0.1, listen_timeout=0.0)

    assert result["summary"]["ok"] is False
    assert result["summary"]["hello_control_reachable"] is False
    assert result["summary"]["hello_conn_reachable"] is False
    assert result["summary"]["set_log_level_sent"] is None
    assert result["summary"]["socks_probe_ok"] is None
    assert result["phases"]["set_log_level"] == {
        "checked": False,
        "reason": "--log-level was not provided.",
    }
    assert result["phases"]["socks_probe"] == {
        "checked": False,
        "reason": "--probe-socks was not provided.",
    }
    assert result["phases"]["hello_control"] == {
        "checked": False,
        "reason": "Not part of the default purple-session flow.",
    }
    assert result["phases"]["begin_control"]["reachable"] is False
    assert result["phases"]["begin_control"]["error_type"] == "OSError"
    assert result["phases"]["hello_conn"]["reachable"] is False


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
        "protocol_version": 2,
        "include_response": False,
        "reachable": False,
        "error_type": "OSError",
    }


def test_summarize_restore_message_type_recognizes_checkpoint_alias():
    summary = summarize_restore_message_type("CheckpointMsg")

    assert summary == {
        "checked": True,
        "message_type": "CheckpointMsg",
        "canonical_type": "Checkpoint",
        "family": "checkpoint",
        "purpose": "Restore checkpoint marker",
        "alias_of": "Checkpoint",
    }


def test_summarize_restore_message_reports_keys_without_payload_values():
    summary = summarize_restore_message({"MsgType": "StatusMsg", "Status": 0, "Log": "hidden"})

    assert summary == {
        "checked": True,
        "message_type": "StatusMsg",
        "canonical_type": "StatusMsg",
        "family": "status",
        "purpose": "Restore status and final error reporting",
        "message_keys": ["Log", "MsgType", "Status"],
    }


def test_summarize_restore_message_details_reports_status_and_log_shape():
    summary = summarize_restore_message_details({"MsgType": "StatusMsg", "Status": 0, "Log": "line1\nline2"})

    assert summary["message_keys"] == ["Log", "MsgType", "Status"]
    assert summary["details"] == {
        "status": {
            "kind": "int",
            "value": 0,
            "success": True,
        },
        "log": {
            "kind": "string",
            "char_count": 11,
            "line_count": 2,
        },
    }


def test_summarize_restore_message_details_reports_restore_state_keys():
    summary = summarize_restore_message_details(
        {
            "MsgType": "CheckpointMsg",
            "restoreOutcome": {"kind": "success"},
            "restoreChildFailures": ["baseband"],
            "restoreRebootRetryEnabled": True,
        }
    )

    assert summary["state"] == {
        "restoreChildFailures": {
            "family": "restore_state",
            "purpose": "Child-operation failures accumulated during restore.",
            "value_summary": {
                "kind": "list",
                "item_count": 1,
            },
        },
        "restoreOutcome": {
            "family": "restore_state",
            "purpose": "Overall restore outcome reported by restored_update.",
            "value_summary": {
                "kind": "dict",
                "item_count": 1,
                "keys": ["kind"],
            },
        },
        "restoreRebootRetryEnabled": {
            "family": "restore_state",
            "purpose": "Reboot retry is enabled for restore.",
            "value_summary": {
                "kind": "bool",
                "value": True,
            },
        },
    }


def test_collect_live_purple_usb_inventory_reports_interface_altsettings(monkeypatch):
    from pymobiledevice3.restore import purple

    monkeypatch.setattr(purple, "usb_find", lambda find_all=True: [FakeUsbDevice()])
    monkeypatch.setattr(
        purple,
        "get_string",
        lambda device, index: {
            2: "Apple Inc.",
            3: "Apple Mobile Device (Recovery Mode)",
            4: "SDOM:01 CPID:8120 CPRV:11 CPFM:03 SCEP:01 BDID:08 ECID:0123456789ABCDEF IBFL:3D SIKA:00 SRNM:[PYMD3TEST0]",
            6: "Apple USB Serial Interface",
        }.get(index, ""),
    )

    summary = collect_live_purple_usb_inventory(ecid="0x123456789abcdef")

    assert summary["mode"] == "RECOVERY_MODE_2"
    assert summary["device_count"] == 1
    device = summary["devices"][0]
    assert device["configuration"] == {
        "value": 1,
        "interface_count": 2,
        "total_length": 57,
    }
    assert device["selected_interface_altsettings"] == [
        {"interface_number": 0, "alternate_setting": 0},
        {"interface_number": 1, "alternate_setting": 0},
    ]
    assert device["interfaces"][0]["selected_altsetting"] == 0
    assert device["interfaces"][0]["alternate_settings"][0]["selected"] is True
    assert device["interfaces"][1]["selected_altsetting"] == 0
    assert device["interfaces"][1]["alternate_settings"][0]["selected"] is True
    assert device["interfaces"][1]["alternate_settings"][1]["selected"] is False
    assert device["interfaces"][1]["alternate_settings"][1]["endpoints"] == [
        {"address": "0x81", "direction": "in", "transfer_type": "bulk", "max_packet_size": 512},
        {"address": "0x02", "direction": "out", "transfer_type": "bulk", "max_packet_size": 512},
    ]


def test_collect_live_purple_usb_inventory_skips_transient_usb_devices(monkeypatch):
    from pymobiledevice3.restore import purple

    class DisappearingUsbDevice(FakeUsbDevice):
        def get_active_configuration(self):
            raise RuntimeError("device disappeared")

    monkeypatch.setattr(purple, "usb_find", lambda find_all=True: [DisappearingUsbDevice()])
    monkeypatch.setattr(
        purple,
        "get_string",
        lambda device, index: {
            2: "Apple Inc.",
            3: "Apple Mobile Device (Recovery Mode)",
            4: "SDOM:01 CPID:8120 CPRV:11 CPFM:03 SCEP:01 BDID:08 ECID:0123456789ABCDEF IBFL:3D SIKA:00 SRNM:[PYMD3TEST0]",
        }.get(index, ""),
    )

    summary = collect_live_purple_usb_inventory(ecid="0x123456789abcdef")

    assert summary["mode"] == "no_usb_device"
    assert summary["device_count"] == 0
    assert summary["skipped_devices"] == [
        {
            "vendor_id": "0x05ac",
            "product_id": "0x1281",
            "reason": "usb_summary_failed:RuntimeError",
        }
    ]


def test_summarize_restore_options_exposes_boot_stability_hints():
    summary = summarize_restore_options(
        {
            "RecoveryOSFailureIsFatal": False,
            "RetainRecoveryOS": True,
            "RecoveryOSOnly": False,
            "InstallRecoveryOS": True,
            "ForceInstallRecoveryOS": False,
            "restoreRebootRetryEnabled": True,
            "restoreRebootRetryZone": "post-boot",
        }
    )

    assert summary["stability"] == {
        "recoveryos_required": True,
        "recoveryos_failure_fatal": False,
        "retains_recoveryos": True,
        "recoveryos_only": False,
        "install_recoveryos": True,
        "force_install_recoveryos": False,
        "reboot_retry_enabled": True,
        "reboot_retry_zone": "post-boot",
    }
    assert "RecoveryOS failure is non-fatal; the device may finish without RecoveryOS." in summary["notes"]
    assert "RecoveryOS installation is explicitly requested." in summary["notes"]
    assert "RecoveryOS is retained after restore." in summary["notes"]
