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
    build_purple_proxy_dictionary,
    classify_purple_proxy_notify_message,
    is_purple_proxy_pong_response,
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
        assert endianity == ">"
        return self.responses.pop(0)

    async def send_plist(self, message, endianity=">", fmt=plistlib.FMT_XML):
        assert endianity == ">"
        assert fmt == plistlib.FMT_XML
        self.sent.append(message)

    async def recvall(self, size):
        response = self.responses.pop(0)
        assert len(response) == size
        return response

    async def sendall(self, payload):
        self.sent.append(payload)

    async def close(self):
        self.closed = True


class FakePurpleProxyClient:
    def __init__(self, response=None, messages=None):
        self.response = response or {}
        self.messages = list(messages or [])
        self.sent = []
        self.closed = False

    async def hello_control(self, protocol_version=1):
        assert protocol_version == 2
        return self.response

    async def begin_control(self, protocol_version=1):
        assert protocol_version == 2
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

    assert await client.begin_control(protocol_version=2, CtrlConn=True) == {"Status": "OK"}
    assert await client.wait_socket(conn_port=1081) == {"SocketReady": True}
    assert await client.send_ping() == {"Pong": True}

    assert service.sent == [
        {"Command": "BeginCtrl", "CtrlProtoVersion": 2, "CtrlConn": True},
        {"Command": "WaitSocket", "ConnPort": 1081},
        {"Command": "Ping"},
    ]


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
async def test_run_purple_proxy_control_command_wait_socket_sends_conn_port(monkeypatch):
    fake_client = FakePurpleProxyClient({"SocketReady": True})

    async def fake_connect_control(udid=None, **kwargs):
        return fake_client

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_control", staticmethod(fake_connect_control))

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
        "reachable": True,
        "response_keys": ["SocketReady"],
        "response": {"SocketReady": True},
    }
    assert fake_client.closed is True


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
        return PurpleProxyClient(service)

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
    assert service.sent == [b"\x05\x01\x00"]
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
    service = FakeService(responses=[b"\x05\x00", b"\x05\x00\x00\x01", b"\x00\x00\x00\x00", b"\x04\xd2"])

    async def fake_connect_socks(udid=None, **kwargs):
        return PurpleProxyClient(service)

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
    assert service.sent == [
        b"\x05\x01\x00",
        b"\x05\x01\x00\x03\x0cexample.test\x01\xbb",
    ]
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
    calls = []

    async def fake_connect_notify(udid=None, **kwargs):
        calls.append({"kind": "notify", "udid": udid, **kwargs})
        return notify_client

    async def fake_connect_control(udid=None, **kwargs):
        calls.append({"kind": "control", "udid": udid, **kwargs})
        return control_client

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_notify", staticmethod(fake_connect_notify))
    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_control", staticmethod(fake_connect_control))

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
        "control_reachable": True,
        "ping_pong": True,
        "wait_socket_reachable": True,
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
    assert phases["begin_control"]["response"] == {"Command": "Pong", "SerialNumber": "<redacted>"}
    assert phases["ping"]["pong"] is True
    assert phases["wait_socket"]["conn_port"] == 4321
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
    ]
    assert notify_client.closed is True
    assert control_client.closed is True
    assert "sensitive" not in repr(result)


@pytest.mark.asyncio
async def test_run_purple_proxy_session_can_include_identifiers(monkeypatch):
    notify_client = FakePurpleProxyClient(messages=[{"Event": "ProxyOnline", "SerialNumber": "sensitive"}])
    control_client = FakePurpleProxyClient({"Command": "Pong", "SerialNumber": "sensitive"})

    async def fake_connect_notify(udid=None, **kwargs):
        return notify_client

    async def fake_connect_control(udid=None, **kwargs):
        return control_client

    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_notify", staticmethod(fake_connect_notify))
    monkeypatch.setattr(purple_proxy.PurpleProxyClient, "connect_control", staticmethod(fake_connect_control))

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
    assert result["phases"]["begin_control"]["response"] == {"Command": "Pong", "SerialNumber": "sensitive"}


@pytest.mark.asyncio
async def test_run_purple_proxy_session_can_require_socks_probe(monkeypatch):
    notify_client = FakePurpleProxyClient()
    control_client = FakePurpleProxyClient({"Command": "Pong"})
    socks_calls = []

    async def fake_connect_notify(udid=None, **kwargs):
        return notify_client

    async def fake_connect_control(udid=None, **kwargs):
        return control_client

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
            "connect_host": "example.test",
            "connect_port": 443,
            "connection_type": "USB",
            "include_response": False,
        }
    ]
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
    assert result["phases"]["begin_control"]["reachable"] is False
    assert result["phases"]["begin_control"]["error_type"] == "OSError"


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
