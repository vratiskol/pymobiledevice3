import hashlib
import json
import plistlib
import struct

import pytest
from typer.testing import CliRunner

from pymobiledevice3 import __main__
from pymobiledevice3.cli import restore as restore_cli
from pymobiledevice3.restore.purple import (
    PURPLE_REVERSE_PROXY_CATALOG,
    PURPLE_REVERSE_PROXY_LAUNCHD_PATH,
    build_purple_reverse_proxy_info,
    collect_live_purple_reverse_proxy_probe,
    parse_purple_reverse_proxy_launchd,
)

TEST_UUID = bytes.fromhex("00112233445566778899aabbccddeeff")


class FakeMuxDevice:
    serial = "fake-sensitive-serial"
    connection_type = "USB"
    is_usb = True


class FakeService:
    def __init__(self, response=None):
        self.response = response or {}
        self.closed = False

    async def start(self):
        return None

    async def send_recv_plist(self, request):
        assert request == {"Request": "QueryType"}
        return self.response

    async def close(self):
        self.closed = True


def _macho64_with_uuid(uuid: bytes, payload: bytes = b"") -> bytes:
    header = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,
        0x0100000C,
        0,
        2,
        1,
        24,
        0,
        0,
    )
    uuid_command = struct.pack("<II", 0x1B, 24) + uuid
    return header + uuid_command + payload


def test_purple_reverse_proxy_catalog_exposes_restoreos_identifiers():
    assert PURPLE_REVERSE_PROXY_CATALOG["availability"] == "restoreos_ramdisk"
    assert PURPLE_REVERSE_PROXY_CATALOG["launchd_label"] == "com.apple.PurpleReverseProxy.ramdisk"
    assert "com.apple.PurpleReverseProxy.transaction" in PURPLE_REVERSE_PROXY_CATALOG["lockdown_services"]
    assert PURPLE_REVERSE_PROXY_CATALOG["restore_options"]["enable"] == "UsePurpleReverseProxy"
    assert PURPLE_REVERSE_PROXY_CATALOG["notify_commands"] == ["RegisterNotify", "SetLogLevel"]
    assert PURPLE_REVERSE_PROXY_CATALOG["proxy_dictionary"] == {
        "function": "CopyProxyDictionaryWithOptions",
        "test_reachability_option": "TestReachability",
        "ping_command": "Ping",
        "pong_response": "Pong",
        "default_socks_host": "127.0.0.1",
        "default_socks_port": 1081,
    }


def test_parse_purple_reverse_proxy_launchd(tmp_path):
    plist_path = tmp_path / "com.apple.PurpleReverseProxy.ramdisk.plist"
    with plist_path.open("wb") as plist_file:
        plistlib.dump(
            {
                "EnablePressuredExit": True,
                "EnableTransactions": True,
                "Label": "com.apple.PurpleReverseProxy.ramdisk",
                "POSIXSpawnType": "Adaptive",
                "ProgramArguments": ["/usr/libexec/PurpleReverseProxy", "--ramdisk"],
                "Sockets": {
                    "ctrl": {"SockFamily": "IPv4v6", "SockServiceName": "1082"},
                    "notify": {
                        "SockFamily": "IPv4",
                        "SockNodeName": "127.0.0.1",
                        "SockServiceName": "1084",
                    },
                    "socks": {"SockServiceName": "1081"},
                },
                "StandardErrorPath": "/dev/console",
                "StandardOutPath": "/dev/console",
            },
            plist_file,
        )

    parsed = parse_purple_reverse_proxy_launchd(plist_path)

    assert parsed["label"] == "com.apple.PurpleReverseProxy.ramdisk"
    assert parsed["program_arguments"] == ["/usr/libexec/PurpleReverseProxy", "--ramdisk"]
    assert parsed["sockets"]["ctrl"]["SockServiceName"] == "1082"
    assert parsed["sockets"]["notify"]["SockNodeName"] == "127.0.0.1"
    assert parsed["sockets"]["socks"]["SockServiceName"] == "1081"


def test_build_purple_reverse_proxy_info_from_firmware_root(tmp_path):
    launchd_path = tmp_path / PURPLE_REVERSE_PROXY_LAUNCHD_PATH
    launchd_path.parent.mkdir(parents=True)
    with launchd_path.open("wb") as plist_file:
        plistlib.dump(
            {
                "Label": "com.apple.PurpleReverseProxy.ramdisk",
                "ProgramArguments": ["/usr/libexec/PurpleReverseProxy", "--ramdisk"],
                "Sockets": {"socks": {"SockServiceName": "1081"}},
            },
            plist_file,
        )

    (tmp_path / "usr/libexec").mkdir(parents=True)
    (tmp_path / "usr/libexec/PurpleReverseProxy").touch()
    (tmp_path / "usr/lib").mkdir(parents=True, exist_ok=True)
    (tmp_path / "usr/lib/libReverseProxyDevice.dylib").touch()

    info = build_purple_reverse_proxy_info(firmware_root=tmp_path)

    assert info["firmware_root"]["launchd_plist"]["exists"] is True
    assert info["firmware_root"]["launchd_plist"]["plist"]["sockets"]["socks"]["SockServiceName"] == "1081"
    assert info["firmware_root"]["executable"]["is_file"] is True
    assert info["firmware_root"]["device_library"]["is_file"] is True


def test_build_purple_reverse_proxy_info_deep_from_firmware_root(tmp_path):
    launchd_path = tmp_path / PURPLE_REVERSE_PROXY_LAUNCHD_PATH
    launchd_path.parent.mkdir(parents=True)
    with launchd_path.open("wb") as plist_file:
        plistlib.dump(
            {
                "Label": "com.apple.PurpleReverseProxy.ramdisk",
                "ProgramArguments": ["/usr/libexec/PurpleReverseProxy", "--ramdisk"],
                "Sockets": {
                    "ctrl": {"SockServiceName": "1082"},
                    "notify": {"SockServiceName": "1084"},
                    "socks": {"SockServiceName": "1081"},
                },
            },
            plist_file,
        )

    purple_proxy = _macho64_with_uuid(
        TEST_UUID,
        b"HelloCtrl BeginCtrl CtrlProtoVersion WaitSocket NotifyConn RegisterNotify SetLogLevel Level "
        b"com.apple.private.PurpleReverseProxy.allowed",
    )
    files = {
        "usr/libexec/PurpleReverseProxy": purple_proxy,
        "usr/lib/libReverseProxyDevice.dylib": (
            b"CopyProxyDictionaryWithOptions TestReachability Ping Pong socks://127.0.0.1:%d/ "
            b"_kCFStreamPropertySOCKSProxyHost _kCFStreamPropertySOCKSProxyPort "
            b"RegisterNotify SetLogLevel Level RPSocketReadDictionary com.apple.PurpleReverseProxy.RPSocket"
        ),
        "usr/local/bin/restored_update": b"/usr/lib/libReverseProxyDevice.dylib FDRSubmit",
        "usr/lib/libFDR.dylib": b"_AMFDRHttpCopyPurpleReverseProxyInformation",
        "usr/lib/libamsupport.dylib": (
            b"UsePurpleReverseProxy DisableReverseProxy _kAMSupportHttpOptionUsePurpleReverseProxy"
        ),
        "System/Library/PrivateFrameworks/AppleRestoreUtils.framework/XPCServices/ARUService.xpc/ARUService": (
            b"com.apple.private.PurpleReverseProxy.allowed"
        ),
    }
    for relative_path, data in files.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    info = build_purple_reverse_proxy_info(firmware_root=tmp_path, deep=True)
    deep = info["deep"]

    assert deep["files"]["purple_reverse_proxy"]["sha256"] == hashlib.sha256(purple_proxy).hexdigest()
    assert deep["files"]["purple_reverse_proxy"]["macho"]["uuids"] == [{"uuid": "00112233-4455-6677-8899-aabbccddeeff"}]
    assert deep["strings"]["purple_reverse_proxy"]["markers"]["HelloCtrl"] is True
    assert deep["strings"]["purple_reverse_proxy"]["markers"]["RegisterNotify"] is True
    assert deep["strings"]["device_library"]["markers"]["SetLogLevel"] is True
    assert deep["strings"]["device_library"]["markers"]["CopyProxyDictionaryWithOptions"] is True
    assert deep["strings"]["device_library"]["markers"]["Ping"] is True
    assert deep["strings"]["device_library"]["markers"]["Pong"] is True
    assert deep["strings"]["amsupport_library"]["markers"]["UsePurpleReverseProxy"] is True
    assert deep["strings"]["fdr_library"]["markers"]["_AMFDRHttpCopyPurpleReverseProxyInformation"] is True
    assert deep["entitlements"]["com.apple.private.PurpleReverseProxy.allowed"]["present"] is True
    assert deep["summary"] == {
        "available_in_restoreos_ramdisk": True,
        "host_option_evidence": True,
        "disable_option_evidence": True,
        "fdr_evidence": True,
        "control_protocol_evidence": True,
        "notify_protocol_evidence": True,
        "proxy_dictionary_evidence": True,
        "entitlement_evidence": True,
        "active_live_probe_required": True,
    }


def test_restore_purple_info_help():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-info", "--help"])

    assert result.exit_code == 0
    assert "--firmware-root" in result.output
    assert "--no-device" in result.output
    assert "--deep" in result.output


def test_restore_purple_probe_help():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-probe", "--help"])

    assert result.exit_code == 0
    assert "--timeout" in result.output
    assert "--include-services" in result.output
    assert "--usbmux-address" in result.output


def test_restore_purple_control_help():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-control", "--help"])

    assert result.exit_code == 0
    assert "--hello" in result.output
    assert "--begin" in result.output
    assert "--wait-socket" in result.output
    assert "--ping" in result.output
    assert "--timeout" in result.output
    assert "--conn-port" in result.output
    assert "--include-response" in result.output
    assert "--strict" in result.output


def test_restore_purple_control_requires_operation():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-control"])

    assert result.exit_code != 0
    assert "Choose exactly one control operation" in str(result.exception)


def test_restore_purple_control_rejects_multiple_operations():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-control", "--hello", "--begin"])

    assert result.exit_code != 0
    assert "Choose exactly one control operation" in str(result.exception)


def test_restore_purple_control_hello_prints_redacted_json(monkeypatch):
    async def fake_run_purple_proxy_control_command(command, **kwargs):
        assert command.value == "HelloCtrl"
        assert kwargs == {
            "udid": "sensitive-udid",
            "usbmux_address": "/tmp/usbmux",
            "timeout": 0.5,
            "port": 1234,
            "protocol_version": 2,
            "conn_port": 1081,
            "include_response": True,
        }
        return {
            "checked": True,
            "experimental": True,
            "command": "HelloCtrl",
            "reachable": True,
            "response": {"SerialNumber": "<redacted>", "Status": "OK"},
        }

    monkeypatch.setattr(restore_cli, "run_purple_proxy_control_command", fake_run_purple_proxy_control_command)

    result = CliRunner().invoke(
        __main__.app,
        [
            "restore",
            "purple-control",
            "--hello",
            "--timeout",
            "0.5",
            "--port",
            "1234",
            "--protocol-version",
            "2",
            "--include-response",
            "--udid",
            "sensitive-udid",
            "--usbmux-address",
            "/tmp/usbmux",
        ],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["reachable"] is True
    assert output["response"] == {"SerialNumber": "<redacted>", "Status": "OK"}
    assert "sensitive-udid" not in result.output


def test_restore_purple_control_begin_prints_json(monkeypatch):
    async def fake_run_purple_proxy_control_command(command, **kwargs):
        assert command.value == "BeginCtrl"
        assert kwargs["protocol_version"] == 3
        return {
            "checked": True,
            "experimental": True,
            "command": "BeginCtrl",
            "protocol_version": 3,
            "reachable": True,
        }

    monkeypatch.setattr(restore_cli, "run_purple_proxy_control_command", fake_run_purple_proxy_control_command)

    result = CliRunner().invoke(__main__.app, ["restore", "purple-control", "--begin", "--protocol-version", "3"])

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["command"] == "BeginCtrl"
    assert output["protocol_version"] == 3
    assert output["reachable"] is True


def test_restore_purple_control_wait_socket_prints_json(monkeypatch):
    async def fake_run_purple_proxy_control_command(command, **kwargs):
        assert command.value == "WaitSocket"
        assert kwargs["conn_port"] == 4321
        return {
            "checked": True,
            "experimental": True,
            "command": "WaitSocket",
            "conn_port": 4321,
            "reachable": True,
        }

    monkeypatch.setattr(restore_cli, "run_purple_proxy_control_command", fake_run_purple_proxy_control_command)

    result = CliRunner().invoke(__main__.app, ["restore", "purple-control", "--wait-socket", "--conn-port", "4321"])

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["command"] == "WaitSocket"
    assert output["conn_port"] == 4321
    assert output["reachable"] is True


def test_restore_purple_control_ping_prints_json(monkeypatch):
    async def fake_run_purple_proxy_control_command(command, **kwargs):
        assert command.value == "Ping"
        return {
            "checked": True,
            "experimental": True,
            "command": "Ping",
            "reachable": True,
            "pong": True,
        }

    monkeypatch.setattr(restore_cli, "run_purple_proxy_control_command", fake_run_purple_proxy_control_command)

    result = CliRunner().invoke(__main__.app, ["restore", "purple-control", "--ping"])

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["command"] == "Ping"
    assert output["pong"] is True


def test_restore_purple_control_strict_fails_when_unreachable(monkeypatch):
    async def fake_run_purple_proxy_control_command(command, **kwargs):
        return {
            "checked": True,
            "experimental": True,
            "command": "HelloCtrl",
            "reachable": False,
            "error_type": "OSError",
        }

    monkeypatch.setattr(restore_cli, "run_purple_proxy_control_command", fake_run_purple_proxy_control_command)

    result = CliRunner().invoke(__main__.app, ["restore", "purple-control", "--hello", "--strict"])

    assert result.exit_code == 1
    assert json.loads(result.output)["reachable"] is False


def test_restore_purple_control_ping_strict_fails_when_not_pong(monkeypatch):
    async def fake_run_purple_proxy_control_command(command, **kwargs):
        return {
            "checked": True,
            "experimental": True,
            "command": "Ping",
            "reachable": True,
            "pong": False,
        }

    monkeypatch.setattr(restore_cli, "run_purple_proxy_control_command", fake_run_purple_proxy_control_command)

    result = CliRunner().invoke(__main__.app, ["restore", "purple-control", "--ping", "--strict"])

    assert result.exit_code == 1
    assert json.loads(result.output)["pong"] is False


def test_restore_purple_proxy_dict_help():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-proxy-dict", "--help"])

    assert result.exit_code == 0
    assert "--url" in result.output
    assert "--socks-port" in result.output
    assert "--proxy-host" in result.output
    assert "--no-test-reachability" in result.output
    assert "--ping" in result.output


def test_restore_purple_proxy_dict_prints_model_json():
    result = CliRunner().invoke(
        __main__.app,
        [
            "restore",
            "purple-proxy-dict",
            "--url",
            "https://example.test/path",
            "--socks-port",
            "4321",
            "--no-test-reachability",
        ],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output == {
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


def test_restore_purple_proxy_dict_ping_prints_redacted_json(monkeypatch):
    async def fake_run_purple_proxy_control_command(command, **kwargs):
        assert command.value == "Ping"
        assert kwargs == {
            "udid": "sensitive-udid",
            "usbmux_address": "/tmp/usbmux",
            "timeout": 0.5,
            "port": 1234,
            "include_response": True,
        }
        return {
            "checked": True,
            "experimental": True,
            "command": "Ping",
            "reachable": True,
            "pong": True,
            "response": {"SerialNumber": "<redacted>", "Command": "Pong"},
        }

    monkeypatch.setattr(restore_cli, "run_purple_proxy_control_command", fake_run_purple_proxy_control_command)

    result = CliRunner().invoke(
        __main__.app,
        [
            "restore",
            "purple-proxy-dict",
            "--ping",
            "--timeout",
            "0.5",
            "--control-port",
            "1234",
            "--include-response",
            "--udid",
            "sensitive-udid",
            "--usbmux-address",
            "/tmp/usbmux",
        ],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["ping"]["pong"] is True
    assert output["ping"]["response"] == {"SerialNumber": "<redacted>", "Command": "Pong"}
    assert "sensitive-udid" not in result.output


def test_restore_purple_proxy_dict_strict_fails_when_ping_is_not_pong(monkeypatch):
    async def fake_run_purple_proxy_control_command(command, **kwargs):
        return {
            "checked": True,
            "experimental": True,
            "command": "Ping",
            "reachable": True,
            "pong": False,
        }

    monkeypatch.setattr(restore_cli, "run_purple_proxy_control_command", fake_run_purple_proxy_control_command)

    result = CliRunner().invoke(__main__.app, ["restore", "purple-proxy-dict", "--ping", "--strict"])

    assert result.exit_code == 1
    assert json.loads(result.output)["ping"]["pong"] is False


def test_restore_purple_notify_help():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-notify", "--help"])

    assert result.exit_code == 0
    assert "--register" in result.output
    assert "--set-log-level" in result.output
    assert "--listen-timeout" in result.output
    assert "--max-messages" in result.output
    assert "--expect-response" in result.output


def test_restore_purple_notify_requires_operation():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-notify"])

    assert result.exit_code != 0
    assert "Choose exactly one notify operation" in str(result.exception)


def test_restore_purple_notify_rejects_multiple_operations():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-notify", "--register", "--set-log-level", "7"])

    assert result.exit_code != 0
    assert "Choose exactly one notify operation" in str(result.exception)


def test_restore_purple_notify_register_prints_redacted_json(monkeypatch):
    async def fake_run_purple_proxy_notify_command(command, **kwargs):
        assert command.value == "RegisterNotify"
        assert kwargs == {
            "level": None,
            "udid": "sensitive-udid",
            "usbmux_address": "/tmp/usbmux",
            "timeout": 0.5,
            "port": 1234,
            "include_response": True,
            "expect_response": False,
            "listen_timeout": 0.2,
            "max_messages": 2,
        }
        return {
            "checked": True,
            "experimental": True,
            "command": "RegisterNotify",
            "reachable": True,
            "sent": True,
            "messages": [{"SerialNumber": "<redacted>", "Event": "ProxyOnline"}],
        }

    monkeypatch.setattr(restore_cli, "run_purple_proxy_notify_command", fake_run_purple_proxy_notify_command)

    result = CliRunner().invoke(
        __main__.app,
        [
            "restore",
            "purple-notify",
            "--register",
            "--timeout",
            "0.5",
            "--port",
            "1234",
            "--include-response",
            "--listen-timeout",
            "0.2",
            "--max-messages",
            "2",
            "--udid",
            "sensitive-udid",
            "--usbmux-address",
            "/tmp/usbmux",
        ],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["command"] == "RegisterNotify"
    assert output["reachable"] is True
    assert output["messages"] == [{"SerialNumber": "<redacted>", "Event": "ProxyOnline"}]
    assert "sensitive-udid" not in result.output


def test_restore_purple_notify_set_log_level_prints_json(monkeypatch):
    async def fake_run_purple_proxy_notify_command(command, **kwargs):
        assert command.value == "SetLogLevel"
        assert kwargs["level"] == 7
        return {
            "checked": True,
            "experimental": True,
            "command": "SetLogLevel",
            "level": 7,
            "reachable": True,
            "sent": True,
        }

    monkeypatch.setattr(restore_cli, "run_purple_proxy_notify_command", fake_run_purple_proxy_notify_command)

    result = CliRunner().invoke(__main__.app, ["restore", "purple-notify", "--set-log-level", "7"])

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["command"] == "SetLogLevel"
    assert output["level"] == 7
    assert output["sent"] is True


def test_restore_purple_notify_strict_fails_when_unreachable(monkeypatch):
    async def fake_run_purple_proxy_notify_command(command, **kwargs):
        return {
            "checked": True,
            "experimental": True,
            "command": "RegisterNotify",
            "reachable": False,
            "error_type": "OSError",
        }

    monkeypatch.setattr(restore_cli, "run_purple_proxy_notify_command", fake_run_purple_proxy_notify_command)

    result = CliRunner().invoke(__main__.app, ["restore", "purple-notify", "--register", "--strict"])

    assert result.exit_code == 1
    assert json.loads(result.output)["reachable"] is False


@pytest.mark.asyncio
async def test_collect_live_purple_reverse_proxy_probe_without_usb_device(monkeypatch):
    async def fake_list_devices(usbmux_address=None):
        return []

    from pymobiledevice3.restore import purple

    monkeypatch.setattr(purple.usbmux, "list_devices", fake_list_devices)

    result = await collect_live_purple_reverse_proxy_probe()

    assert result["mode"] == "no_usb_device"
    assert result["device_count"] == 0


@pytest.mark.asyncio
async def test_collect_live_purple_reverse_proxy_probe_restored_ports_are_redacted(monkeypatch):
    async def fake_list_devices(usbmux_address=None):
        return [FakeMuxDevice()]

    async def fake_create_using_usbmux(serial, port, connection_type=None, usbmux_address=None):
        assert serial == "fake-sensitive-serial"
        if port == 1081:
            raise OSError("closed")
        response = {}
        if port == 62078:
            response = {"Type": "com.apple.mobile.restored", "RestoreProtocolVersion": 15}
        return FakeService(response)

    from pymobiledevice3.restore import purple

    monkeypatch.setattr(purple.usbmux, "list_devices", fake_list_devices)
    monkeypatch.setattr(purple.ServiceConnection, "create_using_usbmux", fake_create_using_usbmux)

    result = await collect_live_purple_reverse_proxy_probe(timeout=0.1)

    assert result["mode"] == "restored"
    assert result["device_count"] == 1
    device = result["devices"][0]
    assert device["query_type"] == {
        "reachable": True,
        "type": "com.apple.mobile.restored",
        "restore_protocol_version": 15,
    }
    ports_by_name = {port["name"]: port for port in device["ports"]}
    assert ports_by_name["restore"]["reachable"] is True
    assert ports_by_name["ctrl"]["reachable"] is True
    assert ports_by_name["notify"]["reachable"] is True
    assert ports_by_name["socks"]["reachable"] is False
    assert ports_by_name["socks"]["error_type"] == "OSError"
    assert device["lockdown_services"] == {
        "checked": False,
        "reason": "--include-services was not provided.",
    }
    assert "fake-sensitive-serial" not in repr(result)
