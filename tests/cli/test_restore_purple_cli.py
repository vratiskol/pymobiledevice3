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
    apply_purple_reverse_proxy_restore_options,
    build_purple_reverse_proxy_capabilities,
    build_purple_reverse_proxy_info,
    build_purple_reverse_proxy_port_config,
    build_purple_reverse_proxy_restore_options,
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


def _write_purple_launchd_root(tmp_path, *, socks=2081, ctrl=2082, notify=2084):
    launchd_path = tmp_path / PURPLE_REVERSE_PROXY_LAUNCHD_PATH
    launchd_path.parent.mkdir(parents=True, exist_ok=True)
    with launchd_path.open("wb") as plist_file:
        plistlib.dump(
            {
                "Label": "com.apple.PurpleReverseProxy.ramdisk",
                "ProgramArguments": ["/usr/libexec/PurpleReverseProxy", "--ramdisk"],
                "Sockets": {
                    "ctrl": {"SockServiceName": str(ctrl)},
                    "notify": {"SockServiceName": str(notify)},
                    "socks": {"SockServiceName": str(socks)},
                },
            },
            plist_file,
        )
    return tmp_path


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
    assert PURPLE_REVERSE_PROXY_CATALOG["restore_options"] == {
        "enable": "UsePurpleReverseProxy",
        "disable": "DisableReverseProxy",
        "log_level": "PRPLogLevel",
        "socks_host": "SOCKSHost",
        "socks_port": "SOCKSPort",
        "disable_when_socks_host_is_set": True,
    }
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


def test_build_purple_reverse_proxy_port_config_from_firmware_root(tmp_path):
    root = _write_purple_launchd_root(tmp_path, socks=2081, ctrl=2082, notify=2084)

    config = build_purple_reverse_proxy_port_config(root)

    assert config["source"] == "firmware_root"
    assert config["ports"] == {
        "restore": 62078,
        "socks": 2081,
        "ctrl": 2082,
        "notify": 2084,
    }
    assert config["sources"] == {
        "restore": "default",
        "socks": "firmware_root",
        "ctrl": "firmware_root",
        "notify": "firmware_root",
    }
    assert {port["name"]: port["port"] for port in config["probe_ports"]} == config["ports"]
    assert config["warnings"] == []


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
        "usr/local/bin/restored_update": b"/usr/lib/libReverseProxyDevice.dylib FDRSubmit PRPLogLevel",
        "usr/lib/libFDR.dylib": b"_AMFDRHttpCopyPurpleReverseProxyInformation",
        "usr/lib/libamsupport.dylib": (
            b"UsePurpleReverseProxy DisableReverseProxy _kAMSupportHttpOptionUsePurpleReverseProxy"
        ),
        "System/Library/PrivateFrameworks/AppleRestoreUtils.framework/XPCServices/ARUService.xpc/ARUService": (
            b"DisableReverseProxy SOCKSHost SOCKSPort RestoreOptions com.apple.private.PurpleReverseProxy.allowed"
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
    assert deep["strings"]["restored_update"]["markers"]["PRPLogLevel"] is True
    assert deep["strings"]["aru_service"]["markers"]["SOCKSHost"] is True
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
        "restore_options_evidence": True,
        "entitlement_evidence": True,
        "active_live_probe_required": True,
    }

    capabilities = build_purple_reverse_proxy_capabilities(tmp_path, deep=True)
    capabilities_by_name = {capability["name"]: capability for capability in capabilities["capabilities"]}
    assert capabilities["summary"]["capability_count"] == 8
    assert capabilities["summary"]["firmware_verified_count"] == 6
    assert capabilities["port_config"]["ports"] == {
        "restore": 62078,
        "socks": 1081,
        "ctrl": 1082,
        "notify": 1084,
    }
    assert capabilities_by_name["restoreos_ramdisk_service"]["status"] == "firmware_verified"
    assert capabilities_by_name["restore_options"]["status"] == "firmware_verified"
    assert capabilities_by_name["control_protocol"]["status"] == "firmware_verified"
    assert capabilities_by_name["notify_protocol"]["status"] == "firmware_verified"
    assert capabilities_by_name["proxy_dictionary"]["status"] == "firmware_verified"
    assert capabilities_by_name["socks_data_plane"]["status"] == "implemented"
    assert capabilities_by_name["notify_event_classification"]["status"] == "implemented"
    assert capabilities_by_name["fdr_purple_reverse_proxy"]["status"] == "firmware_verified"


def test_build_purple_reverse_proxy_restore_options_enables_prp():
    result = build_purple_reverse_proxy_restore_options(enable=True, log_level=7)

    assert result["restore_options"] == {
        "UsePurpleReverseProxy": True,
        "PRPLogLevel": 7,
    }
    assert result["evidence"]["fdr"] == "libFDR _AMFDRHttpCopyPurpleReverseProxyInformation"


def test_build_purple_reverse_proxy_restore_options_socks_disables_prp():
    result = build_purple_reverse_proxy_restore_options(socks_host="127.0.0.1", socks_port=4321)

    assert result["restore_options"] == {
        "SOCKSHost": "127.0.0.1",
        "SOCKSPort": 4321,
        "DisableReverseProxy": True,
    }
    assert result["notes"] == ["SOCKSHost disables PurpleReverseProxy according to ARUService RestoreOptions evidence."]


def test_build_purple_reverse_proxy_restore_options_rejects_conflicts():
    with pytest.raises(ValueError, match="mutually exclusive"):
        build_purple_reverse_proxy_restore_options(enable=True, disable=True)


def test_apply_purple_reverse_proxy_restore_options_updates_object():
    class FakeRestoreOptions:
        pass

    options = FakeRestoreOptions()
    apply_purple_reverse_proxy_restore_options(options, {"UsePurpleReverseProxy": True, "PRPLogLevel": 7})

    assert options.UsePurpleReverseProxy is True
    assert options.PRPLogLevel == 7


def test_restore_purple_info_help():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-info", "--help"])

    assert result.exit_code == 0
    assert "--firmware-root" in result.output
    assert "--no-device" in result.output
    assert "--deep" in result.output


def test_restore_purple_capabilities_help():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-capabilities", "--help"])

    assert result.exit_code == 0
    assert "--firmware-root" in result.output
    assert "--deep" in result.output
    assert "--no-live" in result.output
    assert "--timeout" in result.output
    assert "--include-services" in result.output
    assert "--usbmux-address" in result.output


def test_restore_purple_capabilities_prints_matrix_without_live_probe():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-capabilities", "--no-live"])

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["checked"] is True
    assert output["summary"]["capability_count"] == 8
    assert output["live_probe"] == {
        "checked": False,
        "reason": "--no-live was provided.",
    }
    capabilities_by_name = {capability["name"]: capability for capability in output["capabilities"]}
    assert capabilities_by_name["socks_data_plane"]["status"] == "implemented"
    assert capabilities_by_name["notify_event_classification"]["status"] == "implemented"


def test_restore_purple_capabilities_adds_redacted_live_probe(monkeypatch):
    def fake_build_purple_reverse_proxy_capabilities(firmware_root=None, *, deep=False):
        assert firmware_root is None
        assert deep is True
        return {
            "checked": True,
            "experimental": True,
            "firmware": {"checked": True},
            "capabilities": [],
            "summary": {"capability_count": 0},
        }

    async def fake_collect_live_purple_reverse_proxy_probe(**kwargs):
        assert kwargs == {
            "usbmux_address": "/tmp/usbmux",
            "timeout": 0.5,
            "include_services": True,
        }
        return {
            "checked": True,
            "mode": "restored",
            "device_count": 1,
            "devices": [{"index": 0, "mode": "restored"}],
        }

    monkeypatch.setattr(
        restore_cli, "build_purple_reverse_proxy_capabilities", fake_build_purple_reverse_proxy_capabilities
    )
    monkeypatch.setattr(
        restore_cli, "collect_live_purple_reverse_proxy_probe", fake_collect_live_purple_reverse_proxy_probe
    )

    result = CliRunner().invoke(
        __main__.app,
        [
            "restore",
            "purple-capabilities",
            "--deep",
            "--timeout",
            "0.5",
            "--include-services",
            "--usbmux-address",
            "/tmp/usbmux",
        ],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["live_probe"]["mode"] == "restored"
    assert output["summary"]["live_probe_mode"] == "restored"
    assert output["summary"]["live_probe_device_count"] == 1


def test_restore_purple_probe_help():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-probe", "--help"])

    assert result.exit_code == 0
    assert "--timeout" in result.output
    assert "--firmware-root" in result.output
    assert "--include-services" in result.output
    assert "--usbmux-address" in result.output


def test_restore_purple_probe_uses_firmware_ports(tmp_path, monkeypatch):
    root = _write_purple_launchd_root(tmp_path)

    async def fake_collect_live_purple_reverse_proxy_probe(**kwargs):
        assert kwargs["timeout"] == 0.5
        assert kwargs["include_services"] is True
        assert {port["name"]: port["port"] for port in kwargs["ports"]} == {
            "restore": 62078,
            "socks": 2081,
            "ctrl": 2082,
            "notify": 2084,
        }
        return {
            "checked": True,
            "mode": "no_usb_device",
            "device_count": 0,
            "ports": kwargs["ports"],
        }

    monkeypatch.setattr(
        restore_cli, "collect_live_purple_reverse_proxy_probe", fake_collect_live_purple_reverse_proxy_probe
    )

    result = CliRunner().invoke(
        __main__.app,
        [
            "restore",
            "purple-probe",
            "--firmware-root",
            str(root),
            "--timeout",
            "0.5",
            "--include-services",
        ],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["port_config"]["ports"]["socks"] == 2081
    assert output["port_config"]["ports"]["ctrl"] == 2082
    assert output["port_config"]["ports"]["notify"] == 2084


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
    assert "--firmware-root" in result.output
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


def test_restore_purple_control_uses_firmware_ports(tmp_path, monkeypatch):
    root = _write_purple_launchd_root(tmp_path)

    async def fake_run_purple_proxy_control_command(command, **kwargs):
        assert command.value == "WaitSocket"
        assert kwargs["port"] == 2082
        assert kwargs["conn_port"] == 2081
        return {
            "checked": True,
            "experimental": True,
            "command": "WaitSocket",
            "conn_port": kwargs["conn_port"],
            "port": kwargs["port"],
            "reachable": True,
        }

    monkeypatch.setattr(restore_cli, "run_purple_proxy_control_command", fake_run_purple_proxy_control_command)

    result = CliRunner().invoke(
        __main__.app,
        ["restore", "purple-control", "--wait-socket", "--firmware-root", str(root)],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["port"] == 2082
    assert output["conn_port"] == 2081
    assert output["port_config"]["ports"]["ctrl"] == 2082


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
    assert "--firmware-root" in result.output


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


def test_restore_purple_proxy_dict_uses_firmware_ports(tmp_path, monkeypatch):
    root = _write_purple_launchd_root(tmp_path)

    async def fake_run_purple_proxy_control_command(command, **kwargs):
        assert command.value == "Ping"
        assert kwargs["port"] == 2082
        return {
            "checked": True,
            "experimental": True,
            "command": "Ping",
            "port": kwargs["port"],
            "reachable": True,
            "pong": True,
        }

    monkeypatch.setattr(restore_cli, "run_purple_proxy_control_command", fake_run_purple_proxy_control_command)

    result = CliRunner().invoke(
        __main__.app,
        ["restore", "purple-proxy-dict", "--ping", "--firmware-root", str(root)],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["proxy_url"] == "socks://127.0.0.1:2081/"
    assert output["proxy_dictionary"]["SOCKSProxyPort"] == 2081
    assert output["ping"]["port"] == 2082
    assert output["port_config"]["ports"]["socks"] == 2081


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


def test_restore_purple_socks_probe_help():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-socks-probe", "--help"])

    assert result.exit_code == 0
    assert "--timeout" in result.output
    assert "--port" in result.output
    assert "--connect-host" in result.output
    assert "--connect-port" in result.output
    assert "--include-response" in result.output
    assert "--firmware-root" in result.output
    assert "--strict" in result.output


def test_restore_purple_socks_probe_prints_redacted_json(monkeypatch):
    async def fake_run_purple_proxy_socks_probe(**kwargs):
        assert kwargs == {
            "udid": "sensitive-udid",
            "usbmux_address": "/tmp/usbmux",
            "timeout": 0.5,
            "port": 1234,
            "connect_host": "example.test",
            "connect_port": 443,
            "include_response": True,
        }
        return {
            "checked": True,
            "experimental": True,
            "protocol": "SOCKS5",
            "port": 1234,
            "include_response": True,
            "reachable": True,
            "handshake": {
                "accepted": True,
                "response_hex": "0500",
            },
            "connect": {
                "checked": True,
                "target_address_type": "domain",
                "target_port": 443,
                "succeeded": True,
            },
            "summary": {
                "handshake_ok": True,
                "connect_succeeded": True,
                "ok": True,
            },
        }

    monkeypatch.setattr(restore_cli, "run_purple_proxy_socks_probe", fake_run_purple_proxy_socks_probe)

    result = CliRunner().invoke(
        __main__.app,
        [
            "restore",
            "purple-socks-probe",
            "--timeout",
            "0.5",
            "--port",
            "1234",
            "--connect-host",
            "example.test",
            "--connect-port",
            "443",
            "--include-response",
            "--udid",
            "sensitive-udid",
            "--usbmux-address",
            "/tmp/usbmux",
        ],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["handshake"]["accepted"] is True
    assert output["connect"]["target_address_type"] == "domain"
    assert output["summary"]["ok"] is True
    assert "sensitive-udid" not in result.output


def test_restore_purple_socks_probe_uses_firmware_port(tmp_path, monkeypatch):
    root = _write_purple_launchd_root(tmp_path)

    async def fake_run_purple_proxy_socks_probe(**kwargs):
        assert kwargs["port"] == 2081
        return {
            "checked": True,
            "experimental": True,
            "protocol": "SOCKS5",
            "port": kwargs["port"],
            "reachable": True,
            "summary": {
                "handshake_ok": True,
                "connect_succeeded": None,
                "ok": True,
            },
        }

    monkeypatch.setattr(restore_cli, "run_purple_proxy_socks_probe", fake_run_purple_proxy_socks_probe)

    result = CliRunner().invoke(
        __main__.app,
        ["restore", "purple-socks-probe", "--firmware-root", str(root)],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["port"] == 2081
    assert output["port_config"]["ports"]["socks"] == 2081


def test_restore_purple_socks_probe_strict_fails_when_summary_is_not_ok(monkeypatch):
    async def fake_run_purple_proxy_socks_probe(**kwargs):
        return {
            "checked": True,
            "experimental": True,
            "protocol": "SOCKS5",
            "reachable": False,
            "summary": {
                "handshake_ok": False,
                "connect_succeeded": None,
                "ok": False,
            },
        }

    monkeypatch.setattr(restore_cli, "run_purple_proxy_socks_probe", fake_run_purple_proxy_socks_probe)

    result = CliRunner().invoke(__main__.app, ["restore", "purple-socks-probe", "--strict"])

    assert result.exit_code == 1
    assert json.loads(result.output)["summary"]["ok"] is False


def test_restore_purple_restore_options_help():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-restore-options", "--help"])

    assert result.exit_code == 0
    assert "--enable" in result.output
    assert "--disable" in result.output
    assert "--log-level" in result.output
    assert "--socks-host" in result.output
    assert "--socks-port" in result.output


def test_restore_purple_restore_options_prints_patch_json():
    result = CliRunner().invoke(
        __main__.app,
        ["restore", "purple-restore-options", "--enable", "--log-level", "7"],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["restore_options"] == {
        "UsePurpleReverseProxy": True,
        "PRPLogLevel": 7,
    }
    assert output["evidence"]["log_level"] == "restored_update PRPLogLevel"


def test_restore_purple_restore_options_rejects_conflicting_flags():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-restore-options", "--enable", "--disable"])

    assert result.exit_code != 0
    assert "mutually exclusive" in str(result.exception)


def test_restore_update_help_exposes_purple_flags():
    result = CliRunner().invoke(__main__.app, ["restore", "update", "--help"], env={"COLUMNS": "200"})

    assert result.exit_code == 0
    assert "--use-purple-reverse-proxy" in result.output
    assert "--disable-purple-reverse-proxy" in result.output
    assert "--purple-log-level" in result.output
    assert "--purple-socks-host" in result.output
    assert "--purple-socks-port" in result.output


@pytest.mark.asyncio
async def test_restore_update_task_passes_purple_restore_options(monkeypatch):
    calls = []

    class FakeRestore:
        def __init__(self, ipsw, device, tss=None, behavior=None, ignore_fdr=False, purple_restore_options=None):
            calls.append({
                "ipsw": ipsw,
                "device": device,
                "tss": tss,
                "behavior": behavior,
                "ignore_fdr": ignore_fdr,
                "purple_restore_options": purple_restore_options,
            })

        async def update(self):
            calls[-1]["updated"] = True

    monkeypatch.setattr(restore_cli, "Restore", FakeRestore)

    await restore_cli.restore_update_task(
        "fake-device",
        "fake-ipsw",
        {"tss": True},
        erase=False,
        ignore_fdr=False,
        purple_restore_options={"UsePurpleReverseProxy": True},
    )

    assert calls == [
        {
            "ipsw": "fake-ipsw",
            "device": "fake-device",
            "tss": {"tss": True},
            "behavior": restore_cli.Behavior.Update,
            "ignore_fdr": False,
            "purple_restore_options": {"UsePurpleReverseProxy": True},
            "updated": True,
        }
    ]


def test_restore_purple_notify_help():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-notify", "--help"])

    assert result.exit_code == 0
    assert "--register" in result.output
    assert "--set-log-level" in result.output
    assert "--listen-timeout" in result.output
    assert "--max-messages" in result.output
    assert "--expect-response" in result.output
    assert "--firmware-root" in result.output


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


def test_restore_purple_notify_uses_firmware_port(tmp_path, monkeypatch):
    root = _write_purple_launchd_root(tmp_path)

    async def fake_run_purple_proxy_notify_command(command, **kwargs):
        assert command.value == "RegisterNotify"
        assert kwargs["port"] == 2084
        return {
            "checked": True,
            "experimental": True,
            "command": "RegisterNotify",
            "port": kwargs["port"],
            "reachable": True,
            "sent": True,
        }

    monkeypatch.setattr(restore_cli, "run_purple_proxy_notify_command", fake_run_purple_proxy_notify_command)

    result = CliRunner().invoke(
        __main__.app,
        ["restore", "purple-notify", "--register", "--firmware-root", str(root)],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["port"] == 2084
    assert output["port_config"]["ports"]["notify"] == 2084


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


def test_restore_purple_session_help():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-session", "--help"], env={"COLUMNS": "200"})

    assert result.exit_code == 0
    assert "--control-port" in result.output
    assert "--notify-port" in result.output
    assert "--protocol-version" in result.output
    assert "--conn-port" in result.output
    assert "--log-level" in result.output
    assert "--listen-timeout" in result.output
    assert "--max-messages" in result.output
    assert "--probe-socks" in result.output
    assert "--socks-connect-host" in result.output
    assert "--socks-connect-port" in result.output
    assert "--firmware-root" in result.output
    assert "--include-services" in result.output
    assert "--strict" in result.output


def test_restore_purple_session_prints_orchestrated_json(monkeypatch):
    async def fake_collect_live_purple_reverse_proxy_probe(**kwargs):
        assert kwargs == {
            "usbmux_address": "/tmp/usbmux",
            "timeout": 0.5,
            "include_services": True,
        }
        return {
            "checked": True,
            "mode": "restored",
            "device_count": 1,
            "devices": [
                {
                    "index": 0,
                    "mode": "restored",
                    "ports": [
                        {"name": "restore", "port": 62078, "reachable": True},
                        {"name": "socks", "port": 1081, "reachable": False},
                        {"name": "ctrl", "port": 1082, "reachable": True},
                        {"name": "notify", "port": 1084, "reachable": True},
                    ],
                }
            ],
        }

    async def fake_run_purple_proxy_session(**kwargs):
        assert kwargs == {
            "udid": "sensitive-udid",
            "usbmux_address": "/tmp/usbmux",
            "timeout": 0.5,
            "control_port": 1234,
            "notify_port": 1235,
            "protocol_version": 2,
            "conn_port": 4321,
            "log_level": 7,
            "url": "https://example.test/path",
            "proxy_host": "127.0.0.1",
            "include_response": True,
            "listen_timeout": 0.2,
            "max_messages": 2,
            "probe_socks": True,
            "socks_connect_host": "example.test",
            "socks_connect_port": 443,
        }
        return {
            "checked": True,
            "experimental": True,
            "phases": {
                "set_log_level": {"checked": True, "command": "SetLogLevel", "reachable": True, "sent": True},
                "register_notify": {
                    "checked": True,
                    "command": "RegisterNotify",
                    "reachable": True,
                    "sent": True,
                    "messages": [{"SerialNumber": "<redacted>", "Event": "ProxyOnline"}],
                },
                "begin_control": {"checked": True, "command": "BeginCtrl", "reachable": True},
                "ping": {"checked": True, "command": "Ping", "reachable": True, "pong": True},
                "wait_socket": {"checked": True, "command": "WaitSocket", "reachable": True},
                "proxy_dictionary": {"checked": True, "proxy_url": "socks://127.0.0.1:4321/"},
                "socks_probe": {
                    "checked": True,
                    "protocol": "SOCKS5",
                    "reachable": True,
                    "summary": {
                        "handshake_ok": True,
                        "connect_succeeded": True,
                        "ok": True,
                    },
                },
            },
            "summary": {
                "control_reachable": True,
                "ping_pong": True,
                "wait_socket_reachable": True,
                "notify_registered": True,
                "set_log_level_sent": True,
                "socks_probe_ok": True,
                "proxy_dictionary_ready": True,
                "ok": True,
            },
        }

    monkeypatch.setattr(
        restore_cli, "collect_live_purple_reverse_proxy_probe", fake_collect_live_purple_reverse_proxy_probe
    )
    monkeypatch.setattr(restore_cli, "run_purple_proxy_session", fake_run_purple_proxy_session)

    result = CliRunner().invoke(
        __main__.app,
        [
            "restore",
            "purple-session",
            "--timeout",
            "0.5",
            "--control-port",
            "1234",
            "--notify-port",
            "1235",
            "--protocol-version",
            "2",
            "--conn-port",
            "4321",
            "--log-level",
            "7",
            "--url",
            "https://example.test/path",
            "--proxy-host",
            "127.0.0.1",
            "--include-response",
            "--listen-timeout",
            "0.2",
            "--max-messages",
            "2",
            "--include-services",
            "--probe-socks",
            "--socks-connect-host",
            "example.test",
            "--socks-connect-port",
            "443",
            "--udid",
            "sensitive-udid",
            "--usbmux-address",
            "/tmp/usbmux",
        ],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["phases"]["probe"]["mode"] == "restored"
    assert output["phases"]["register_notify"]["messages"] == [{"SerialNumber": "<redacted>", "Event": "ProxyOnline"}]
    assert output["phases"]["socks_probe"]["summary"]["connect_succeeded"] is True
    assert output["summary"]["ok"] is True
    assert output["summary"]["socks_probe_ok"] is True
    assert output["summary"]["probe_mode"] == "restored"
    assert output["summary"]["probe_reachable_ports"] == ["ctrl", "notify", "restore"]
    assert "sensitive-udid" not in result.output


def test_restore_purple_session_uses_firmware_ports(tmp_path, monkeypatch):
    root = _write_purple_launchd_root(tmp_path)

    async def fake_collect_live_purple_reverse_proxy_probe(**kwargs):
        assert {port["name"]: port["port"] for port in kwargs["ports"]} == {
            "restore": 62078,
            "socks": 2081,
            "ctrl": 2082,
            "notify": 2084,
        }
        return {
            "checked": True,
            "mode": "restored",
            "device_count": 1,
            "devices": [],
        }

    async def fake_run_purple_proxy_session(**kwargs):
        assert kwargs["control_port"] == 2082
        assert kwargs["notify_port"] == 2084
        assert kwargs["conn_port"] == 2081
        return {
            "checked": True,
            "experimental": True,
            "phases": {
                "set_log_level": {"checked": False, "reason": "--log-level was not provided."},
                "register_notify": {"checked": True, "reachable": True},
                "begin_control": {"checked": True, "reachable": True},
                "ping": {"checked": True, "reachable": True, "pong": True},
                "wait_socket": {"checked": True, "reachable": True, "conn_port": 2081},
                "proxy_dictionary": {"checked": True, "proxy_url": "socks://127.0.0.1:2081/"},
                "socks_probe": {"checked": False, "reason": "--probe-socks was not provided."},
            },
            "summary": {
                "control_reachable": True,
                "ping_pong": True,
                "wait_socket_reachable": True,
                "notify_registered": True,
                "set_log_level_sent": None,
                "socks_probe_ok": None,
                "proxy_dictionary_ready": True,
                "ok": True,
            },
        }

    monkeypatch.setattr(
        restore_cli, "collect_live_purple_reverse_proxy_probe", fake_collect_live_purple_reverse_proxy_probe
    )
    monkeypatch.setattr(restore_cli, "run_purple_proxy_session", fake_run_purple_proxy_session)

    result = CliRunner().invoke(
        __main__.app,
        ["restore", "purple-session", "--firmware-root", str(root)],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["phases"]["wait_socket"]["conn_port"] == 2081
    assert output["port_config"]["ports"]["ctrl"] == 2082
    assert output["port_config"]["ports"]["notify"] == 2084


def test_restore_purple_session_strict_fails_when_summary_is_not_ok(monkeypatch):
    async def fake_collect_live_purple_reverse_proxy_probe(**kwargs):
        return {
            "checked": True,
            "mode": "no_usb_device",
            "device_count": 0,
        }

    async def fake_run_purple_proxy_session(**kwargs):
        return {
            "checked": True,
            "experimental": True,
            "phases": {
                "set_log_level": {"checked": False, "reason": "--log-level was not provided."},
                "register_notify": {"checked": True, "reachable": False},
                "begin_control": {"checked": True, "reachable": False},
                "ping": {"checked": True, "reachable": False},
                "wait_socket": {"checked": True, "reachable": False},
                "proxy_dictionary": {"checked": True},
            },
            "summary": {
                "control_reachable": False,
                "ping_pong": False,
                "wait_socket_reachable": False,
                "notify_registered": False,
                "set_log_level_sent": None,
                "proxy_dictionary_ready": True,
                "ok": False,
            },
        }

    monkeypatch.setattr(
        restore_cli, "collect_live_purple_reverse_proxy_probe", fake_collect_live_purple_reverse_proxy_probe
    )
    monkeypatch.setattr(restore_cli, "run_purple_proxy_session", fake_run_purple_proxy_session)

    result = CliRunner().invoke(__main__.app, ["restore", "purple-session", "--strict"])

    assert result.exit_code == 1
    assert json.loads(result.output)["summary"]["ok"] is False


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
