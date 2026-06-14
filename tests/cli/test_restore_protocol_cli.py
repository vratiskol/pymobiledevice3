import asyncio
import json
import plistlib

from typer.testing import CliRunner

from pymobiledevice3 import __main__
from pymobiledevice3.cli import restore as restore_cli
from pymobiledevice3.restore import protocol


class FakeMuxDevice:
    devid = 42
    serial = "sensitive-serial"
    connection_type = "USB"

    @property
    def is_usb(self):
        return True

    def matches_udid(self, udid):
        return self.serial.replace("-", "") == udid.replace("-", "")


class FakeService:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        self.closed = False
        self.started = False

    async def start(self):
        self.started = True

    async def send_recv_plist(self, request):
        self.requests.append(request)
        return self.responses.pop(0)

    async def close(self):
        self.closed = True


def test_restore_protocol_info_command_has_options():
    result = CliRunner().invoke(__main__.app, ["restore", "protocol-info", "--help"])

    assert result.exit_code == 0, result.output
    assert "--query-key" in result.output
    assert "--include-values" in result.output
    assert "Include raw device" in result.output
    assert "--strict" in result.output


def test_restore_protocol_info_command_prints_json(monkeypatch):
    captured = {}

    async def fake_collect_restore_protocol_info(**kwargs):
        captured.update(kwargs)
        return {
            "mode": "restored",
            "device_count": 1,
            "devices": [{"mode": "restored"}],
        }

    monkeypatch.setattr(restore_cli, "collect_restore_protocol_info", fake_collect_restore_protocol_info)

    result = CliRunner().invoke(
        __main__.app,
        [
            "restore",
            "protocol-info",
            "--udid",
            "sensitive-serial",
            "--usbmux-address",
            "/tmp/usbmux",
            "--timeout",
            "0.5",
            "--include-values",
            "--query-key",
            "BasebandStatus",
            "--include-identifiers",
            "--trace",
            "--strict",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["mode"] == "restored"
    assert captured == {
        "udid": "sensitive-serial",
        "usbmux_address": "/tmp/usbmux",
        "timeout": 0.5,
        "include_values": True,
        "query_keys": ["BasebandStatus"],
        "include_identifiers": True,
        "include_trace": True,
    }


def test_restore_protocol_info_strict_fails_without_restored_device(monkeypatch):
    async def fake_collect_restore_protocol_info(**kwargs):
        return {"mode": "no_usb_device", "device_count": 0, "devices": []}

    monkeypatch.setattr(restore_cli, "collect_restore_protocol_info", fake_collect_restore_protocol_info)

    result = CliRunner().invoke(__main__.app, ["restore", "protocol-info", "--strict"])

    assert result.exit_code == 1
    assert json.loads(result.output)["mode"] == "no_usb_device"


def test_collect_restore_protocol_info_redacts_identifiers(monkeypatch):
    fake_service = FakeService([
        {"Type": "com.apple.mobile.restored", "RestoreProtocolVersion": 15},
        {"HardwareInfo": {"ProductType": "iPhone18,2", "UniqueChipID": 123456789}},
        {"SavedDebugInfo": {"SerialNumber": "raw-serial"}},
    ])

    async def fake_list_devices(**kwargs):
        return [FakeMuxDevice()]

    async def fake_create_using_usbmux(*args, **kwargs):
        return fake_service

    monkeypatch.setattr(protocol.usbmux, "list_devices", fake_list_devices)
    monkeypatch.setattr(protocol.ServiceConnection, "create_using_usbmux", fake_create_using_usbmux)

    output = asyncio.run(protocol.collect_restore_protocol_info(include_values=True, include_trace=True))

    assert output["mode"] == "restored"
    assert output["devices"][0]["restore_protocol_version"] == 15
    assert output["devices"][0]["device"] == {"connection_type": "USB", "device_id": 42}
    assert output["devices"][0]["query_values"]["HardwareInfo"]["HardwareInfo"] == {
        "ProductType": "iPhone18,2",
        "UniqueChipID": "<redacted>",
    }
    assert output["devices"][0]["query_values"]["SavedDebugInfo"]["SavedDebugInfo"] == {"SerialNumber": "<redacted>"}
    assert "sensitive-serial" not in json.dumps(output)
    assert fake_service.closed is True


def test_collect_restore_protocol_info_can_include_identifiers(monkeypatch):
    fake_service = FakeService([
        {"Type": "com.apple.mobile.restored", "RestoreProtocolVersion": 15},
        {"HardwareInfo": {"ProductType": "iPhone18,2", "UniqueChipID": 123456789}},
    ])

    async def fake_list_devices(**kwargs):
        return [FakeMuxDevice()]

    async def fake_create_using_usbmux(*args, **kwargs):
        return fake_service

    monkeypatch.setattr(protocol.usbmux, "list_devices", fake_list_devices)
    monkeypatch.setattr(protocol.ServiceConnection, "create_using_usbmux", fake_create_using_usbmux)

    output = asyncio.run(
        protocol.collect_restore_protocol_info(
            include_values=False,
            query_keys=["HardwareInfo"],
            include_identifiers=True,
        )
    )

    assert output["devices"][0]["device"]["serial"] == "sensitive-serial"
    assert output["devices"][0]["query_values"]["HardwareInfo"]["HardwareInfo"]["UniqueChipID"] == 123456789


def test_collect_restore_protocol_info_reports_usbmux_error(monkeypatch):
    async def fake_list_devices(**kwargs):
        raise RuntimeError("usbmux down")

    monkeypatch.setattr(protocol.usbmux, "list_devices", fake_list_devices)

    output = asyncio.run(protocol.collect_restore_protocol_info())

    assert output == {
        "mode": "usbmux_unavailable",
        "device_count": 0,
        "devices": [],
        "error_type": "RuntimeError",
        "error": "usbmux down",
    }


def test_build_restore_message_report_summarizes_failure_and_requests():
    output = protocol.build_restore_message_report([
        {"MsgType": "DataRequestMsg", "DataType": "SystemImageData", "DataPort": 12345},
        {"MsgType": "DataRequestMsg", "DataType": "NewFirmwareThing"},
        {"MsgType": "ProgressMsg", "Operation": 14, "Progress": 42},
        {"MsgType": "StatusMsg", "Status": 27, "Log": "failed for 00000000-0000000000000000 at 192.0.2.10"},
    ])

    assert output["summary"]["total"] == 4
    assert output["summary"]["failures"] == 1
    assert output["summary"]["warnings"] == 1
    assert output["summary"]["data_requests"] == 2
    assert output["summary"]["last_progress"]["operation"] == "VERIFY_RESTORE"
    assert output["summary"]["final_status"]["error"] == "failed to mount filesystems"
    assert output["messages"][0]["fields"]["implemented_by_pymobiledevice3"] is True
    assert output["messages"][1]["fields"]["implemented_by_pymobiledevice3"] is False
    assert output["messages"][3]["fields"]["log"] == "failed for <redacted> at <redacted>"


def test_build_restore_message_report_can_include_raw_messages():
    output = protocol.build_restore_message_report(
        [{"MsgType": "PreviousRestoreLogMsg", "PreviousRestoreLog": b"\x01\x02"}],
        include_raw=True,
    )

    assert output["warnings"][0]["raw"] == {
        "MsgType": "PreviousRestoreLogMsg",
        "PreviousRestoreLog": "<bytes:2>",
    }
    assert output["warnings"][0]["fields"]["log"] == "<bytes:2>"


def test_restore_message_report_redacts_identifier_markers_in_logs():
    output = protocol.build_restore_message_report([
        {
            "MsgType": "StatusMsg",
            "Status": 14,
            "Log": "SerialNumber=raw-serial ECID:123456789 apnonce=abcdef",
        }
    ])

    assert output["failures"][0]["fields"]["log"] == "SerialNumber=<redacted> ECID:<redacted> apnonce=<redacted>"


def test_restore_message_report_command_reads_json(tmp_path):
    capture = tmp_path / "restore_messages.json"
    capture.write_text(
        json.dumps({
            "messages": [
                {"MsgType": "ProgressMsg", "Operation": 18, "Progress": 5},
                {"MsgType": "StatusMsg", "Status": 0},
            ]
        })
    )

    result = CliRunner().invoke(__main__.app, ["restore", "message-report", str(capture)])

    assert result.exit_code == 0, result.output
    output = json.loads(result.output)
    assert output["summary"]["completed"] is True
    assert output["summary"]["last_progress"]["operation"] == "FLASH_FIRMWARE"


def test_restore_message_report_command_reads_plist(tmp_path):
    capture = tmp_path / "restore_message.plist"
    capture.write_bytes(plistlib.dumps({"MsgType": "RestoredCrash", "RestoredBacktrace": ["frame0", "frame1"]}))

    result = CliRunner().invoke(__main__.app, ["restore", "message-report", str(capture), "--include-raw"])

    assert result.exit_code == 0, result.output
    output = json.loads(result.output)
    assert output["summary"]["failures"] == 1
    assert output["failures"][0]["fields"]["backtrace_frames"] == 2
    assert output["failures"][0]["raw"]["MsgType"] == "RestoredCrash"
