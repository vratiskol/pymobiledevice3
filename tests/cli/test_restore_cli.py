from typer.testing import CliRunner

from pymobiledevice3.cli import restore
from pymobiledevice3.irecv import Mode


class FakeLockdown:
    def __init__(self) -> None:
        self.udid = "normal-udid"
        self.product_type = "iPhone99,9"
        self.all_values = {
            "ApParameters": {
                "ApNonce": b"\x01\x02",
                "SepNonce": b"\x03\x04",
            },
            "BuildVersion": "24A000",
            "DeviceClass": "iPhone",
            "HardwareModel": "d00ap",
            "HardwarePlatform": "t9999",
            "Image4Supported": True,
            "ProductType": "iPhone99,9",
            "ProductVersion": "27.0",
            "UniqueChipID": 1234,
            "UniqueDeviceID": "normal-udid",
        }


class FakeIRecv:
    mode = Mode.RECOVERY_MODE_4
    ibfl = 0x1C
    ecid = 1234
    product_type = "iPhone99,9"
    hardware_model = "d00ap"
    display_name = "iPhone Test"
    chip_id = 0x8120
    board_id = 0x12
    serial_number = "serial"
    iboot_version = "iBoot-9999.0"
    is_image4_supported = True
    ap_nonce = b"\xaa\xbb"
    sep_nonce = b"\xcc\xdd"


class FakeRestoredClient:
    def __init__(self) -> None:
        self.udid = "restored-udid"
        self.ecid = 1234
        self.version = "15"
        self.hardware_info = {
            "UniqueChipID": 1234,
            "BoardID": 0x12,
            "ChipID": 0x8120,
        }
        self.saved_debug_info = {
            "panic": b"\x01\x02",
        }


def test_restore_info_help() -> None:
    result = CliRunner().invoke(restore.cli, ["info", "--help"])

    assert result.exit_code == 0
    assert "--ecid" in result.output
    assert "--wait" in result.output
    assert "--include-errors" in result.output


def test_parse_ecid_decimal_prefixed_and_plain_hex() -> None:
    assert restore._parse_ecid("1234") == 1234
    assert restore._parse_ecid("0x4d2") == 1234
    assert restore._parse_ecid("4d2") == 1234


def test_lockdown_restore_info_decodes_normal_mode() -> None:
    info = restore._lockdown_restore_info(FakeLockdown(), "USB")

    assert info["source"] == "lockdown"
    assert info["mode"] == "normal"
    assert info["transport"] == "USB"
    assert info["identifier"] == "normal-udid"
    assert info["ecid"]["decimal"] == 1234
    assert info["product"]["type"] == "iPhone99,9"
    assert info["nonces"]["ap_nonce"] == "0102"
    assert info["preflight"]["ap_parameters_available"] is True


def test_irecv_restore_info_decodes_recovery_mode() -> None:
    info = restore._irecv_restore_info(FakeIRecv())

    assert info["source"] == "irecv"
    assert info["mode"]["name"] == "RECOVERY_MODE_4"
    assert info["mode"]["value"] == "0x1283"
    assert info["mode"]["is_recovery"] is True
    assert info["hardware"]["chip_id"]["hex"] == "0x8120"
    assert info["iboot"]["flags"]["image4_aware"] is True
    assert info["iboot"]["flags"]["effective_security_mode"] is True
    assert info["iboot"]["flags"]["effective_production_mode"] is True
    assert info["nonces"]["sep_nonce"] == "ccdd"


def test_restored_restore_info_includes_query_type_and_debug_info() -> None:
    info = restore._restored_restore_info(
        FakeRestoredClient(),
        {
            "Type": "com.apple.mobile.restored",
            "RestoreProtocolVersion": "15",
        },
        "USB",
    )

    assert info["source"] == "restored"
    assert info["mode"] == "restored"
    assert info["restore_protocol_version"] == "15"
    assert info["hardware_info"]["UniqueChipID"] == 1234
    assert info["saved_debug_info"]["panic"] == "0102"
