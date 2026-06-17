import json
import plistlib
import zipfile

from typer.testing import CliRunner

from pymobiledevice3 import __main__
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

    def getenv(self, name):
        return {
            "auto-boot": b"true\x00ignored",
            "build-version": b"iBoot-9999\x00",
            "serial-number": b"sensitive-serial\x00",
        "missing": None,
    }[name]


class FakeIRecvNoSrtg(FakeIRecv):
    iboot_version = None


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


def test_restore_iboot_env_help() -> None:
    result = CliRunner().invoke(restore.cli, ["iboot-env", "--help"])

    assert result.exit_code == 0
    assert "--include-identifiers" in result.output


def test_restore_options_info_help() -> None:
    result = CliRunner().invoke(restore.cli, ["options-info", "--help"])

    assert result.exit_code == 0
    assert "--ipsw" in result.output
    assert "--include-defaults" in result.output


def test_parse_ecid_decimal_prefixed_and_plain_hex() -> None:
    assert restore._parse_ecid("1234") == 1234
    assert restore._parse_ecid("0x4d2") == 1234
    assert restore._parse_ecid("4d2") == 1234


def test_irecv_environment_info_decodes_and_redacts_values() -> None:
    output = restore._irecv_environment_info(
        FakeIRecv(),
        ["auto-boot", "build-version", "serial-number", "missing"],
    )

    assert output["source"] == "irecv"
    assert output["environment"]["auto-boot"] == {"available": True, "value": "true"}
    assert output["environment"]["build-version"]["value"] == "iBoot-9999"
    assert output["environment"]["serial-number"] == {"available": True, "value": "<redacted>"}
    assert output["environment"]["missing"] == {"available": False, "value": None}


def test_irecv_environment_info_can_include_identifiers() -> None:
    output = restore._irecv_environment_info(FakeIRecv(), ["serial-number"], include_identifiers=True)

    assert output["environment"]["serial-number"] == {"available": True, "value": "sensitive-serial"}


def test_restore_options_info_reports_python_gaps() -> None:
    output = restore.build_restore_options_info()

    assert "SupportedDataTypes" in output["python"]["default_option_keys"]
    assert "RecoveryOSAppleLogo" in output["gaps"]["supported_data_types_without_handler"]
    assert "CrashLog" in output["gaps"]["supported_message_types_without_handler"]


def test_restore_options_info_reads_ipsw_manifest(tmp_path) -> None:
    ipsw = tmp_path / "sample.ipsw"
    build_manifest = {
        "ProductVersion": "27.0",
        "ProductBuildVersion": "24A000",
        "SupportedProductTypes": ["iPhone99,9"],
        "BuildIdentities": [
            {
                "Info": {
                    "Variant": "Developer Erase Install (IPSW)",
                    "RestoreBehavior": "Erase",
                    "DeviceClass": "d00ap",
                    "ContentEncoding": "aea",
                    "MinimumSystemPartition": 123,
                    "SystemPartitionPadding": {"128": 1280},
                    "RestoreAttestationMode": 8,
                },
                "Manifest": {
                    "iBoot": {"Info": {"Path": "Firmware/all_flash/iBoot.test.im4p", "Personalize": True}},
                    "RestoreRamDisk": {"Info": {"Path": "restore.dmg", "Personalize": True}},
                },
            }
        ],
    }
    restore_plist = {
        "ProductVersion": "27.0",
        "ProductBuildVersion": "24A000",
        "SupportedProductTypes": ["iPhone99,9"],
        "SupportedProductTypeIDs": {"Recovery": [1]},
        "SystemRestoreImageFileSystems": {"restore.dmg": "APFS"},
    }
    with zipfile.ZipFile(ipsw, "w") as archive:
        archive.writestr("BuildManifest.plist", plistlib.dumps(build_manifest))
        archive.writestr("Restore.plist", plistlib.dumps(restore_plist))

    output = restore.build_restore_options_info(ipsw)

    assert output["ipsw"]["build_manifest"]["product"]["build_version"] == "24A000"
    identity = output["ipsw"]["build_manifest"]["build_identities"][0]
    assert identity["restore_behavior"] == "Erase"
    assert identity["components"]["iBoot"]["path"] == "Firmware/all_flash/iBoot.test.im4p"
    assert output["ipsw"]["restore_plist"]["system_restore_image_file_systems"] == {"restore.dmg": "APFS"}
    assert output["gaps"]["manifest_restore_behavior_not_in_default_options"] is True


def test_restore_options_info_command_prints_json(tmp_path) -> None:
    build_manifest = {
        "ProductVersion": "27.0",
        "ProductBuildVersion": "24A000",
        "BuildIdentities": [],
    }
    ipsw = tmp_path / "sample.ipsw"
    with zipfile.ZipFile(ipsw, "w") as archive:
        archive.writestr("BuildManifest.plist", plistlib.dumps(build_manifest))

    result = CliRunner().invoke(__main__.app, ["restore", "options-info", "--ipsw", str(ipsw)])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["ipsw"]["build_manifest"]["product"]["version"] == "27.0"


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


def test_irecv_restore_info_allows_missing_iboot_version() -> None:
    info = restore._irecv_restore_info(FakeIRecvNoSrtg())

    assert info["mode"]["name"] == "RECOVERY_MODE_4"
    assert info["iboot"]["version"] is None


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
