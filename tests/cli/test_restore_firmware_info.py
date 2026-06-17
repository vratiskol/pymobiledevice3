import json
import plistlib

from typer.testing import CliRunner

from pymobiledevice3 import __main__
from pymobiledevice3.restore.firmware_inventory import build_restore_firmware_inventory


def _write_plist(path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        plistlib.dump(value, f)


def _write_restore_firmware_fixture(root) -> None:
    _write_plist(
        root / "BuildManifest.plist",
        {
            "ProductVersion": "27.0",
            "ProductBuildVersion": "24A5355q",
            "ManifestVersion": 0,
            "SupportedProductTypes": ["iPhone18,2"],
            "BuildIdentities": [
                {
                    "Info": {
                        "Variant": "Developer Erase Install (IPSW)",
                        "RestoreBehavior": "Erase",
                        "DeviceClass": "v54ap",
                        "BuildNumber": "24A5355q",
                        "FDRSupport": True,
                        "RestoreAttestationMode": 8,
                        "VariantContents": {"BasebandFirmware": "Release"},
                    },
                    "Manifest": {
                        "BasebandFirmware": {
                            "Info": {
                                "Path": "Firmware/Mav25-2.07.05.Release.bbfw",
                                "RestoreRequestRules": [
                                    {
                                        "Actions": {"EPRO": True},
                                        "Conditions": {"ApRawProductionMode": True},
                                    }
                                ],
                            }
                        },
                        "RestoreRamDisk": {
                            "Info": {
                                "Path": "094-13753-120.dmg",
                                "Personalize": True,
                                "RestoreRequestRules": [
                                    {
                                        "Actions": {"ESEC": True},
                                        "Conditions": {"ApRawSecurityMode": True},
                                    }
                                ],
                            }
                        },
                        "Wireless1,ACIWIFI": {
                            "Info": {
                                "Path": "Firmware/t2026phoneG1/Release/ftab.bin",
                                "IsFTAB": True,
                                "IsFUDFirmware": True,
                                "RestoreRequestRules": [],
                            }
                        },
                    },
                }
            ],
        },
    )
    _write_plist(
        root / "Restore.plist",
        {
            "ProductVersion": "27.0",
            "ProductBuildVersion": "24A5355q",
            "SupportedProductTypes": ["iPhone18,2"],
            "SupportedProductTypeIDs": {"DFU": [234914128], "Recovery": [234914128]},
            "SystemRestoreImageFileSystems": {"094-13654-116.dmg.aea": "APFS"},
            "DeviceMap": [
                {
                    "BoardConfig": "v54ap",
                    "Platform": "t8150",
                    "CPID": 33104,
                    "BDID": 14,
                    "SDOM": 1,
                    "SCEP": 0,
                }
            ],
        },
    )

    _write_plist(
        root / "System" / "Library" / "LaunchDaemons" / "com.apple.restored_update.plist",
        {
            "Label": "com.apple.restored_update",
            "ProgramArguments": ["/usr/local/bin/restored_update"],
            "RunAtLoad": True,
        },
    )
    _write_plist(
        root / "System" / "Library" / "LaunchDaemons" / "com.apple.PurpleReverseProxy.ramdisk.plist",
        {
            "Label": "com.apple.PurpleReverseProxy.ramdisk",
            "ProgramArguments": ["/usr/libexec/PurpleReverseProxy", "--ramdisk"],
            "Sockets": {"ctrl": {}, "notify": {}, "socks": {}},
        },
    )

    restored_update = root / "usr" / "local" / "bin" / "restored_update"
    restored_update.parent.mkdir(parents=True)
    restored_update.write_bytes(
        b"com.apple.restored.WKMS com.apple.restored.large-file-readback "
        b"com.apple.restored.cliupdaters com.apple.restored.roseupdater"
    )

    libauthinstall = root / "usr" / "lib" / "libauthinstall.dylib"
    libauthinstall.parent.mkdir(parents=True)
    libauthinstall.write_bytes(
        b"com.apple.EmbeddedSoftwareRestore.Baseband.ChipId "
        b"com.apple.EmbeddedSoftwareRestore.eUICC.firmwareMac"
    )

    updater = root / "usr" / "lib" / "updaters" / "libRoseUpdater.dylib"
    updater.parent.mkdir(parents=True)
    updater.write_bytes(b"")

    firmware = root / "usr" / "standalone" / "firmware" / "nfrestore" / "firmware" / "fw.bin"
    firmware.parent.mkdir(parents=True)
    firmware.write_bytes(b"fw")

    _write_plist(
        root / "System" / "Library" / "FDR" / "FDRSealingMap.plist",
        {
            "iPhone18,2": "resolved-map",
            "resolved-map": [
                {
                    "Tag": "bbcl",
                    "DataInstanceIdentifier": "BasebandUniqueId",
                    "Attributes": ["RequiredToSeal", "GeneratedByRestore"],
                },
                {
                    "Tag": "rMC2",
                    "DataInstanceIdentifierList": ["ArrowChipID", "ArrowUniqueChipID"],
                    "Attributes": ["RequiredToSeal"],
                    "SubCCList": [{"Tag": "rMUB", "Attributes": ["RequiredToSeal"]}],
                },
            ],
        },
    )
    _write_plist(
        root / "System" / "Library" / "FDR" / "FDRSealingMapRepairConfiguration.plist",
        {"iPhone18,2": "repair-ref"},
    )


def test_build_restore_firmware_inventory_summarizes_manifest_and_restoreos(tmp_path) -> None:
    _write_restore_firmware_fixture(tmp_path)

    output = build_restore_firmware_inventory(ipsw_root=tmp_path, firmware_root=tmp_path, chunk_size=8)

    assert output["product"] == "iPhone18,2"
    manifest = output["manifest"]["build_manifest"]
    assert manifest["product_version"] == "27.0"
    assert manifest["build_identity_count"] == 1
    identity = manifest["build_identities"][0]
    assert identity["restore_behavior"] == "Erase"
    assert identity["manifest_item_count"] == 3
    assert identity["restore_request_rule_count"] == 2
    assert identity["restore_request_rule_component_count"] == 2
    assert identity["component_family_counts"]["Restore"] == 1
    assert identity["component_family_counts"]["Wireless1"] == 1
    assert identity["flag_counts"]["IsFUDFirmware"] == 1

    restore_plist = output["manifest"]["restore_plist"]
    assert restore_plist["device_map"][0]["board_config"] == "v54ap"
    assert restore_plist["device_map"][0]["cpid"] == 33104

    restoreos = output["restoreos"]
    assert restoreos["host_api"] == {
        "mode": "inventory-only",
        "updater_commands_exposed": False,
    }
    assert "com.apple.restored.WKMS" in restoreos["service_markers"]["fdr_wkms"]
    assert "com.apple.restored.roseupdater" in restoreos["service_markers"]["component_restore"]
    assert restoreos["updater_libraries"] == ["usr/lib/updaters/libRoseUpdater.dylib"]
    assert restoreos["standalone_firmware"]["by_family"]["nfrestore"] == 1
    assert restoreos["fdr"]["resolved_key"] == "resolved-map"
    assert restoreos["fdr"]["repair_reference"] == "repair-ref"
    assert restoreos["fdr"]["sealing_entry_count"] == 2
    assert restoreos["fdr"]["subcomponent_entry_count"] == 1
    assert restoreos["fdr"]["top_attributes"]["RequiredToSeal"] == 3


def test_build_restore_firmware_inventory_can_include_components(tmp_path) -> None:
    _write_restore_firmware_fixture(tmp_path)

    output = build_restore_firmware_inventory(ipsw_root=tmp_path, include_components=True)
    components = output["manifest"]["build_manifest"]["build_identities"][0]["components"]

    assert {component["name"] for component in components} == {
        "BasebandFirmware",
        "RestoreRamDisk",
        "Wireless1,ACIWIFI",
    }
    restore_ramdisk = next(component for component in components if component["name"] == "RestoreRamDisk")
    assert restore_ramdisk["path"] == "094-13753-120.dmg"
    assert restore_ramdisk["restore_request_rule_count"] == 1


def test_restore_firmware_info_command_prints_json(tmp_path) -> None:
    _write_restore_firmware_fixture(tmp_path)

    result = CliRunner().invoke(
        __main__.app,
        [
            "--no-color",
            "restore",
            "firmware-info",
            "--ipsw-root",
            str(tmp_path),
            "--firmware-root",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    output = json.loads(result.output)
    assert output["product"] == "iPhone18,2"
    assert output["manifest"]["build_manifest"]["build_identities"][0]["component_family_counts"]["Restore"] == 1
    assert output["restoreos"]["firmware_root"] is None
    assert output["restoreos"]["service_files"][0]["path"] == "usr/local/bin/restored_update"


def test_restore_firmware_info_requires_a_root() -> None:
    result = CliRunner().invoke(__main__.app, ["--no-color", "restore", "firmware-info"])

    assert result.exit_code == 1
    assert "ipsw_root or firmware_root is required" in str(result.exception)
