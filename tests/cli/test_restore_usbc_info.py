import json

from typer.testing import CliRunner

from pymobiledevice3 import __main__
from pymobiledevice3.restore.usbc_flasher import build_usbc_flasher_inventory


def test_build_usbc_flasher_inventory_reports_firmware_markers(tmp_path) -> None:
    tool = tmp_path / "usr" / "bin" / "usbcfwflasher"
    library = tmp_path / "usr" / "lib" / "libUSBCfwflasher.dylib"
    tool.parent.mkdir(parents=True)
    library.parent.mkdir(parents=True)
    tool.write_bytes(b"com.apple.usbcfwflasher _USBCFlasherSupported query:andErrorResponse:")
    library.write_bytes(
        b"com.apple.libUSBCfwflasher _USBCFlasherExecCmd "
        b"flash:andErrorResponse: reset: SWDFlashWrite SWDFlashErase"
    )

    output = build_usbc_flasher_inventory(tmp_path, chunk_size=8)

    assert output["available"] is True
    assert {file["path"] for file in output["files"]} == {
        "usr/bin/usbcfwflasher",
        "usr/lib/libUSBCfwflasher.dylib",
    }
    assert "com.apple.usbcfwflasher" in output["markers"]["services"]
    assert "_USBCFlasherExecCmd" in output["markers"]["functions"]
    assert "query:andErrorResponse:" in output["markers"]["diagnostic_operations"]
    assert "flash:andErrorResponse:" in output["markers"]["controller_operations"]
    assert output["host_api"] == {
        "flash_commands_exposed": False,
        "mode": "inventory-only",
    }


def test_build_usbc_flasher_inventory_reports_absent_support(tmp_path) -> None:
    output = build_usbc_flasher_inventory(tmp_path)

    assert output["available"] is False
    assert output["files"] == []
    assert output["markers"] == {}


def test_restore_usbc_info_command_prints_json(tmp_path) -> None:
    tool = tmp_path / "usr" / "bin" / "usbcfwflasher"
    tool.parent.mkdir(parents=True)
    tool.write_bytes(b"com.apple.usbcfwflasher _USBCFlasherCreate")

    result = CliRunner().invoke(__main__.app, ["--no-color", "restore", "usbc-info", "--firmware-root", str(tmp_path)])

    assert result.exit_code == 0, result.output
    output = json.loads(result.output)
    assert output["available"] is True
    assert output["files"][0]["path"] == "usr/bin/usbcfwflasher"
    assert "com.apple.usbcfwflasher" in output["markers"]["services"]
