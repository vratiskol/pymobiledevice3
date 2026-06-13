import json

from typer.testing import CliRunner

from pymobiledevice3 import __main__


def _write(path, value):
    path.write_text(f"{value}\n")


def test_usbmux_interfaces_reads_fake_sysfs(tmp_path):
    device = tmp_path / "1-2"
    device.mkdir()
    _write(device / "idVendor", "05ac")
    _write(device / "idProduct", "12a8")
    _write(device / "manufacturer", "Apple Inc.")
    _write(device / "product", "iPhone")
    _write(device / "serial", "00008120000E65841122201E")
    _write(device / "bConfigurationValue", "4")
    _write(device / "configuration", "PTP + Apple Mobile Device")

    mux = tmp_path / "1-2:4.1"
    mux.mkdir()
    _write(mux / "interface", "Apple USB Multiplexor")
    _write(mux / "bInterfaceNumber", "01")
    _write(mux / "bAlternateSetting", "0")
    _write(mux / "bInterfaceClass", "ff")
    _write(mux / "bInterfaceSubClass", "fe")
    _write(mux / "bInterfaceProtocol", "02")
    _write(mux / "bNumEndpoints", "02")

    result = CliRunner().invoke(
        __main__.app,
        ["--no-color", "usbmux", "interfaces", "--sysfs", str(tmp_path), "--no-network"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload[0]["configuration"] == "PTP + Apple Mobile Device"
    assert payload[0]["interfaces"][0]["alias"] == "AppleUSBMux"
    assert payload[0]["interfaces"][0]["role"] == "usbmux"
