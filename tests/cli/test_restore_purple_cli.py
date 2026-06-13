import plistlib

from typer.testing import CliRunner

from pymobiledevice3 import __main__
from pymobiledevice3.restore.purple import (
    PURPLE_REVERSE_PROXY_CATALOG,
    PURPLE_REVERSE_PROXY_LAUNCHD_PATH,
    build_purple_reverse_proxy_info,
    parse_purple_reverse_proxy_launchd,
)


def test_purple_reverse_proxy_catalog_exposes_restoreos_identifiers():
    assert PURPLE_REVERSE_PROXY_CATALOG["availability"] == "restoreos_ramdisk"
    assert PURPLE_REVERSE_PROXY_CATALOG["launchd_label"] == "com.apple.PurpleReverseProxy.ramdisk"
    assert "com.apple.PurpleReverseProxy.transaction" in PURPLE_REVERSE_PROXY_CATALOG["lockdown_services"]
    assert PURPLE_REVERSE_PROXY_CATALOG["restore_options"]["enable"] == "UsePurpleReverseProxy"


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


def test_restore_purple_info_help():
    result = CliRunner().invoke(__main__.app, ["restore", "purple-info", "--help"])

    assert result.exit_code == 0
    assert "--firmware-root" in result.output
    assert "--no-device" in result.output
