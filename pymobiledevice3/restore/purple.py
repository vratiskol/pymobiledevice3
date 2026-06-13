import plistlib
from pathlib import Path
from typing import Any, Optional

from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import ConnectionFailedToUsbmuxdError, PyMobileDevice3Exception
from pymobiledevice3.lockdown import create_using_usbmux

PURPLE_REVERSE_PROXY_LAUNCHD_PATH = Path(
    "System/Library/LaunchDaemons/com.apple.PurpleReverseProxy.ramdisk.plist"
)
PURPLE_REVERSE_PROXY_EXECUTABLE_PATH = Path("usr/libexec/PurpleReverseProxy")
PURPLE_REVERSE_PROXY_DEVICE_LIBRARY_PATH = Path("usr/lib/libReverseProxyDevice.dylib")


PURPLE_REVERSE_PROXY_CATALOG = {
    "availability": "restoreos_ramdisk",
    "launchd_label": "com.apple.PurpleReverseProxy.ramdisk",
    "program_arguments": ["/usr/libexec/PurpleReverseProxy", "--ramdisk"],
    "lockdown_services": [
        "com.apple.PurpleReverseProxy",
        "com.apple.PurpleReverseProxy.transaction",
    ],
    "internal_labels": [
        "com.apple.PurpleReverseProxy.FDQueue",
        "com.apple.PurpleReverseProxy.RPSocket",
        "com.apple.libReverseProxyDevice",
    ],
    "restore_options": {
        "enable": "UsePurpleReverseProxy",
        "disable": "DisableReverseProxy",
        "disable_when_socks_host_is_set": True,
    },
    "fdr_symbols": [
        "_AMFDRHttpCopyPurpleReverseProxyInformation",
    ],
    "amsupport_symbols": [
        "_kAMSupportHttpOptionUsePurpleReverseProxy",
    ],
    "expected_ramdisk_paths": {
        "launchd_plist": str(PURPLE_REVERSE_PROXY_LAUNCHD_PATH),
        "executable": str(PURPLE_REVERSE_PROXY_EXECUTABLE_PATH),
        "device_library": str(PURPLE_REVERSE_PROXY_DEVICE_LIBRARY_PATH),
    },
}


def _path_status(root: Path, relative_path: Path) -> dict[str, Any]:
    path = root / relative_path
    return {
        "relative_path": str(relative_path),
        "exists": path.exists(),
        "is_file": path.is_file(),
    }


def _ecid_matches(device_ecid: Any, requested_ecid: Optional[str]) -> bool:
    if requested_ecid is None:
        return True
    try:
        return int(device_ecid) == int(requested_ecid, 0)
    except (TypeError, ValueError):
        return str(device_ecid) == requested_ecid


def _lockdown_value(lockdown: Any, property_name: str, value_key: str) -> Any:
    value = getattr(lockdown, property_name, None)
    if value is not None:
        return value
    return getattr(lockdown, "all_values", {}).get(value_key)


def parse_purple_reverse_proxy_launchd(plist_path: Path) -> dict[str, Any]:
    with plist_path.open("rb") as plist_file:
        plist = plistlib.load(plist_file)

    sockets = {}
    for name, socket_config in sorted((plist.get("Sockets") or {}).items()):
        if not isinstance(socket_config, dict):
            sockets[name] = socket_config
            continue
        sockets[name] = {
            key: socket_config[key]
            for key in ("SockFamily", "SockNodeName", "SockServiceName")
            if key in socket_config
        }

    return {
        "label": plist.get("Label"),
        "program_arguments": plist.get("ProgramArguments", []),
        "posix_spawn_type": plist.get("POSIXSpawnType"),
        "enable_transactions": plist.get("EnableTransactions"),
        "enable_pressured_exit": plist.get("EnablePressuredExit"),
        "standard_error_path": plist.get("StandardErrorPath"),
        "standard_out_path": plist.get("StandardOutPath"),
        "sockets": sockets,
    }


def inspect_purple_reverse_proxy_root(root: Path) -> dict[str, Any]:
    root = root.expanduser()
    launchd = _path_status(root, PURPLE_REVERSE_PROXY_LAUNCHD_PATH)
    executable = _path_status(root, PURPLE_REVERSE_PROXY_EXECUTABLE_PATH)
    device_library = _path_status(root, PURPLE_REVERSE_PROXY_DEVICE_LIBRARY_PATH)

    if launchd["is_file"]:
        launchd["plist"] = parse_purple_reverse_proxy_launchd(root / PURPLE_REVERSE_PROXY_LAUNCHD_PATH)

    return {
        "checked": True,
        "launchd_plist": launchd,
        "executable": executable,
        "device_library": device_library,
    }


async def collect_live_purple_reverse_proxy_status(
    ecid: Optional[str] = None,
    usbmux_address: Optional[str] = None,
) -> dict[str, Any]:
    try:
        devices = [device for device in await usbmux.list_devices(usbmux_address=usbmux_address) if device.is_usb]
    except ConnectionFailedToUsbmuxdError as e:
        return {
            "checked": True,
            "mode": "unknown",
            "purple_reverse_proxy_available": False,
            "reason": str(e),
        }

    if not devices:
        return {
            "checked": True,
            "mode": "no_usb_device",
            "purple_reverse_proxy_available": False,
            "reason": "No USB device is visible through usbmux.",
        }

    normal_mode_devices = []
    inaccessible_devices = 0
    for device in devices:
        try:
            lockdown = await create_using_usbmux(
                serial=device.serial,
                connection_type="USB",
                autopair=False,
                usbmux_address=usbmux_address,
            )
        except PyMobileDevice3Exception:
            inaccessible_devices += 1
            continue

        try:
            if not _ecid_matches(lockdown.ecid, ecid):
                continue
            normal_mode_devices.append(
                {
                    "mode": "normal_lockdown",
                    "product_type": _lockdown_value(lockdown, "product_type", "ProductType"),
                    "product_version": _lockdown_value(lockdown, "product_version", "ProductVersion"),
                    "build_version": _lockdown_value(lockdown, "product_build_version", "BuildVersion"),
                }
            )
        finally:
            await lockdown.close()

    if normal_mode_devices:
        return {
            "checked": True,
            "mode": "normal_lockdown",
            "normal_mode_devices": normal_mode_devices,
            "purple_reverse_proxy_available": False,
            "reason": "PurpleReverseProxy is a RestoreOS ramdisk launchd service, not a normal-mode lockdown service.",
        }

    return {
        "checked": True,
        "mode": "not_normal_lockdown",
        "usb_device_count": len(devices),
        "inaccessible_device_count": inaccessible_devices,
        "purple_reverse_proxy_available": False,
        "reason": "USB devices are present, but normal lockdown was not reachable without pairing.",
    }


def build_purple_reverse_proxy_info(firmware_root: Optional[Path] = None) -> dict[str, Any]:
    info = {"catalog": PURPLE_REVERSE_PROXY_CATALOG}
    if firmware_root is not None:
        info["firmware_root"] = inspect_purple_reverse_proxy_root(firmware_root)
    else:
        info["firmware_root"] = {"checked": False, "reason": "No extracted RestoreOS ramdisk root was provided."}
    return info
