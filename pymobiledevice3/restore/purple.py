import asyncio
import contextlib
import hashlib
import plistlib
import struct
from pathlib import Path
from typing import Any, Optional

from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import ConnectionFailedToUsbmuxdError, PyMobileDevice3Exception
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.restore.restored_client import RestoredClient
from pymobiledevice3.service_connection import ServiceConnection

PURPLE_REVERSE_PROXY_LAUNCHD_PATH = Path("System/Library/LaunchDaemons/com.apple.PurpleReverseProxy.ramdisk.plist")
PURPLE_REVERSE_PROXY_EXECUTABLE_PATH = Path("usr/libexec/PurpleReverseProxy")
PURPLE_REVERSE_PROXY_DEVICE_LIBRARY_PATH = Path("usr/lib/libReverseProxyDevice.dylib")
PURPLE_REVERSE_PROXY_RESTORED_UPDATE_PATH = Path("usr/local/bin/restored_update")
PURPLE_REVERSE_PROXY_FDR_LIBRARY_PATH = Path("usr/lib/libFDR.dylib")
PURPLE_REVERSE_PROXY_AMSUPPORT_LIBRARY_PATH = Path("usr/lib/libamsupport.dylib")
PURPLE_REVERSE_PROXY_ARU_SERVICE_PATH = Path(
    "System/Library/PrivateFrameworks/AppleRestoreUtils.framework/XPCServices/ARUService.xpc/ARUService"
)
PURPLE_REVERSE_PROXY_PORTS = [
    {"name": "restore", "port": RestoredClient.SERVICE_PORT, "purpose": "restore/lockdown QueryType"},
    {"name": "socks", "port": 1081, "purpose": "PurpleReverseProxy SOCKS socket"},
    {"name": "ctrl", "port": 1082, "purpose": "PurpleReverseProxy control socket"},
    {"name": "notify", "port": 1084, "purpose": "PurpleReverseProxy notify socket"},
]
PURPLE_REVERSE_PROXY_RELATED_FILES = {
    "purple_reverse_proxy": PURPLE_REVERSE_PROXY_EXECUTABLE_PATH,
    "device_library": PURPLE_REVERSE_PROXY_DEVICE_LIBRARY_PATH,
    "restored_update": PURPLE_REVERSE_PROXY_RESTORED_UPDATE_PATH,
    "fdr_library": PURPLE_REVERSE_PROXY_FDR_LIBRARY_PATH,
    "amsupport_library": PURPLE_REVERSE_PROXY_AMSUPPORT_LIBRARY_PATH,
    "aru_service": PURPLE_REVERSE_PROXY_ARU_SERVICE_PATH,
}
PURPLE_REVERSE_PROXY_STRING_MARKERS = {
    "purple_reverse_proxy": [
        "BeginCtrl",
        "HelloCtrl",
        "CtrlConn",
        "CtrlProtoVersion",
        "WaitSocket",
        "ConnPort",
        "NotifyConn",
        "RegisterNotify",
        "SetLogLevel",
        "Level",
        "sendPingMessage",
        "sendProxyControlMessage",
        "RPSocketReadDictionary",
        "RPSocketWriteDictionary",
        "com.apple.PurpleReverseProxy",
        "com.apple.PurpleReverseProxy.Ctrl",
        "com.apple.PurpleReverseProxy.Conn",
        "com.apple.PurpleReverseProxy.ProxyOnline",
        "com.apple.private.PurpleReverseProxy.allowed",
    ],
    "device_library": [
        "RegisterNotify",
        "SetLogLevel",
        "Level",
        "RPSocketReadDictionary",
        "RPSocketWriteDictionary",
        "com.apple.PurpleReverseProxy.FDQueue",
        "com.apple.PurpleReverseProxy.RPSocket",
        "com.apple.libReverseProxyDevice",
    ],
    "restored_update": [
        "/usr/lib/libReverseProxyDevice.dylib",
        "FDRSubmit",
        "DataRequestMsg",
        "AsyncDataRequestMsg",
        "PreviousRestoreLogMsg",
    ],
    "fdr_library": [
        "_AMFDRHttpCopyPurpleReverseProxyInformation",
    ],
    "amsupport_library": [
        "UsePurpleReverseProxy",
        "DisableReverseProxy",
        "_kAMSupportHttpOptionUsePurpleReverseProxy",
    ],
    "aru_service": [
        "DisableReverseProxy",
        "com.apple.private.PurpleReverseProxy.allowed",
    ],
}


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
    "notify_commands": [
        "RegisterNotify",
        "SetLogLevel",
    ],
    "expected_ramdisk_paths": {
        "launchd_plist": str(PURPLE_REVERSE_PROXY_LAUNCHD_PATH),
        "executable": str(PURPLE_REVERSE_PROXY_EXECUTABLE_PATH),
        "device_library": str(PURPLE_REVERSE_PROXY_DEVICE_LIBRARY_PATH),
    },
}


def _error_result(e: BaseException) -> dict[str, Any]:
    return {
        "reachable": False,
        "error_type": e.__class__.__name__,
    }


def _format_uuid(uuid_bytes: bytes) -> str:
    value = uuid_bytes.hex()
    return f"{value[:8]}-{value[8:12]}-{value[12:16]}-{value[16:20]}-{value[20:]}"


def _parse_macho_uuid_at(path: Path, offset: int = 0) -> tuple[bool, list[dict[str, Any]]]:
    with path.open("rb") as f:
        f.seek(offset)
        header = f.read(32)
        magic = header[:4]
        if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
            endian = "<"
            header_size = 32 if magic == b"\xcf\xfa\xed\xfe" else 28
        elif magic in (b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
            endian = ">"
            header_size = 32 if magic == b"\xfe\xed\xfa\xcf" else 28
        else:
            return False, []

        if len(header) < header_size:
            return True, []

        ncmds, sizeofcmds = struct.unpack_from(endian + "II", header, 16)
        f.seek(offset + header_size)
        commands = f.read(sizeofcmds)

    uuids = []
    command_offset = 0
    for _ in range(ncmds):
        if command_offset + 8 > len(commands):
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", commands, command_offset)
        if cmdsize < 8 or command_offset + cmdsize > len(commands):
            break
        if cmd == 0x1B and cmdsize >= 24:
            uuids.append({"uuid": _format_uuid(commands[command_offset + 8 : command_offset + 24])})
        command_offset += cmdsize
    return True, uuids


def _parse_macho_uuids(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as f:
            header = f.read(8)
            magic = header[:4]

            if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"):
                endian = ">" if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") else "<"
                is_fat64 = magic in (b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
                nfat = struct.unpack(endian + "I", header[4:8])[0]
                arch_size = 32 if is_fat64 else 20
                arch_data = f.read(nfat * arch_size)
                slices = []
                for index in range(nfat):
                    arch_offset = index * arch_size
                    if arch_offset + arch_size > len(arch_data):
                        break
                    if is_fat64:
                        cputype, cpusubtype, slice_offset, size, align, reserved = struct.unpack_from(
                            endian + "IIQQII", arch_data, arch_offset
                        )
                    else:
                        cputype, cpusubtype, slice_offset, size, align = struct.unpack_from(
                            endian + "IIIII", arch_data, arch_offset
                        )
                        reserved = None
                    slices.append({
                        "index": index,
                        "cputype": cputype,
                        "cpusubtype": cpusubtype,
                        "offset": slice_offset,
                        "size": size,
                        "align": align,
                        "reserved": reserved,
                        "uuids": _parse_macho_uuid_at(path, slice_offset)[1],
                    })
                return {"is_macho": True, "fat": True, "slices": slices}

        is_macho, uuids = _parse_macho_uuid_at(path)
    except OSError as e:
        return {"is_macho": False, "error": e.__class__.__name__}
    else:
        return {"is_macho": is_macho, "fat": False, "uuids": uuids}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_metadata(root: Path, relative_path: Path) -> dict[str, Any]:
    status = _path_status(root, relative_path)
    path = root / relative_path
    if not status["is_file"]:
        return status
    status["size"] = path.stat().st_size
    status["sha256"] = _sha256_file(path)
    status["macho"] = _parse_macho_uuids(path)
    return status


def _scan_file_markers(path: Path, markers: list[str]) -> dict[str, bool]:
    marker_bytes = {marker: marker.encode() for marker in markers}
    found = dict.fromkeys(markers, False)
    max_marker_len = max((len(value) for value in marker_bytes.values()), default=1)
    carry = b""
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            data = carry + chunk
            for marker, needle in marker_bytes.items():
                if not found[marker] and needle in data:
                    found[marker] = True
            if all(found.values()):
                break
            carry = data[-max_marker_len + 1 :] if max_marker_len > 1 else b""
    return found


def _component_string_evidence(root: Path, component: str, relative_path: Path, markers: list[str]) -> dict[str, Any]:
    status = _path_status(root, relative_path)
    result = {
        "relative_path": str(relative_path),
        "exists": status["exists"],
        "is_file": status["is_file"],
        "markers": dict.fromkeys(markers, False),
    }
    if not status["is_file"]:
        return result

    marker_results = _scan_file_markers(root / relative_path, markers)
    result["markers"] = marker_results
    result["present"] = [marker for marker, present in marker_results.items() if present]
    result["missing"] = [marker for marker, present in marker_results.items() if not present]
    result["component"] = component
    return result


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
            key: socket_config[key] for key in ("SockFamily", "SockNodeName", "SockServiceName") if key in socket_config
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


def inspect_purple_reverse_proxy_root_deep(root: Path) -> dict[str, Any]:
    root = root.expanduser()
    files = {
        component: _file_metadata(root, relative_path)
        for component, relative_path in PURPLE_REVERSE_PROXY_RELATED_FILES.items()
    }
    strings = {
        component: _component_string_evidence(
            root,
            component,
            PURPLE_REVERSE_PROXY_RELATED_FILES[component],
            markers,
        )
        for component, markers in PURPLE_REVERSE_PROXY_STRING_MARKERS.items()
    }

    entitlement_marker = "com.apple.private.PurpleReverseProxy.allowed"
    entitlement_components = [
        component
        for component, evidence in strings.items()
        if evidence.get("markers", {}).get(entitlement_marker) is True
    ]
    summary = {
        "available_in_restoreos_ramdisk": files["purple_reverse_proxy"]["is_file"]
        and files["device_library"]["is_file"],
        "host_option_evidence": strings["amsupport_library"]["markers"].get("UsePurpleReverseProxy") is True,
        "disable_option_evidence": any(
            evidence["markers"].get("DisableReverseProxy") is True for evidence in strings.values()
        ),
        "fdr_evidence": strings["fdr_library"]["markers"].get("_AMFDRHttpCopyPurpleReverseProxyInformation") is True,
        "control_protocol_evidence": strings["purple_reverse_proxy"]["markers"].get("HelloCtrl") is True
        or strings["purple_reverse_proxy"]["markers"].get("BeginCtrl") is True,
        "notify_protocol_evidence": strings["purple_reverse_proxy"]["markers"].get("RegisterNotify") is True
        or strings["purple_reverse_proxy"]["markers"].get("SetLogLevel") is True,
        "entitlement_evidence": bool(entitlement_components),
        "active_live_probe_required": True,
    }

    return {
        "checked": True,
        "files": files,
        "strings": strings,
        "entitlements": {
            entitlement_marker: {
                "present": bool(entitlement_components),
                "components": entitlement_components,
            }
        },
        "summary": summary,
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
            normal_mode_devices.append({
                "mode": "normal_lockdown",
                "product_type": _lockdown_value(lockdown, "product_type", "ProductType"),
                "product_version": _lockdown_value(lockdown, "product_version", "ProductVersion"),
                "build_version": _lockdown_value(lockdown, "product_build_version", "BuildVersion"),
            })
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


async def _close_service(service: Any) -> None:
    with contextlib.suppress(Exception):
        await service.close()


async def _probe_usbmux_port(
    device: Any,
    port: int,
    *,
    timeout: float,
    usbmux_address: Optional[str],
) -> dict[str, Any]:
    service = None
    try:
        service = await asyncio.wait_for(
            ServiceConnection.create_using_usbmux(
                device.serial,
                port,
                connection_type=device.connection_type,
                usbmux_address=usbmux_address,
            ),
            timeout=timeout,
        )
    except Exception as e:
        return _error_result(e)
    finally:
        if service is not None:
            await _close_service(service)

    return {"reachable": True}


async def _query_usbmux_type(
    device: Any,
    *,
    timeout: float,
    usbmux_address: Optional[str],
) -> dict[str, Any]:
    service = None
    try:
        service = await asyncio.wait_for(
            ServiceConnection.create_using_usbmux(
                device.serial,
                RestoredClient.SERVICE_PORT,
                connection_type=device.connection_type,
                usbmux_address=usbmux_address,
            ),
            timeout=timeout,
        )
        await asyncio.wait_for(service.start(), timeout=timeout)
        response = await asyncio.wait_for(service.send_recv_plist({"Request": "QueryType"}), timeout=timeout)
    except Exception as e:
        return _error_result(e)
    finally:
        if service is not None:
            await _close_service(service)

    result = {
        "reachable": True,
        "type": response.get("Type"),
    }
    if "RestoreProtocolVersion" in response:
        result["restore_protocol_version"] = response["RestoreProtocolVersion"]
    return result


async def _probe_lockdown_services(
    device: Any,
    service_names: list[str],
    *,
    timeout: float,
    usbmux_address: Optional[str],
) -> dict[str, Any]:
    lockdown = None
    try:
        lockdown = await asyncio.wait_for(
            create_using_usbmux(
                serial=device.serial,
                connection_type="USB",
                autopair=False,
                usbmux_address=usbmux_address,
            ),
            timeout=timeout,
        )
    except Exception as e:
        return {
            "checked": False,
            "reason": f"lockdown_unavailable:{e.__class__.__name__}",
        }

    results = []
    try:
        for service_name in service_names:
            service = None
            result = {"name": service_name}
            try:
                service = await asyncio.wait_for(lockdown.start_lockdown_service(service_name), timeout=timeout)
                result["reachable"] = True
            except Exception as e:
                result.update(_error_result(e))
            finally:
                if service is not None:
                    await _close_service(service)
            results.append(result)
    finally:
        await _close_service(lockdown)

    return {
        "checked": True,
        "services": results,
    }


def _mode_from_query_type(query_type: dict[str, Any]) -> str:
    if not query_type.get("reachable"):
        return "unknown"
    if query_type.get("type") == "com.apple.mobile.restored":
        return "restored"
    if query_type.get("type") == "com.apple.mobile.lockdown":
        return "normal_lockdown"
    return "unknown"


async def collect_live_purple_reverse_proxy_probe(
    *,
    usbmux_address: Optional[str] = None,
    timeout: float = 1.0,
    include_services: bool = False,
) -> dict[str, Any]:
    """
    Probe PurpleReverseProxy-related RestoreOS ports through usbmuxd.

    This intentionally omits UDID, serial, ECID, and pair-record details from its
    public result so probe output can be pasted into issue/PR text.
    """
    try:
        devices = [device for device in await usbmux.list_devices(usbmux_address=usbmux_address) if device.is_usb]
    except ConnectionFailedToUsbmuxdError:
        return {
            "checked": True,
            "mode": "unknown",
            "device_count": 0,
            "reason": "usbmuxd_unavailable",
        }
    except OSError as e:
        return {
            "checked": True,
            "mode": "unknown",
            "device_count": 0,
            "reason": f"usbmuxd_error:{e.__class__.__name__}",
        }

    if not devices:
        return {
            "checked": True,
            "mode": "no_usb_device",
            "device_count": 0,
            "reason": "No USB device is visible through usbmux.",
        }

    probed_devices = []
    for index, device in enumerate(devices):
        query_type = await _query_usbmux_type(device, timeout=timeout, usbmux_address=usbmux_address)
        ports = []
        for port_info in PURPLE_REVERSE_PROXY_PORTS:
            port_probe = await _probe_usbmux_port(
                device,
                port_info["port"],
                timeout=timeout,
                usbmux_address=usbmux_address,
            )
            ports.append({**port_info, **port_probe})

        device_result = {
            "index": index,
            "mode": _mode_from_query_type(query_type),
            "query_type": query_type,
            "ports": ports,
        }
        if include_services:
            device_result["lockdown_services"] = await _probe_lockdown_services(
                device,
                PURPLE_REVERSE_PROXY_CATALOG["lockdown_services"],
                timeout=timeout,
                usbmux_address=usbmux_address,
            )
        else:
            device_result["lockdown_services"] = {
                "checked": False,
                "reason": "--include-services was not provided.",
            }
        probed_devices.append(device_result)

    modes = {device["mode"] for device in probed_devices}
    mode = modes.pop() if len(modes) == 1 else "multiple"
    return {
        "checked": True,
        "mode": mode,
        "device_count": len(probed_devices),
        "ports": PURPLE_REVERSE_PROXY_PORTS,
        "devices": probed_devices,
    }


def build_purple_reverse_proxy_info(firmware_root: Optional[Path] = None, deep: bool = False) -> dict[str, Any]:
    info = {"catalog": PURPLE_REVERSE_PROXY_CATALOG}
    if firmware_root is not None:
        info["firmware_root"] = inspect_purple_reverse_proxy_root(firmware_root)
        if deep:
            info["deep"] = inspect_purple_reverse_proxy_root_deep(firmware_root)
    else:
        info["firmware_root"] = {"checked": False, "reason": "No extracted RestoreOS ramdisk root was provided."}
        if deep:
            info["deep"] = {"checked": False, "reason": "--deep requires --firmware-root."}
    return info
