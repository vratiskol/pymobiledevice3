import asyncio
import contextlib
import hashlib
import plistlib
import struct
from pathlib import Path
from typing import Any, Optional

from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import ConnectionFailedToUsbmuxdError, IRecvNoDeviceConnectedError, PyMobileDevice3Exception
from pymobiledevice3.irecv import IRecv, Mode
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.restore.restored_client import RestoredClient
from pymobiledevice3.service_connection import ServiceConnection
from usb.core import find as usb_find
from usb.util import find_descriptor, get_string

PURPLE_REVERSE_PROXY_ENABLE_OPTION = "UsePurpleReverseProxy"
PURPLE_REVERSE_PROXY_DISABLE_OPTION = "DisableReverseProxy"
PURPLE_REVERSE_PROXY_LOG_LEVEL_OPTION = "PRPLogLevel"
PURPLE_REVERSE_PROXY_SOCKS_HOST_OPTION = "SOCKSHost"
PURPLE_REVERSE_PROXY_SOCKS_PORT_OPTION = "SOCKSPort"
PURPLE_REVERSE_PROXY_PROXY_ENABLE_OPTION = "EnableProxy"
PURPLE_REVERSE_PROXY_PROXY_ENABLE_SSL_OPTION = "EnableProxySsl"
PURPLE_REVERSE_PROXY_PROXY_FOR_HTTPS_OPTION = "ForHttps"
PURPLE_REVERSE_PROXY_PROXY_SOCKS_HOST_OPTION = "UseSOCKSHost"
PURPLE_REVERSE_PROXY_PROXY_SOCKS_PORT_OPTION = "UseSOCKSPort"
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
PURPLE_REVERSE_PROXY_PORT_PURPOSES = {port["name"]: port["purpose"] for port in PURPLE_REVERSE_PROXY_PORTS}
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
        "HelloConn",
        "CtrlConn",
        "CtrlProtoVersion",
        "ConnProtoVersion",
        "Identifier",
        "WaitSocket",
        "ConnPort",
        "NotifyConn",
        "RegisterNotify",
        "SetLogLevel",
        "Level",
        "RPSocketReadDictionary",
        "RPSocketWriteDictionary",
        "com.apple.PurpleReverseProxy",
        "com.apple.PurpleReverseProxy.Ctrl",
        "com.apple.PurpleReverseProxy.Conn",
        "com.apple.PurpleReverseProxy.ProxyOnline",
        "com.apple.private.PurpleReverseProxy.allowed",
    ],
    "device_library": [
        "CopyProxyDictionary",
        "CopyProxyDictionaryWithOptions",
        "TestReachability",
        "Ping",
        "Pong",
        "sendPingMessage",
        "sendProxyControlMessage",
        "socks://127.0.0.1:%d/",
        "_kCFStreamPropertySOCKSProxyHost",
        "_kCFStreamPropertySOCKSProxyPort",
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
        "PRPLogLevel",
        "EnableProxy",
        "EnableProxySsl",
        "ForHttps",
        "ProxySettings",
        "SocksProxySettings",
        "SOCKSProxyHost",
        "SOCKSProxyPort",
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
        "EnableProxy",
        "EnableProxySsl",
        "ForHttps",
        "UseSOCKSHost",
        "UseSOCKSPort",
        "SOCKSHost",
        "SOCKSPort",
        "RestoreOptions",
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
        "enable": PURPLE_REVERSE_PROXY_ENABLE_OPTION,
        "disable": PURPLE_REVERSE_PROXY_DISABLE_OPTION,
        "log_level": PURPLE_REVERSE_PROXY_LOG_LEVEL_OPTION,
        "socks_host": PURPLE_REVERSE_PROXY_SOCKS_HOST_OPTION,
        "socks_port": PURPLE_REVERSE_PROXY_SOCKS_PORT_OPTION,
        "proxy_enable": PURPLE_REVERSE_PROXY_PROXY_ENABLE_OPTION,
        "proxy_enable_ssl": PURPLE_REVERSE_PROXY_PROXY_ENABLE_SSL_OPTION,
        "proxy_for_https": PURPLE_REVERSE_PROXY_PROXY_FOR_HTTPS_OPTION,
        "proxy_socks_host": PURPLE_REVERSE_PROXY_PROXY_SOCKS_HOST_OPTION,
        "proxy_socks_port": PURPLE_REVERSE_PROXY_PROXY_SOCKS_PORT_OPTION,
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
    "internal_strings": [
        "WaitSocket",
    ],
    "proxy_dictionary": {
        "function": "CopyProxyDictionaryWithOptions",
        "test_reachability_option": "TestReachability",
        "ping_command": "Ping",
        "pong_response": "Pong",
        "default_socks_host": "127.0.0.1",
        "default_socks_port": 1081,
    },
    "expected_ramdisk_paths": {
        "launchd_plist": str(PURPLE_REVERSE_PROXY_LAUNCHD_PATH),
        "executable": str(PURPLE_REVERSE_PROXY_EXECUTABLE_PATH),
        "device_library": str(PURPLE_REVERSE_PROXY_DEVICE_LIBRARY_PATH),
    },
}


def build_purple_reverse_proxy_restore_options(
    *,
    enable: bool = False,
    disable: bool = False,
    log_level: Optional[int] = None,
    socks_host: Optional[str] = None,
    socks_port: Optional[int] = None,
    proxy_enable: bool = False,
    proxy_enable_ssl: bool = False,
    proxy_for_https: bool = False,
    proxy_socks_host: Optional[str] = None,
    proxy_socks_port: Optional[int] = None,
) -> dict[str, Any]:
    if enable and disable:
        raise ValueError("UsePurpleReverseProxy and DisableReverseProxy are mutually exclusive")
    if socks_port is not None and socks_host is None:
        raise ValueError("SOCKSPort requires SOCKSHost")
    if proxy_socks_port is not None and proxy_socks_host is None:
        raise ValueError("UseSOCKSPort requires UseSOCKSHost")
    if log_level is not None and not 0 <= log_level <= 7:
        raise ValueError("PRPLogLevel must be between 0 and 7")

    restore_options: dict[str, Any] = {}
    notes = []
    if enable:
        restore_options[PURPLE_REVERSE_PROXY_ENABLE_OPTION] = True
    if disable:
        restore_options[PURPLE_REVERSE_PROXY_DISABLE_OPTION] = True
    if log_level is not None:
        restore_options[PURPLE_REVERSE_PROXY_LOG_LEVEL_OPTION] = log_level
    if socks_host is not None:
        restore_options[PURPLE_REVERSE_PROXY_SOCKS_HOST_OPTION] = socks_host
        restore_options[PURPLE_REVERSE_PROXY_SOCKS_PORT_OPTION] = socks_port if socks_port is not None else 1081
        restore_options[PURPLE_REVERSE_PROXY_DISABLE_OPTION] = True
        notes.append("SOCKSHost disables PurpleReverseProxy according to ARUService RestoreOptions evidence.")
    if proxy_enable:
        restore_options[PURPLE_REVERSE_PROXY_PROXY_ENABLE_OPTION] = True
    if proxy_enable_ssl:
        restore_options[PURPLE_REVERSE_PROXY_PROXY_ENABLE_SSL_OPTION] = True
    if proxy_for_https:
        restore_options[PURPLE_REVERSE_PROXY_PROXY_FOR_HTTPS_OPTION] = True
    if proxy_socks_host is not None:
        restore_options[PURPLE_REVERSE_PROXY_PROXY_SOCKS_HOST_OPTION] = proxy_socks_host
        restore_options[PURPLE_REVERSE_PROXY_PROXY_SOCKS_PORT_OPTION] = (
            proxy_socks_port if proxy_socks_port is not None else 1081
        )
        notes.append("UseSOCKSHost/UseSOCKSPort are ARU proxy options found in RestoreOS firmware.")

    return {
        "checked": True,
        "experimental": True,
        "restore_options": restore_options,
        "evidence": {
            "enable": "libamsupport UsePurpleReverseProxy / _kAMSupportHttpOptionUsePurpleReverseProxy",
            "disable": "ARUService DisableReverseProxy",
            "log_level": "restored_update PRPLogLevel",
            "socks": "ARUService SOCKSHost / SOCKSPort",
            "proxy_options": "ARUService/restored_update EnableProxy / EnableProxySsl / ForHttps",
            "proxy_socks": "ARUService UseSOCKSHost / UseSOCKSPort",
            "socks_proxy_settings": "AMSupport/FDR SocksProxySettings with SOCKSProxyHost / SOCKSProxyPort",
            "fdr": "libFDR _AMFDRHttpCopyPurpleReverseProxyInformation",
        },
        "notes": notes,
    }


def apply_purple_reverse_proxy_restore_options(restore_options: Any, options: dict[str, Any]) -> None:
    if isinstance(restore_options, dict):
        restore_options.update(options)
        return
    for key, value in options.items():
        setattr(restore_options, key, value)


def _firmware_status(value: Optional[bool]) -> str:
    if value is True:
        return "firmware_verified"
    if value is False:
        return "firmware_missing"
    return "cataloged"


def _deep_summary_value(info: dict[str, Any], key: str) -> Optional[bool]:
    summary = info.get("deep", {}).get("summary")
    if isinstance(summary, dict) and key in summary:
        return bool(summary[key])
    return None


def _basic_restoreos_availability(info: dict[str, Any]) -> Optional[bool]:
    firmware_root = info.get("firmware_root", {})
    if not firmware_root.get("checked"):
        return None
    return bool(
        firmware_root.get("executable", {}).get("is_file")
        and firmware_root.get("device_library", {}).get("is_file")
        and firmware_root.get("launchd_plist", {}).get("exists")
    )


def build_purple_reverse_proxy_capabilities(
    firmware_root: Optional[Path] = None,
    *,
    deep: bool = False,
) -> dict[str, Any]:
    info = build_purple_reverse_proxy_info(firmware_root=firmware_root, deep=deep)
    restoreos_available = _deep_summary_value(info, "available_in_restoreos_ramdisk")
    if restoreos_available is None:
        restoreos_available = _basic_restoreos_availability(info)

    capabilities = [
        {
            "name": "restoreos_ramdisk_service",
            "layer": "static_firmware",
            "status": _firmware_status(restoreos_available),
            "commands": ["restore purple-info", "restore purple-probe"],
            "evidence": [
                PURPLE_REVERSE_PROXY_CATALOG["launchd_label"],
                str(PURPLE_REVERSE_PROXY_EXECUTABLE_PATH),
                str(PURPLE_REVERSE_PROXY_DEVICE_LIBRARY_PATH),
            ],
            "requires_live_device": False,
        },
        {
            "name": "restore_options",
            "layer": "restore_update",
            "status": _firmware_status(_deep_summary_value(info, "restore_options_evidence")),
            "commands": ["restore purple-restore-options", "restore update"],
            "evidence": [
                PURPLE_REVERSE_PROXY_ENABLE_OPTION,
                PURPLE_REVERSE_PROXY_DISABLE_OPTION,
                PURPLE_REVERSE_PROXY_LOG_LEVEL_OPTION,
                PURPLE_REVERSE_PROXY_SOCKS_HOST_OPTION,
                PURPLE_REVERSE_PROXY_SOCKS_PORT_OPTION,
            ],
            "requires_live_device": False,
        },
        {
            "name": "control_protocol",
            "layer": "control_socket",
            "status": _firmware_status(_deep_summary_value(info, "control_protocol_evidence")),
            "commands": ["restore purple-control", "restore purple-session"],
            "evidence": ["HelloCtrl", "BeginCtrl", "CtrlConn", "CtrlProtoVersion", "Ping", "Pong"],
            "requires_live_device": True,
        },
        {
            "name": "internal_accept_helper",
            "layer": "control_socket",
            "status": _firmware_status(_deep_summary_value(info, "control_protocol_evidence")),
            "commands": [],
            "evidence": PURPLE_REVERSE_PROXY_CATALOG["internal_strings"],
            "requires_live_device": False,
            "note": "WaitSocket is a firmware accept-helper string, not a host wire command.",
        },
        {
            "name": "connection_protocol",
            "layer": "conn_socket",
            "status": _firmware_status(_deep_summary_value(info, "connection_protocol_evidence")),
            "commands": ["restore purple-conn", "restore purple-socks-probe", "restore purple-session --probe-socks"],
            "evidence": ["HelloConn", "ConnProtoVersion", "Identifier"],
            "requires_live_device": True,
        },
        {
            "name": "notify_protocol",
            "layer": "notify_socket",
            "status": _firmware_status(_deep_summary_value(info, "notify_protocol_evidence")),
            "commands": ["restore purple-notify", "restore purple-session"],
            "evidence": ["RegisterNotify", "SetLogLevel", "Level"],
            "requires_live_device": True,
        },
        {
            "name": "proxy_dictionary",
            "layer": "host_model",
            "status": _firmware_status(_deep_summary_value(info, "proxy_dictionary_evidence")),
            "commands": ["restore purple-proxy-dict"],
            "evidence": ["CopyProxyDictionaryWithOptions", "TestReachability", "socks://127.0.0.1:%d/"],
            "requires_live_device": False,
        },
        {
            "name": "socks_data_plane",
            "layer": "socks_socket",
            "status": "implemented",
            "commands": ["restore purple-socks-probe", "restore purple-session --probe-socks"],
            "evidence": ["SOCKS5 greeting", "SOCKS5 CONNECT"],
            "requires_live_device": True,
        },
        {
            "name": "notify_event_classification",
            "layer": "host_summary",
            "status": "implemented",
            "commands": ["restore purple-notify", "restore purple-session"],
            "evidence": ["proxy_online", "error", "log", "status", "unknown"],
            "requires_live_device": True,
        },
        {
            "name": "fdr_purple_reverse_proxy",
            "layer": "fdr",
            "status": _firmware_status(_deep_summary_value(info, "fdr_evidence")),
            "commands": ["restore update"],
            "evidence": PURPLE_REVERSE_PROXY_CATALOG["fdr_symbols"],
            "requires_live_device": True,
        },
    ]

    return {
        "checked": True,
        "experimental": True,
        "firmware": info,
        "port_config": build_purple_reverse_proxy_port_config(firmware_root),
        "capabilities": capabilities,
        "summary": {
            "capability_count": len(capabilities),
            "implemented_count": sum(1 for capability in capabilities if capability["status"] == "implemented"),
            "firmware_verified_count": sum(
                1 for capability in capabilities if capability["status"] == "firmware_verified"
            ),
            "live_required_count": sum(1 for capability in capabilities if capability["requires_live_device"]),
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


def _irecv_public_state() -> Optional[dict[str, Any]]:
    try:
        irecv = IRecv(timeout=0.2)
    except IRecvNoDeviceConnectedError:
        return None
    except Exception:
        return None

    if irecv.mode is None:
        return None

    state: dict[str, Any] = {
        "state": "recovery" if irecv.mode.is_recovery else "dfu",
        "mode": irecv.mode.name,
        "mode_value": irecv.mode.value,
    }
    with contextlib.suppress(Exception):
        state["product_type"] = irecv.product_type
    with contextlib.suppress(Exception):
        state["hardware_model"] = irecv.hardware_model
    with contextlib.suppress(Exception):
        state["ecid"] = f"0x{irecv.ecid:x}"
    return state


def _parse_apple_usb_serial_string(serial_string: Optional[str]) -> dict[str, Any]:
    if not serial_string:
        return {}

    parsed: dict[str, Any] = {}
    for component in serial_string.split(" "):
        if ":" not in component:
            continue
        key, value = component.split(":", 1)
        if key in ("SRNM", "SRTG") and value.startswith("[") and value.endswith("]"):
            value = value[1:-1]
        parsed[key] = value
    return parsed


def _usb_class_name(interface_class: int, interface_subclass: int, interface_protocol: int) -> str:
    if interface_class == 0xFE and interface_subclass == 0x01 and interface_protocol == 0x02:
        return "device_firmware_upgrade"
    if interface_class == 0xFF:
        return "vendor_specific"
    return f"class_0x{interface_class:02x}"


def _usb_speed_name(speed: Any) -> Optional[str]:
    return {
        1: "low",
        2: "full",
        3: "high",
        4: "super",
        5: "super_plus",
    }.get(speed)


def _usb_endpoint_summary(endpoint) -> dict[str, Any]:
    transfer_type = endpoint.bmAttributes & 0x3
    return {
        "address": f"0x{endpoint.bEndpointAddress:02x}",
        "direction": "in" if endpoint.bEndpointAddress & 0x80 else "out",
        "transfer_type": {
            0: "control",
            1: "isochronous",
            2: "bulk",
            3: "interrupt",
        }.get(transfer_type, f"transfer_type_0x{transfer_type:02x}"),
        "max_packet_size": endpoint.wMaxPacketSize,
    }


def _usb_expected_interface_altsettings(mode: Optional[Mode]) -> dict[int, int]:
    selections = {0: 0}
    if mode is None:
        return selections
    if mode.is_recovery:
        selections[1] = 1 if mode.value > Mode.RECOVERY_MODE_2.value else 0
    return selections


def _usb_interface_summary(device, interface, selected_altsetting: Optional[int]) -> dict[str, Any]:
    endpoints = [_usb_endpoint_summary(endpoint) for endpoint in interface.endpoints()]
    interface_string = None
    with contextlib.suppress(Exception):
        if interface.iInterface:
            interface_string = get_string(device, interface.iInterface)

    return {
        "interface_number": interface.bInterfaceNumber,
        "alternate_setting": interface.bAlternateSetting,
        "selected": selected_altsetting == interface.bAlternateSetting if selected_altsetting is not None else False,
        "class": _usb_class_name(interface.bInterfaceClass, interface.bInterfaceSubClass, interface.bInterfaceProtocol),
        "class_code": f"0x{interface.bInterfaceClass:02x}",
        "subclass_code": f"0x{interface.bInterfaceSubClass:02x}",
        "protocol_code": f"0x{interface.bInterfaceProtocol:02x}",
        "endpoint_count": len(endpoints),
        "iInterface": interface.iInterface,
        "interface_string": interface_string,
        "endpoints": endpoints,
    }


def _usb_device_summary(device, *, ecid: Optional[str] = None) -> Optional[dict[str, Any]]:
    mode = Mode.get_mode_from_value(device.idProduct)
    if mode is None:
        return None

    serial_string = None
    manufacturer_string = None
    product_string = None
    with contextlib.suppress(Exception):
        serial_string = get_string(device, device.iSerialNumber)
    with contextlib.suppress(Exception):
        manufacturer_string = get_string(device, device.iManufacturer)
    with contextlib.suppress(Exception):
        product_string = get_string(device, device.iProduct)
    serial_info = _parse_apple_usb_serial_string(serial_string)

    if ecid is not None:
        device_ecid = serial_info.get("ECID")
        if device_ecid is None:
            return None
        try:
            if int(device_ecid, 16) != int(ecid, 0):
                return None
        except ValueError:
            if str(device_ecid) != str(ecid):
                return None

    configuration = device.get_active_configuration()
    selection_map = _usb_expected_interface_altsettings(mode)
    interfaces_by_number: dict[int, dict[str, Any]] = {}
    for interface in find_descriptor(configuration, find_all=True, custom_match=lambda item: True):
        interface_summary = _usb_interface_summary(device, interface, selection_map.get(interface.bInterfaceNumber))
        interfaces_by_number.setdefault(
            interface.bInterfaceNumber,
            {
                "interface_number": interface.bInterfaceNumber,
                "selected_altsetting": selection_map.get(interface.bInterfaceNumber),
                "alternate_settings": [],
            },
        )["alternate_settings"].append(interface_summary)

    interfaces = []
    for interface_number in sorted(interfaces_by_number):
        interface_summary = interfaces_by_number[interface_number]
        interface_summary["alternate_settings"].sort(key=lambda item: item["alternate_setting"])
        interfaces.append(interface_summary)

    return {
        "checked": True,
        "source": "pyusb",
        "state": "recovery" if mode.is_recovery else "dfu",
        "mode": mode.name,
        "mode_value": mode.value,
        "selected_interface_altsettings": [
            {"interface_number": interface_number, "alternate_setting": altsetting}
            for interface_number, altsetting in sorted(selection_map.items())
        ],
        "device": {
            "vendor_id": f"0x{device.idVendor:04x}",
            "product_id": f"0x{device.idProduct:04x}",
            "manufacturer": manufacturer_string,
            "product": product_string,
            "serial_number": serial_string,
            "ecid": f"0x{int(serial_info['ECID'], 16):x}" if "ECID" in serial_info else None,
            "hardware_model": serial_info.get("CPID"),
            "board_id": serial_info.get("BDID"),
            "chip_id": serial_info.get("CPID"),
            "speed": _usb_speed_name(getattr(device, "speed", None)) or getattr(device, "speed", None),
        },
        "configuration": {
            "value": configuration.bConfigurationValue,
            "interface_count": configuration.bNumInterfaces,
            "total_length": configuration.wTotalLength,
        },
        "interfaces": interfaces,
    }


def collect_live_purple_usb_inventory(ecid: Optional[str] = None) -> dict[str, Any]:
    try:
        devices = list(usb_find(find_all=True))
    except Exception as e:
        return {
            "checked": True,
            "source": "pyusb",
            "mode": "unknown",
            "device_count": 0,
            "reason": f"usb_scan_failed:{e.__class__.__name__}",
        }

    inventory_devices = []
    skipped_devices = []
    for device in devices:
        if device.idVendor != 0x05AC:
            continue
        try:
            summary = _usb_device_summary(device, ecid=ecid)
        except Exception as e:
            skipped_devices.append(
                {
                    "vendor_id": f"0x{device.idVendor:04x}",
                    "product_id": f"0x{device.idProduct:04x}",
                    "reason": f"usb_summary_failed:{e.__class__.__name__}",
                }
            )
            continue
        if summary is not None:
            inventory_devices.append(summary)

    if not inventory_devices:
        result = {
            "checked": True,
            "source": "pyusb",
            "mode": "no_usb_device",
            "device_count": 0,
            "reason": (
                "No matching Apple recovery/DFU USB device is visible."
                if ecid is not None
                else "No Apple recovery/DFU USB device is visible."
            ),
        }
        if skipped_devices:
            result["skipped_devices"] = skipped_devices
        return result

    modes = {device["mode"] for device in inventory_devices}
    mode = modes.pop() if len(modes) == 1 else "multiple"
    return {
        "checked": True,
        "source": "pyusb",
        "mode": mode,
        "device_count": len(inventory_devices),
        "devices": inventory_devices,
    }


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


def _parse_launchd_port(value: Any) -> Optional[int]:
    try:
        port = int(str(value), 10)
    except (TypeError, ValueError):
        return None
    if not 1 <= port <= 0xFFFF:
        return None
    return port


def _purple_reverse_proxy_default_ports() -> dict[str, int]:
    return {port["name"]: int(port["port"]) for port in PURPLE_REVERSE_PROXY_PORTS}


def _purple_reverse_proxy_port_list(port_map: dict[str, int]) -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "port": port_map[name],
            "purpose": PURPLE_REVERSE_PROXY_PORT_PURPOSES[name],
        }
        for name in ("restore", "socks", "ctrl", "notify")
    ]


def build_purple_reverse_proxy_port_config(firmware_root: Optional[Path] = None) -> dict[str, Any]:
    port_map = _purple_reverse_proxy_default_ports()
    sources = dict.fromkeys(port_map, "default")
    evidence: dict[str, Any] = {}
    warnings = []
    source = "defaults"

    if firmware_root is not None:
        source = "firmware_root"
        launchd_path = firmware_root.expanduser() / PURPLE_REVERSE_PROXY_LAUNCHD_PATH
        if launchd_path.is_file():
            launchd = parse_purple_reverse_proxy_launchd(launchd_path)
            for name in ("socks", "ctrl", "notify"):
                socket_config = launchd.get("sockets", {}).get(name)
                if not isinstance(socket_config, dict):
                    warnings.append(f"missing_socket:{name}")
                    continue
                raw_port = socket_config.get("SockServiceName")
                port = _parse_launchd_port(raw_port)
                if port is None:
                    warnings.append(f"invalid_sock_service_name:{name}")
                    continue
                port_map[name] = port
                sources[name] = "firmware_root"
                evidence[name] = {
                    "launchd_socket": name,
                    "SockServiceName": str(raw_port),
                }
        else:
            warnings.append("launchd_plist_missing")

    return {
        "checked": True,
        "source": source,
        "ports": port_map,
        "sources": sources,
        "probe_ports": _purple_reverse_proxy_port_list(port_map),
        "evidence": evidence,
        "warnings": warnings,
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
        "connection_protocol_evidence": strings["purple_reverse_proxy"]["markers"].get("HelloConn") is True
        or strings["purple_reverse_proxy"]["markers"].get("ConnProtoVersion") is True
        or strings["purple_reverse_proxy"]["markers"].get("Identifier") is True,
        "notify_protocol_evidence": strings["purple_reverse_proxy"]["markers"].get("RegisterNotify") is True
        or strings["purple_reverse_proxy"]["markers"].get("SetLogLevel") is True,
        "proxy_dictionary_evidence": strings["device_library"]["markers"].get("CopyProxyDictionaryWithOptions") is True
        and strings["device_library"]["markers"].get("Ping") is True
        and strings["device_library"]["markers"].get("Pong") is True,
        "restore_options_evidence": strings["amsupport_library"]["markers"].get("UsePurpleReverseProxy") is True
        and strings["restored_update"]["markers"].get("PRPLogLevel") is True
        and strings["aru_service"]["markers"].get("DisableReverseProxy") is True,
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
    usb_inventory = collect_live_purple_usb_inventory(ecid=ecid)
    irecv_state = _irecv_public_state()
    if irecv_state is not None:
        return {
            "checked": True,
            "mode": irecv_state["state"],
            "usb_inventory": usb_inventory,
            "boot_state": {
                "checked": True,
                "source": "irecv",
                "state": irecv_state["state"],
                "ready": False,
                "recovery_mode": irecv_state["state"] == "recovery",
                "dfu_mode": irecv_state["state"] == "dfu",
                "irecv": irecv_state,
            },
            "irecv": irecv_state,
            "purple_reverse_proxy_available": False,
            "reason": "Recovery/DFU devices are not visible through usbmuxd.",
        }

    try:
        devices = [device for device in await usbmux.list_devices(usbmux_address=usbmux_address) if device.is_usb]
    except ConnectionFailedToUsbmuxdError as e:
        return {
            "checked": True,
            "mode": "unknown",
            "usb_inventory": usb_inventory,
            "boot_state": {
                "checked": True,
                "source": "usbmux",
                "state": "unknown",
                "ready": False,
                "reason": str(e),
            },
            "purple_reverse_proxy_available": False,
            "reason": str(e),
        }

    if not devices:
        return {
            "checked": True,
            "mode": "no_usb_device",
            "usb_inventory": usb_inventory,
            "boot_state": {
                "checked": True,
                "source": "usbmux",
                "state": "not_seen",
                "ready": False,
            },
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
            "usb_inventory": usb_inventory,
            "boot_state": {
                "checked": True,
                "source": "usbmux",
                "state": "normal_lockdown",
                "ready": False,
                "normal_mode_devices": normal_mode_devices,
            },
            "normal_mode_devices": normal_mode_devices,
            "purple_reverse_proxy_available": False,
            "reason": "PurpleReverseProxy is a RestoreOS ramdisk launchd service, not a normal-mode lockdown service.",
        }

    return {
        "checked": True,
        "mode": "not_normal_lockdown",
        "usb_inventory": usb_inventory,
        "boot_state": {
            "checked": True,
            "source": "usbmux",
            "state": "not_normal_lockdown",
            "ready": False,
            "usb_device_count": len(devices),
            "inaccessible_device_count": inaccessible_devices,
        },
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


def _boot_state_from_query_type(query_type: dict[str, Any]) -> dict[str, Any]:
    state = _mode_from_query_type(query_type)
    boot_state = {
        "checked": True,
        "source": "usbmux_query_type",
        "state": state,
        "ready": state == "restored",
        "reachable": bool(query_type.get("reachable")),
    }
    if "type" in query_type:
        boot_state["query_type"] = query_type["type"]
    if "restore_protocol_version" in query_type:
        boot_state["restore_protocol_version"] = query_type["restore_protocol_version"]
    return boot_state


async def collect_live_purple_reverse_proxy_probe(
    *,
    udid: Optional[str] = None,
    usbmux_address: Optional[str] = None,
    timeout: float = 1.0,
    include_services: bool = False,
    ports: Optional[list[dict[str, Any]]] = None,
    include_identifiers: bool = False,
) -> dict[str, Any]:
    """
    Probe PurpleReverseProxy-related RestoreOS ports through usbmuxd.

    This omits UDID, serial, ECID, and pair-record details by default so probe
    output can be pasted into issue/PR text. Raw usbmux identifiers are included
    only when include_identifiers is explicitly enabled.
    """
    usb_inventory = collect_live_purple_usb_inventory(ecid=udid)
    try:
        devices = [device for device in await usbmux.list_devices(usbmux_address=usbmux_address) if device.is_usb]
    except ConnectionFailedToUsbmuxdError:
        return {
            "checked": True,
            "mode": "unknown",
            "device_count": 0,
            "usb_inventory": usb_inventory,
            "reason": "usbmuxd_unavailable",
        }
    except OSError as e:
        return {
            "checked": True,
            "mode": "unknown",
            "device_count": 0,
            "usb_inventory": usb_inventory,
            "reason": f"usbmuxd_error:{e.__class__.__name__}",
        }

    if udid is not None:
        devices = [device for device in devices if device.matches_udid(udid)]

    if not devices:
        return {
            "checked": True,
            "mode": "no_usb_device",
            "device_count": 0,
            "usb_inventory": usb_inventory,
            "reason": (
                "No matching USB device is visible through usbmux."
                if udid is not None
                else "No USB device is visible through usbmux."
            ),
        }

    probe_ports = ports or PURPLE_REVERSE_PROXY_PORTS
    probed_devices = []
    for index, device in enumerate(devices):
        query_type = await _query_usbmux_type(device, timeout=timeout, usbmux_address=usbmux_address)
        ports = []
        for port_info in probe_ports:
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
            "boot_state": _boot_state_from_query_type(query_type),
            "ports": ports,
        }
        if include_identifiers:
            device_result["identifiers"] = {
                "device_id": getattr(device, "devid", getattr(device, "device_id", None)),
                "serial": device.serial,
                "connection_type": device.connection_type,
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
        "usb_inventory": usb_inventory,
        **({"include_identifiers": True} if include_identifiers else {}),
        "ports": probe_ports,
        "devices": probed_devices,
    }


def _purple_probe_has_restored_device(probe: dict[str, Any]) -> bool:
    return any(device.get("mode") == "restored" for device in probe.get("devices", []))


def _purple_probe_wait_snapshot(
    attempt: int,
    elapsed: float,
    probe: dict[str, Any],
    *,
    restored_streak: int,
    stable_ready: bool,
    stable_since: Optional[float],
    stable_attempts: int,
    stable_seconds: float,
    poll_interval: float,
) -> dict[str, Any]:
    return {
        "attempt": attempt,
        "elapsed": round(elapsed, 3),
        "mode": probe.get("mode"),
        "device_count": probe.get("device_count", 0),
        "restored": _purple_probe_has_restored_device(probe),
        "restored_streak": restored_streak,
        "stable_ready": stable_ready,
        "stable_since": round(stable_since, 3) if stable_since is not None else None,
        "stable_attempts": stable_attempts,
        "stable_seconds": stable_seconds,
        "poll_interval": round(poll_interval, 3),
    }


async def wait_for_purple_restoreos(
    *,
    udid: Optional[str] = None,
    usbmux_address: Optional[str] = None,
    timeout: float = 180.0,
    poll_interval: float = 1.0,
    probe_timeout: float = 1.0,
    stable_attempts: int = 2,
    stable_seconds: float = 0.0,
    poll_backoff_factor: float = 1.0,
    max_poll_interval: float = 5.0,
    include_services: bool = False,
    ports: Optional[list[dict[str, Any]]] = None,
    include_identifiers: bool = False,
    include_history: bool = False,
) -> dict[str, Any]:
    """
    Poll usbmux until at least one matching USB device reports RestoreOS/restored.
    """
    start = asyncio.get_running_loop().time()
    deadline = start + timeout
    attempt_count = 0
    last_probe: dict[str, Any] = {
        "checked": False,
        "reason": "No probe was attempted.",
    }
    history: list[dict[str, Any]] = []
    restored_streak = 0
    stable_since: Optional[float] = None
    current_poll_interval = poll_interval

    if stable_attempts < 1:
        raise ValueError("stable_attempts must be at least 1")
    if stable_seconds < 0:
        raise ValueError("stable_seconds must be non-negative")
    if poll_backoff_factor < 1.0:
        raise ValueError("poll_backoff_factor must be at least 1.0")
    if max_poll_interval < poll_interval:
        raise ValueError("max_poll_interval must be greater than or equal to poll_interval")

    while True:
        attempt_count += 1
        last_probe = await collect_live_purple_reverse_proxy_probe(
            udid=udid,
            usbmux_address=usbmux_address,
            timeout=probe_timeout,
            include_services=include_services,
            ports=ports,
            include_identifiers=include_identifiers,
        )
        elapsed = asyncio.get_running_loop().time() - start
        restored = _purple_probe_has_restored_device(last_probe)
        if restored:
            if restored_streak == 0:
                stable_since = elapsed
            restored_streak += 1
        else:
            restored_streak = 0
            stable_since = None
        stable_ready = bool(
            restored
            and restored_streak >= stable_attempts
            and stable_since is not None
            and (elapsed - stable_since) >= stable_seconds
        )
        snapshot = _purple_probe_wait_snapshot(
            attempt_count,
            elapsed,
            last_probe,
            restored_streak=restored_streak,
            stable_ready=stable_ready,
            stable_since=stable_since,
            stable_attempts=stable_attempts,
            stable_seconds=stable_seconds,
            poll_interval=current_poll_interval,
        )
        if include_history:
            history.append(snapshot)
        if stable_ready:
            result = {
                "checked": True,
                "ready": True,
                "expected_mode": "restored",
                "mode": last_probe.get("mode"),
                "attempt_count": attempt_count,
                "elapsed": round(elapsed, 3),
                "timeout": timeout,
                "poll_interval": poll_interval,
                "probe_timeout": probe_timeout,
                "stability": {
                    "stable_ready": True,
                    "required_stable_attempts": stable_attempts,
                    "required_stable_seconds": stable_seconds,
                    "restored_streak": restored_streak,
                    "stable_since": round(stable_since, 3) if stable_since is not None else None,
                    "poll_backoff_factor": poll_backoff_factor,
                    "max_poll_interval": max_poll_interval,
                },
                "last_probe": last_probe,
                "reason": "restoreos_reached",
            }
            if include_history:
                result["history"] = history
            return result

        now = asyncio.get_running_loop().time()
        if now >= deadline:
            elapsed = now - start
            result = {
                "checked": True,
                "ready": False,
                "expected_mode": "restored",
                "mode": last_probe.get("mode"),
                "attempt_count": attempt_count,
                "elapsed": round(elapsed, 3),
                "timeout": timeout,
                "poll_interval": poll_interval,
                "probe_timeout": probe_timeout,
                "stability": {
                    "stable_ready": False,
                    "required_stable_attempts": stable_attempts,
                    "required_stable_seconds": stable_seconds,
                    "restored_streak": restored_streak,
                    "stable_since": round(stable_since, 3) if stable_since is not None else None,
                    "poll_backoff_factor": poll_backoff_factor,
                    "max_poll_interval": max_poll_interval,
                },
                "last_probe": last_probe,
                "reason": "timeout_waiting_for_restoreos",
            }
            if include_history:
                result["history"] = history
            return result

        await asyncio.sleep(min(current_poll_interval, max(0.0, deadline - now)))
        if poll_backoff_factor > 1.0:
            current_poll_interval = min(max_poll_interval, current_poll_interval * poll_backoff_factor)


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
