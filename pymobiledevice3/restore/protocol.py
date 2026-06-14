import asyncio
import contextlib
import time
from collections.abc import Iterable
from typing import Any, Optional

from pymobiledevice3 import usbmux
from pymobiledevice3.lockdown import DEFAULT_LABEL
from pymobiledevice3.restore.restored_client import RestoredClient
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.usbmux import MuxDevice

DEFAULT_RESTORE_PROTOCOL_QUERY_KEYS = ("HardwareInfo", "SavedDebugInfo")
SENSITIVE_RESTORE_PROTOCOL_KEYS = (
    "apnonce",
    "chipid",
    "ecid",
    "identifier",
    "nonce",
    "sepnonce",
    "serial",
    "srnm",
    "uniquechipid",
    "udid",
)


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower()
    return any(sensitive in normalized for sensitive in SENSITIVE_RESTORE_PROTOCOL_KEYS)


def sanitize_restore_protocol_value(value: Any, *, include_identifiers: bool = False) -> Any:
    if include_identifiers:
        return value

    if isinstance(value, dict):
        return {
            key: "<redacted>"
            if _is_sensitive_key(str(key))
            else sanitize_restore_protocol_value(val, include_identifiers=include_identifiers)
            for key, val in value.items()
        }

    if isinstance(value, list):
        return [sanitize_restore_protocol_value(item, include_identifiers=include_identifiers) for item in value]

    if isinstance(value, tuple):
        return [sanitize_restore_protocol_value(item, include_identifiers=include_identifiers) for item in value]

    return value


def _mode_from_query_type(query_type: Any) -> str:
    if not isinstance(query_type, dict):
        return "unknown"

    device_type = query_type.get("Type")
    if device_type == "com.apple.mobile.restored":
        return "restored"
    if device_type == "com.apple.mobile.lockdown":
        return "normal_lockdown"
    return "unknown"


def _device_summary(device: MuxDevice, *, include_identifiers: bool) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "connection_type": device.connection_type,
        "device_id": device.devid,
    }
    if include_identifiers:
        summary["serial"] = device.serial
    return summary


def _dedupe_query_keys(query_keys: Iterable[str]) -> list[str]:
    deduped = []
    for key in query_keys:
        if key not in deduped:
            deduped.append(key)
    return deduped


async def _send_recv_plist(
    service: ServiceConnection,
    message: dict[str, Any],
    *,
    timeout: float,
    trace_messages: list[dict[str, Any]],
    include_identifiers: bool,
) -> Any:
    start = time.monotonic()
    try:
        response = await asyncio.wait_for(service.send_recv_plist(message), timeout=timeout)
    except Exception as e:
        trace_messages.append({
            "request": sanitize_restore_protocol_value(message, include_identifiers=include_identifiers),
            "duration": round(time.monotonic() - start, 6),
            "error_type": type(e).__name__,
            "error": str(e),
        })
        raise

    trace_messages.append({
        "request": sanitize_restore_protocol_value(message, include_identifiers=include_identifiers),
        "response": sanitize_restore_protocol_value(response, include_identifiers=include_identifiers),
        "duration": round(time.monotonic() - start, 6),
    })
    return response


async def probe_restore_protocol_device(
    device: MuxDevice,
    *,
    usbmux_address: Optional[str] = None,
    timeout: float = 1.0,
    query_keys: Optional[Iterable[str]] = None,
    include_identifiers: bool = False,
    include_trace: bool = False,
) -> dict[str, Any]:
    service: Optional[ServiceConnection] = None
    trace_messages: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        "device": _device_summary(device, include_identifiers=include_identifiers),
        "port": RestoredClient.SERVICE_PORT,
        "reachable": False,
    }

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
        result["reachable"] = True

        query_type = await _send_recv_plist(
            service,
            {"Request": "QueryType"},
            timeout=timeout,
            trace_messages=trace_messages,
            include_identifiers=include_identifiers,
        )
        sanitized_query_type = sanitize_restore_protocol_value(query_type, include_identifiers=include_identifiers)
        result["mode"] = _mode_from_query_type(query_type)
        result["query_type"] = sanitized_query_type
        if isinstance(query_type, dict) and "RestoreProtocolVersion" in query_type:
            result["restore_protocol_version"] = query_type["RestoreProtocolVersion"]

        if query_keys:
            result["query_values"] = {}
            for key in _dedupe_query_keys(query_keys):
                message = {"Request": "QueryValue", "Label": DEFAULT_LABEL, "QueryKey": key}
                try:
                    value = await _send_recv_plist(
                        service,
                        message,
                        timeout=timeout,
                        trace_messages=trace_messages,
                        include_identifiers=include_identifiers,
                    )
                    result["query_values"][key] = sanitize_restore_protocol_value(
                        value, include_identifiers=include_identifiers
                    )
                except Exception as e:
                    result["query_values"][key] = {
                        "error_type": type(e).__name__,
                        "error": str(e),
                    }
    except Exception as e:
        result["error_type"] = type(e).__name__
        result["error"] = str(e)
        result.setdefault("mode", "unreachable")
    finally:
        if include_trace:
            result["trace"] = trace_messages
        if service is not None:
            with contextlib.suppress(Exception):
                await service.close()

    return result


async def collect_restore_protocol_info(
    *,
    udid: Optional[str] = None,
    usbmux_address: Optional[str] = None,
    timeout: float = 1.0,
    include_values: bool = False,
    query_keys: Optional[Iterable[str]] = None,
    include_identifiers: bool = False,
    include_trace: bool = False,
) -> dict[str, Any]:
    try:
        devices = [device for device in await usbmux.list_devices(usbmux_address=usbmux_address) if device.is_usb]
    except Exception as e:
        return {
            "mode": "usbmux_unavailable",
            "device_count": 0,
            "devices": [],
            "error_type": type(e).__name__,
            "error": str(e),
        }

    if udid is not None:
        devices = [device for device in devices if device.matches_udid(udid)]

    keys_to_query: list[str] = []
    if include_values:
        keys_to_query.extend(DEFAULT_RESTORE_PROTOCOL_QUERY_KEYS)
    if query_keys:
        keys_to_query.extend(query_keys)

    probes = [
        await probe_restore_protocol_device(
            device,
            usbmux_address=usbmux_address,
            timeout=timeout,
            query_keys=keys_to_query,
            include_identifiers=include_identifiers,
            include_trace=include_trace,
        )
        for device in devices
    ]
    modes = sorted({probe.get("mode", "unknown") for probe in probes})

    return {
        "mode": modes[0] if len(modes) == 1 else "multiple" if modes else "no_usb_device",
        "device_count": len(probes),
        "devices": probes,
    }
