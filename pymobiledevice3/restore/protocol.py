import asyncio
import contextlib
import re
import time
from collections.abc import Iterable
from typing import Any, Optional

from pymobiledevice3 import usbmux
from pymobiledevice3.lockdown import DEFAULT_LABEL
from pymobiledevice3.restore.consts import PROGRESS_BAR_OPERATIONS
from pymobiledevice3.restore.restore_options import SUPPORTED_DATA_TYPES, SUPPORTED_MESSAGE_TYPES
from pymobiledevice3.restore.restored_client import RestoredClient
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.usbmux import MuxDevice

DEFAULT_RESTORE_PROTOCOL_QUERY_KEYS = ("HardwareInfo", "SavedDebugInfo")
KNOWN_RESTORE_STATUS_ERRORS = {
    0xFFFFFFFFFFFFFFFF: "verification error",
    6: "disk failure",
    14: "fail",
    27: "failed to mount filesystems",
    50: "failed to load SEP firmware",
    51: "failed to load SEP firmware",
    53: "failed to recover FDR data",
    1015: "X-Gold Baseband Update Failed. Defective Unit?",
}
PYMOBILEDEVICE3_RESTORE_MESSAGE_HANDLERS = frozenset({
    "AsyncDataRequestMsg",
    "AsyncWait",
    "BasebandUpdaterOutputData",
    "BBUpdateStatusMsg",
    "CheckpointMsg",
    "CrashLog",
    "DataRequestMsg",
    "FDRSubmit",
    "PreviousRestoreLogMsg",
    "ProgressMsg",
    "ProvisioningAck",
    "ProvisioningInfo",
    "ProvisioningStatusMsg",
    "ReceivedFinalStatusMsg",
    "RestoreAttestation",
    "RestoredCrash",
    "StatusMsg",
    "USBLog",
})
PYMOBILEDEVICE3_DATA_REQUEST_HANDLERS = frozenset({
    "BasebandData",
    "BasebandUpdaterOutputData",
    "BootabilityBundle",
    "BuildIdentityDict",
    "DeviceTree",
    "EANData",
    "FDRTrustData",
    "FirmwareUpdaterData",
    "FirmwareUpdaterPreflight",
    "FUDData",
    "HostSystemTime",
    "KernelCache",
    "NORData",
    "PersonalizedBootObjectV3",
    "PersonalizedData",
    "ReceiptManifest",
    "RecoveryOSASRImage",
    "RecoveryOSLocalPolicy",
    "RecoveryOSRootTicketData",
    "RootTicket",
    "SourceBootObjectV4",
    "StreamedImageDecryptionKey",
    "SystemImageCanonicalMetadata",
    "SystemImageData",
    "SystemImageRootHash",
    "URLAsset",
})
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
_UDID_RE = re.compile(r"\b(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{16}|[0-9a-fA-F]{40})\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SENSITIVE_STRING_PAIR_RE = re.compile(
    r"\b(udid|serial(?:number)?|ecid|uniquechipid|apnonce|sepnonce)\b(\s*[:=]\s*)([^\s,;]+)",
    re.IGNORECASE,
)


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower()
    return any(sensitive in normalized for sensitive in SENSITIVE_RESTORE_PROTOCOL_KEYS)


def _redact_sensitive_string(value: str) -> str:
    value = _UDID_RE.sub("<redacted>", value)
    value = _IPV4_RE.sub("<redacted>", value)
    return _SENSITIVE_STRING_PAIR_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}<redacted>", value)


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

    if isinstance(value, bytes):
        return f"<bytes:{len(value)}>"

    if isinstance(value, str):
        return _redact_sensitive_string(value)

    return value


def _restore_message_type(message: dict[str, Any]) -> str:
    return str(message.get("MsgType") or "Unknown")


def _progress_operation_name(operation: Any) -> Any:
    if isinstance(operation, int):
        return PROGRESS_BAR_OPERATIONS.get(operation, operation)
    return operation


def _first_present(message: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in message:
            return message[key]
    return None


def _payload_size(value: Any) -> Optional[int]:
    if isinstance(value, (bytes, str, list, tuple, dict)):
        return len(value)
    return None


def _summary_text_for_restore_message(msg_type: str, fields: dict[str, Any], severity: str) -> str:
    if msg_type in ("DataRequestMsg", "AsyncDataRequestMsg"):
        data_type = fields.get("data_type") or "unknown"
        return f"{msg_type} requested {data_type}"
    if msg_type == "ProgressMsg":
        operation = fields.get("operation") or "unknown"
        progress = fields.get("progress")
        return f"{operation} {progress}%" if progress is not None else str(operation)
    if msg_type == "StatusMsg":
        status = fields.get("status")
        if status == 0:
            return "restore completed successfully"
        error = fields.get("error")
        return f"restore status {status}: {error}" if error else f"restore status {status}"
    if msg_type == "PreviousRestoreLogMsg":
        return "previous restore log available"
    if msg_type == "RestoredCrash":
        return "restored crash backtrace available"
    if msg_type == "RestoreAttestation":
        return "restore attestation request"
    if msg_type == "BBUpdateStatusMsg":
        return "baseband update accepted" if fields.get("accepted") is True else "baseband update failed"
    if msg_type == "CheckpointMsg":
        checkpoint = fields.get("checkpoint")
        return f"checkpoint {checkpoint}" if checkpoint is not None else "restore checkpoint"
    if msg_type == "CrashLog":
        return "restore crash log available"
    if msg_type == "FDRSubmit":
        return "FDR submit request"
    if msg_type == "ProvisioningInfo":
        return "provisioning info available"
    if msg_type == "ProvisioningStatusMsg":
        status = fields.get("status")
        return f"provisioning status {status}" if status is not None else "provisioning status update"
    if msg_type == "ProvisioningAck":
        return "provisioning acknowledged"
    if msg_type == "ReceivedFinalStatusMsg":
        return "final restore status acknowledged"
    if msg_type == "USBLog":
        return "USB restore log available"
    if severity == "warning":
        return f"unhandled restore message {msg_type}"
    return msg_type


def summarize_restore_message(
    message: dict[str, Any],
    *,
    include_raw: bool = False,
    include_identifiers: bool = False,
) -> dict[str, Any]:
    msg_type = _restore_message_type(message)
    fields: dict[str, Any] = {}
    severity = "info"

    if msg_type in ("DataRequestMsg", "AsyncDataRequestMsg"):
        data_type = message.get("DataType")
        fields = {
            "data_type": data_type,
            "data_port": message.get("DataPort"),
            "supported_by_restore_options": SUPPORTED_DATA_TYPES.get(data_type) if isinstance(data_type, str) else None,
            "implemented_by_pymobiledevice3": data_type in PYMOBILEDEVICE3_DATA_REQUEST_HANDLERS,
        }
        severity = "request"
        if isinstance(data_type, str) and data_type not in PYMOBILEDEVICE3_DATA_REQUEST_HANDLERS:
            severity = "warning"
    elif msg_type == "ProgressMsg":
        operation = message.get("Operation")
        fields = {
            "operation_raw": operation,
            "operation": _progress_operation_name(operation),
            "progress": message.get("Progress"),
        }
        severity = "progress"
    elif msg_type == "StatusMsg":
        status = message.get("Status")
        fields = {
            "status": status,
            "error": KNOWN_RESTORE_STATUS_ERRORS.get(status) if isinstance(status, int) else None,
            "log_available": bool(message.get("Log")),
        }
        severity = "success" if status == 0 else "error"
        if message.get("Log") is not None:
            fields["log"] = sanitize_restore_protocol_value(message["Log"], include_identifiers=include_identifiers)
    elif msg_type == "PreviousRestoreLogMsg":
        log = message.get("PreviousRestoreLog")
        fields = {
            "log_available": log is not None,
            "log_size": len(log) if isinstance(log, (str, bytes)) else None,
        }
        if log is not None:
            fields["log"] = sanitize_restore_protocol_value(log, include_identifiers=include_identifiers)
        severity = "warning"
    elif msg_type == "RestoredCrash":
        backtrace = message.get("RestoredBacktrace") or []
        fields = {
            "backtrace_frames": len(backtrace) if isinstance(backtrace, list) else None,
            "backtrace": sanitize_restore_protocol_value(backtrace, include_identifiers=include_identifiers),
        }
        severity = "error"
    elif msg_type == "CrashLog":
        log = _first_present(message, "CrashLog", "Log")
        fields = {
            "log_available": log is not None,
            "log_size": _payload_size(log),
        }
        if log is not None:
            fields["log"] = sanitize_restore_protocol_value(log, include_identifiers=include_identifiers)
        severity = "warning"
    elif msg_type == "RestoreAttestation":
        fields = {
            "handled_by_pymobiledevice3": True,
            "response": {"RestoreShouldAttest": False},
        }
        severity = "request"
    elif msg_type == "BBUpdateStatusMsg":
        fields = {"accepted": message.get("Accepted")}
        severity = "info" if message.get("Accepted") else "error"
    elif msg_type == "CheckpointMsg":
        fields = {
            "checkpoint": message.get("Checkpoint") or message.get("CheckpointID"),
            "operation": message.get("Operation"),
        }
    elif msg_type == "FDRSubmit":
        fdr_keys = sorted(key for key in message if key != "MsgType")
        fields = {
            "keys": fdr_keys,
            "urls": {
                key: sanitize_restore_protocol_value(value, include_identifiers=include_identifiers)
                for key, value in message.items()
                if key != "MsgType" and "URL" in key.upper()
            },
            "memory_commit": message.get("FDRMemoryCommit"),
        }
        severity = "request"
    elif msg_type == "ProvisioningInfo":
        fields = {
            "keys": sorted(key for key in message if key != "MsgType"),
            "status": _first_present(message, "Status", "ProvisioningStatus"),
        }
    elif msg_type == "ProvisioningStatusMsg":
        status = _first_present(message, "Status", "ProvisioningStatus", "ProvisioningStatusCode")
        error = _first_present(message, "Error", "ErrorCode", "ErrorDescription")
        fields = {
            "status": status,
            "operation": _first_present(message, "Operation", "Step", "Stage"),
            "error": sanitize_restore_protocol_value(error, include_identifiers=include_identifiers),
        }
        if error not in (None, 0, ""):
            severity = "error"
    elif msg_type == "ProvisioningAck":
        fields = {
            "acknowledged": _first_present(message, "Acknowledged", "Ack"),
            "status": _first_present(message, "Status", "ProvisioningStatus"),
        }
    elif msg_type == "ReceivedFinalStatusMsg":
        status = _first_present(message, "Status", "FinalStatus", "Result")
        fields = {
            "status": status,
            "error": KNOWN_RESTORE_STATUS_ERRORS.get(status) if isinstance(status, int) else None,
        }
        if isinstance(status, int):
            severity = "success" if status == 0 else "error"
    elif msg_type == "USBLog":
        log = _first_present(message, "USBLog", "Log")
        fields = {
            "log_available": log is not None,
            "log_size": _payload_size(log),
        }
        if log is not None:
            fields["log"] = sanitize_restore_protocol_value(log, include_identifiers=include_identifiers)
    elif msg_type == "AsyncWait":
        fields = {"async_context": message.get("AsyncContext")}
    elif msg_type == "BasebandUpdaterOutputData":
        fields = {"data_port": message.get("DataPort")}
        severity = "request"
    elif msg_type not in PYMOBILEDEVICE3_RESTORE_MESSAGE_HANDLERS:
        severity = "warning"

    summary = {
        "msg_type": msg_type,
        "known_to_restore_options": msg_type in SUPPORTED_MESSAGE_TYPES,
        "supported_by_restore_options": SUPPORTED_MESSAGE_TYPES.get(msg_type),
        "implemented_by_pymobiledevice3": msg_type in PYMOBILEDEVICE3_RESTORE_MESSAGE_HANDLERS,
        "severity": severity,
        "summary": _summary_text_for_restore_message(msg_type, fields, severity),
        "fields": fields,
    }
    if include_raw:
        summary["raw"] = sanitize_restore_protocol_value(message, include_identifiers=include_identifiers)
    return summary


def build_restore_message_report(
    messages: Iterable[dict[str, Any]],
    *,
    include_raw: bool = False,
    include_identifiers: bool = False,
) -> dict[str, Any]:
    summarized = [
        summarize_restore_message(message, include_raw=include_raw, include_identifiers=include_identifiers)
        for message in messages
    ]
    failures = [message for message in summarized if message["severity"] == "error"]
    warnings = [message for message in summarized if message["severity"] == "warning"]
    data_requests = [
        message for message in summarized if message["msg_type"] in ("DataRequestMsg", "AsyncDataRequestMsg")
    ]
    progress = [message for message in summarized if message["msg_type"] == "ProgressMsg"]
    final_statuses = [message for message in summarized if message["msg_type"] == "StatusMsg"]
    unimplemented = [
        message
        for message in summarized
        if not message["implemented_by_pymobiledevice3"]
        or (
            message["msg_type"] in ("DataRequestMsg", "AsyncDataRequestMsg")
            and not message["fields"].get("implemented_by_pymobiledevice3")
        )
    ]

    return {
        "summary": {
            "total": len(summarized),
            "failures": len(failures),
            "warnings": len(warnings),
            "data_requests": len(data_requests),
            "progress_updates": len(progress),
            "unimplemented": len(unimplemented),
            "completed": any(message["fields"].get("status") == 0 for message in final_statuses),
            "last_progress": progress[-1]["fields"] if progress else None,
            "final_status": final_statuses[-1]["fields"] if final_statuses else None,
        },
        "failures": failures,
        "warnings": warnings,
        "unimplemented": unimplemented,
        "messages": summarized,
    }


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
