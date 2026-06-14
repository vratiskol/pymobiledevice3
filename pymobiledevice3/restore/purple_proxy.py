import asyncio
import contextlib
import ipaddress
import plistlib
from collections import Counter
from enum import Enum
from typing import Any, Optional, Union

from pymobiledevice3.service_connection import ServiceConnection

PURPLE_PROXY_SOCKS_PORT = 1081
PURPLE_PROXY_CONTROL_PORT = 1082
PURPLE_PROXY_NOTIFY_PORT = 1084
PURPLE_PROXY_CONTROL_PROTOCOL_VERSION = 1
PURPLE_PROXY_LOOPBACK_HOST = "127.0.0.1"
PURPLE_PROXY_COMMAND_KEY = "Command"
PURPLE_PROXY_CTRL_PROTO_VERSION_KEY = "CtrlProtoVersion"
PURPLE_PROXY_CONN_PORT_KEY = "ConnPort"
PURPLE_PROXY_CONN_PROTO_VERSION_KEY = "ConnProtoVersion"
PURPLE_PROXY_IDENTIFIER_KEY = "Identifier"
PURPLE_PROXY_LEVEL_KEY = "Level"
PURPLE_PROXY_SOCKS_PROXY_HOST_KEY = "SOCKSProxyHost"
PURPLE_PROXY_SOCKS_PROXY_PORT_KEY = "SOCKSProxyPort"
PURPLE_PROXY_SOCKS_VERSION = 5
PURPLE_PROXY_SOCKS_NO_AUTHENTICATION = 0
PURPLE_PROXY_SOCKS_CONNECT_COMMAND = 1
PURPLE_PROXY_SOCKS_RESERVED = 0
PURPLE_PROXY_SOCKS_ATYP_IPV4 = 1
PURPLE_PROXY_SOCKS_ATYP_DOMAIN = 3
PURPLE_PROXY_SOCKS_ATYP_IPV6 = 4
SENSITIVE_PURPLE_PROXY_KEYS = (
    "ecid",
    "serial",
    "udid",
    "uniquechipid",
    "identifier",
    "hostid",
    "systembuid",
    "pair",
)


class PurpleProxyCommand(str, Enum):
    HELLO_CONTROL = "HelloCtrl"
    BEGIN_CONTROL = "BeginCtrl"
    WAIT_SOCKET = "WaitSocket"
    REGISTER_NOTIFY = "RegisterNotify"
    SET_LOG_LEVEL = "SetLogLevel"
    PING = "Ping"


def format_purple_proxy_socks_url(host: str = PURPLE_PROXY_LOOPBACK_HOST, port: int = PURPLE_PROXY_SOCKS_PORT) -> str:
    return f"socks://{host}:{port}/"


def _validate_socks_port(port: int) -> None:
    if not 1 <= port <= 0xFFFF:
        raise ValueError("SOCKS port must be between 1 and 65535")


def _socks_method_name(method: int) -> str:
    if method == PURPLE_PROXY_SOCKS_NO_AUTHENTICATION:
        return "no_authentication_required"
    if method == 0xFF:
        return "no_acceptable_methods"
    return f"method_0x{method:02x}"


def _socks_reply_name(reply: int) -> str:
    return {
        0x00: "succeeded",
        0x01: "general_failure",
        0x02: "connection_not_allowed",
        0x03: "network_unreachable",
        0x04: "host_unreachable",
        0x05: "connection_refused",
        0x06: "ttl_expired",
        0x07: "command_not_supported",
        0x08: "address_type_not_supported",
    }.get(reply, f"reply_0x{reply:02x}")


def _socks_address_type_name(address_type: int) -> str:
    return {
        PURPLE_PROXY_SOCKS_ATYP_IPV4: "ipv4",
        PURPLE_PROXY_SOCKS_ATYP_DOMAIN: "domain",
        PURPLE_PROXY_SOCKS_ATYP_IPV6: "ipv6",
    }.get(address_type, f"address_type_0x{address_type:02x}")


def _build_socks_connect_request(host: str, port: int) -> tuple[bytes, str]:
    _validate_socks_port(port)
    if not host:
        raise ValueError("connect host must not be empty")

    try:
        ip_address = ipaddress.ip_address(host)
    except ValueError:
        address = host.encode("idna")
        if len(address) > 255:
            raise ValueError("connect host is too long for a SOCKS5 domain address") from None
        address_type = PURPLE_PROXY_SOCKS_ATYP_DOMAIN
        address_payload = bytes([len(address)]) + address
    else:
        address_type = PURPLE_PROXY_SOCKS_ATYP_IPV4 if ip_address.version == 4 else PURPLE_PROXY_SOCKS_ATYP_IPV6
        address_payload = ip_address.packed

    return (
        bytes([
            PURPLE_PROXY_SOCKS_VERSION,
            PURPLE_PROXY_SOCKS_CONNECT_COMMAND,
            PURPLE_PROXY_SOCKS_RESERVED,
            address_type,
        ])
        + address_payload
        + port.to_bytes(2, "big"),
        _socks_address_type_name(address_type),
    )


def build_purple_proxy_dictionary(
    *,
    url: str,
    host: str = PURPLE_PROXY_LOOPBACK_HOST,
    socks_port: int = PURPLE_PROXY_SOCKS_PORT,
    test_reachability: bool = True,
) -> dict[str, Any]:
    return {
        "checked": True,
        "source": "libReverseProxyDevice",
        "function": "CopyProxyDictionaryWithOptions",
        "url": url,
        "test_reachability": test_reachability,
        "proxy_url": format_purple_proxy_socks_url(host=host, port=socks_port),
        "proxy_dictionary": {
            PURPLE_PROXY_SOCKS_PROXY_HOST_KEY: host,
            PURPLE_PROXY_SOCKS_PROXY_PORT_KEY: socks_port,
        },
        "requires_ping": True,
    }


def is_purple_proxy_pong_response(response: dict[str, Any]) -> bool:
    return response.get(PURPLE_PROXY_COMMAND_KEY) == "Pong" or response.get("Pong") is True


def sanitize_purple_proxy_response(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            key_text = str(key).lower()
            if any(sensitive in key_text for sensitive in SENSITIVE_PURPLE_PROXY_KEYS):
                sanitized[key] = "<redacted>"
            else:
                sanitized[key] = sanitize_purple_proxy_response(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_purple_proxy_response(item) for item in value]
    return value


def _visible_purple_proxy_response(value: Any, *, include_identifiers: bool) -> Any:
    if include_identifiers:
        return value
    return sanitize_purple_proxy_response(value)


def _trace_time() -> float:
    return round(asyncio.get_running_loop().time(), 6)


def _trace_duration(start: float) -> float:
    return round(asyncio.get_running_loop().time() - start, 6)


def _trace_append(trace: Optional[list[dict[str, Any]]], event: str, **fields: Any) -> None:
    if trace is None:
        return
    entry = {
        "index": len(trace),
        "time": _trace_time(),
        "event": event,
    }
    entry.update(fields)
    trace.append(entry)


def _mark_identifier_output(result: dict[str, Any], *, include_identifiers: bool) -> None:
    if include_identifiers:
        result["include_identifiers"] = True


def _contains_text(value: Any, needles: tuple[str, ...]) -> bool:
    if isinstance(value, dict):
        return any(_contains_text(key, needles) or _contains_text(item, needles) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_text(item, needles) for item in value)
    text = str(value).lower()
    return any(needle in text for needle in needles)


def classify_purple_proxy_notify_message(message: dict[str, Any]) -> str:
    if _contains_text(message, ("proxyonline", "proxy online", "purplereverseproxy.proxyonline")):
        return "proxy_online"
    if _contains_text(message, ("error", "fault", "failed", "failure")):
        return "error"
    if _contains_text(message, ("log", "level")):
        return "log"
    if _contains_text(message, ("status", "state")):
        return "status"
    return "unknown"


def summarize_purple_proxy_notify_messages(messages: list[dict[str, Any]]) -> dict[str, Any]:
    event_counts = Counter(classify_purple_proxy_notify_message(message) for message in messages)
    return {
        "classified": True,
        "message_count": len(messages),
        "observed_events": sorted(event for event, count in event_counts.items() if count),
        "event_counts": dict(sorted(event_counts.items())),
        "proxy_online": event_counts["proxy_online"] > 0,
        "error_count": event_counts["error"],
        "unknown_count": event_counts["unknown"],
    }


def _purple_proxy_skipped_phase(reason: str) -> dict[str, Any]:
    return {
        "checked": False,
        "reason": reason,
    }


def _purple_proxy_control_phase_result(
    command: PurpleProxyCommand,
    *,
    port: int,
    protocol_version: int,
    conn_port: int,
    include_response: bool,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "checked": True,
        "experimental": True,
        "command": command.value,
        "port": port,
        "include_response": include_response,
    }
    if command in (PurpleProxyCommand.HELLO_CONTROL, PurpleProxyCommand.BEGIN_CONTROL):
        result["protocol_version"] = protocol_version
    if command is PurpleProxyCommand.WAIT_SOCKET:
        result["conn_port"] = conn_port
    return result


def _purple_proxy_notify_phase_result(
    command: PurpleProxyCommand,
    *,
    port: int,
    include_response: bool,
    level: Optional[int] = None,
    listen_timeout: float = 0.0,
    max_messages: int = 8,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "checked": True,
        "experimental": True,
        "command": command.value,
        "port": port,
        "include_response": include_response,
        "expect_response": False,
    }
    if command is PurpleProxyCommand.SET_LOG_LEVEL:
        result["level"] = level
    if listen_timeout > 0:
        result.update({
            "listen_timeout": listen_timeout,
            "max_messages": max_messages,
        })
    return result


def _purple_proxy_unreachable_phase(result: dict[str, Any], e: BaseException) -> dict[str, Any]:
    result.update({
        "reachable": False,
        "error_type": e.__class__.__name__,
    })
    return result


async def _run_connected_control_phase(
    client: "PurpleProxyClient",
    command: PurpleProxyCommand,
    *,
    timeout: float,
    port: int,
    protocol_version: int,
    conn_port: int,
    include_response: bool,
    include_identifiers: bool = False,
    trace: Optional[list[dict[str, Any]]] = None,
    phase_name: Optional[str] = None,
) -> dict[str, Any]:
    phase = phase_name or command.value
    start = asyncio.get_running_loop().time()
    _trace_append(trace, "phase_start", phase=phase, channel="control", command=command.value, port=port)
    result = _purple_proxy_control_phase_result(
        command,
        port=port,
        protocol_version=protocol_version,
        conn_port=conn_port,
        include_response=include_response,
    )
    try:
        if command is PurpleProxyCommand.BEGIN_CONTROL:
            response = await asyncio.wait_for(client.begin_control(protocol_version=protocol_version), timeout=timeout)
        elif command is PurpleProxyCommand.WAIT_SOCKET:
            response = await asyncio.wait_for(client.wait_socket(conn_port=conn_port), timeout=timeout)
        elif command is PurpleProxyCommand.PING:
            response = await asyncio.wait_for(client.send_ping(), timeout=timeout)
        else:
            raise ValueError(f"unsupported PurpleReverseProxy session control command: {command.value}")
    except Exception as e:
        result = _purple_proxy_unreachable_phase(result, e)
        if trace is not None:
            result["trace_timing"] = {"duration": _trace_duration(start)}
        _trace_append(
            trace,
            "phase_end",
            phase=phase,
            channel="control",
            command=command.value,
            reachable=False,
            error_type=e.__class__.__name__,
            duration=result.get("trace_timing", {}).get("duration"),
        )
        return result

    _mark_identifier_output(result, include_identifiers=include_identifiers)
    visible_response = _visible_purple_proxy_response(response, include_identifiers=include_identifiers)
    result.update({
        "reachable": True,
        "response_keys": sorted(str(key) for key in visible_response),
    })
    if command is PurpleProxyCommand.PING:
        result["pong"] = is_purple_proxy_pong_response(visible_response)
    if include_response:
        result["response"] = visible_response
    if trace is not None:
        result["trace_timing"] = {"duration": _trace_duration(start)}
    _trace_append(
        trace,
        "phase_end",
        phase=phase,
        channel="control",
        command=command.value,
        reachable=True,
        duration=result.get("trace_timing", {}).get("duration"),
    )
    return result


async def _run_connected_notify_phase(
    client: "PurpleProxyClient",
    command: PurpleProxyCommand,
    *,
    timeout: float,
    port: int,
    include_response: bool,
    level: Optional[int] = None,
    listen_timeout: float = 0.0,
    max_messages: int = 8,
    include_identifiers: bool = False,
    trace: Optional[list[dict[str, Any]]] = None,
    phase_name: Optional[str] = None,
) -> dict[str, Any]:
    phase = phase_name or command.value
    start = asyncio.get_running_loop().time()
    _trace_append(trace, "phase_start", phase=phase, channel="notify", command=command.value, port=port)
    result = _purple_proxy_notify_phase_result(
        command,
        port=port,
        include_response=include_response,
        level=level,
        listen_timeout=listen_timeout,
        max_messages=max_messages,
    )
    try:
        if command is PurpleProxyCommand.REGISTER_NOTIFY:
            await asyncio.wait_for(client.register_notify(), timeout=timeout)
        elif command is PurpleProxyCommand.SET_LOG_LEVEL:
            if level is None:
                raise ValueError("level is required for SetLogLevel")
            await asyncio.wait_for(client.set_log_level(level), timeout=timeout)
        else:
            await asyncio.wait_for(client.send_command_message(command), timeout=timeout)
    except Exception as e:
        result = _purple_proxy_unreachable_phase(result, e)
        if trace is not None:
            result["trace_timing"] = {"duration": _trace_duration(start)}
        _trace_append(
            trace,
            "phase_end",
            phase=phase,
            channel="notify",
            command=command.value,
            reachable=False,
            error_type=e.__class__.__name__,
            duration=result.get("trace_timing", {}).get("duration"),
        )
        return result

    _mark_identifier_output(result, include_identifiers=include_identifiers)
    result.update({
        "reachable": True,
        "sent": True,
    })
    if trace is not None:
        result["trace_timing"] = {"duration": _trace_duration(start)}
    _trace_append(
        trace,
        "phase_end",
        phase=phase,
        channel="notify",
        command=command.value,
        reachable=True,
        duration=result.get("trace_timing", {}).get("duration"),
    )
    return result


def _add_notify_messages_to_phase(
    phase: dict[str, Any],
    messages: list[dict[str, Any]],
    *,
    include_response: bool,
    include_identifiers: bool = False,
) -> dict[str, Any]:
    visible_messages = [
        _visible_purple_proxy_response(message, include_identifiers=include_identifiers) for message in messages
    ]
    _mark_identifier_output(phase, include_identifiers=include_identifiers)
    phase["message_count"] = len(visible_messages)
    phase["message_keys"] = [sorted(str(key) for key in message) for message in visible_messages]
    phase["notify_summary"] = summarize_purple_proxy_notify_messages(visible_messages)
    if include_response:
        phase["messages"] = visible_messages
    return phase


def summarize_purple_proxy_session(phases: dict[str, Any]) -> dict[str, Any]:
    log_phase = phases.get("set_log_level", {})
    socks_phase = phases.get("socks_probe", {})
    log_level_requested = bool(log_phase.get("checked"))
    socks_requested = bool(socks_phase.get("checked"))
    control_reachable = bool(phases.get("begin_control", {}).get("reachable"))
    ping_pong = bool(phases.get("ping", {}).get("reachable") and phases.get("ping", {}).get("pong"))
    wait_socket_reachable = bool(phases.get("wait_socket", {}).get("reachable"))
    notify_registered = bool(phases.get("register_notify", {}).get("reachable"))
    proxy_dictionary_ready = bool(phases.get("proxy_dictionary", {}).get("checked"))
    socks_probe_ok = None
    set_log_level_sent = None
    if log_level_requested:
        set_log_level_sent = bool(log_phase.get("reachable") and log_phase.get("sent"))
    if socks_requested:
        socks_probe_ok = bool(socks_phase.get("summary", {}).get("ok"))

    required = [
        control_reachable,
        ping_pong,
        wait_socket_reachable,
        notify_registered,
        proxy_dictionary_ready,
    ]
    if log_level_requested:
        required.append(bool(set_log_level_sent))
    if socks_requested:
        required.append(bool(socks_probe_ok))

    return {
        "control_reachable": control_reachable,
        "ping_pong": ping_pong,
        "wait_socket_reachable": wait_socket_reachable,
        "notify_registered": notify_registered,
        "set_log_level_sent": set_log_level_sent,
        "socks_probe_ok": socks_probe_ok,
        "proxy_dictionary_ready": proxy_dictionary_ready,
        "ok": all(required),
    }


class PurpleProxyClient:
    """
    Minimal PurpleReverseProxy dictionary protocol client.

    The firmware strings expose RPSocketReadDictionary/RPSocketWriteDictionary and
    control commands such as HelloCtrl, BeginCtrl, CtrlProtoVersion, and WaitSocket.
    This class deliberately implements only the reusable plist/dictionary framing
    and conservative command helpers; higher-level restore/FDR behavior still needs
    live validation.
    """

    def __init__(
        self,
        service: ServiceConnection,
        *,
        endianity: str = ">",
        trace: Optional[list[dict[str, Any]]] = None,
        trace_channel: Optional[str] = None,
        include_identifiers: bool = False,
    ) -> None:
        self.service = service
        self.endianity = endianity
        self.trace = trace
        self.trace_channel = trace_channel
        self.include_identifiers = include_identifiers

    @classmethod
    async def connect_control(
        cls,
        udid: Optional[str] = None,
        *,
        connection_type: str = "USB",
        usbmux_address: Optional[str] = None,
        port: int = PURPLE_PROXY_CONTROL_PORT,
        endianity: str = ">",
        trace: Optional[list[dict[str, Any]]] = None,
        include_identifiers: bool = False,
    ) -> "PurpleProxyClient":
        return cls(
            await ServiceConnection.create_using_usbmux(
                udid,
                port,
                connection_type=connection_type,
                usbmux_address=usbmux_address,
            ),
            endianity=endianity,
            trace=trace,
            trace_channel="control",
            include_identifiers=include_identifiers,
        )

    @classmethod
    async def connect_socks(
        cls,
        udid: Optional[str] = None,
        *,
        connection_type: str = "USB",
        usbmux_address: Optional[str] = None,
        port: int = PURPLE_PROXY_SOCKS_PORT,
        endianity: str = ">",
        trace: Optional[list[dict[str, Any]]] = None,
        include_identifiers: bool = False,
    ) -> "PurpleProxyClient":
        return cls(
            await ServiceConnection.create_using_usbmux(
                udid,
                port,
                connection_type=connection_type,
                usbmux_address=usbmux_address,
            ),
            endianity=endianity,
            trace=trace,
            trace_channel="socks",
            include_identifiers=include_identifiers,
        )

    @classmethod
    async def connect_notify(
        cls,
        udid: Optional[str] = None,
        *,
        connection_type: str = "USB",
        usbmux_address: Optional[str] = None,
        port: int = PURPLE_PROXY_NOTIFY_PORT,
        endianity: str = ">",
        trace: Optional[list[dict[str, Any]]] = None,
        include_identifiers: bool = False,
    ) -> "PurpleProxyClient":
        return cls(
            await ServiceConnection.create_using_usbmux(
                udid,
                port,
                connection_type=connection_type,
                usbmux_address=usbmux_address,
            ),
            endianity=endianity,
            trace=trace,
            trace_channel="notify",
            include_identifiers=include_identifiers,
        )

    async def close(self) -> None:
        await self.service.close()

    async def aclose(self) -> None:
        await self.close()

    async def read_dictionary(self) -> dict[str, Any]:
        start = asyncio.get_running_loop().time()
        try:
            response = await self.service.recv_plist(endianity=self.endianity)
        except Exception as e:
            _trace_append(
                self.trace,
                "recv_plist_error",
                channel=self.trace_channel,
                duration=_trace_duration(start),
                error_type=e.__class__.__name__,
            )
            raise
        if not isinstance(response, dict):
            _trace_append(
                self.trace,
                "recv_plist_error",
                channel=self.trace_channel,
                duration=_trace_duration(start),
                response_type=type(response).__name__,
            )
            raise TypeError(f"expected PurpleReverseProxy dictionary, got {type(response).__name__}")
        _trace_append(
            self.trace,
            "recv_plist",
            channel=self.trace_channel,
            duration=_trace_duration(start),
            response=_visible_purple_proxy_response(response, include_identifiers=self.include_identifiers),
            response_keys=sorted(str(key) for key in response),
        )
        return response

    async def write_dictionary(self, message: dict[str, Any]) -> None:
        start = asyncio.get_running_loop().time()
        try:
            await self.service.send_plist(message, endianity=self.endianity, fmt=plistlib.FMT_XML)
        except Exception as e:
            _trace_append(
                self.trace,
                "send_plist_error",
                channel=self.trace_channel,
                duration=_trace_duration(start),
                error_type=e.__class__.__name__,
                message=_visible_purple_proxy_response(message, include_identifiers=self.include_identifiers),
            )
            raise
        _trace_append(
            self.trace,
            "send_plist",
            channel=self.trace_channel,
            duration=_trace_duration(start),
            message=_visible_purple_proxy_response(message, include_identifiers=self.include_identifiers),
            message_keys=sorted(str(key) for key in message),
        )

    async def send_command_message(self, command: Union[str, PurpleProxyCommand], **fields: Any) -> None:
        if isinstance(command, PurpleProxyCommand):
            command = command.value
        message = {PURPLE_PROXY_COMMAND_KEY: command}
        message.update(fields)
        await self.write_dictionary(message)

    async def send_recv_command_message(self, command: Union[str, PurpleProxyCommand], **fields: Any) -> dict[str, Any]:
        await self.send_command_message(command, **fields)
        return await self.read_dictionary()

    async def send_control_message(self, command: Union[str, PurpleProxyCommand], **fields: Any) -> None:
        await self.send_command_message(command, **fields)

    async def send_recv_control_message(self, command: Union[str, PurpleProxyCommand], **fields: Any) -> dict[str, Any]:
        return await self.send_recv_command_message(command, **fields)

    async def hello_control(
        self,
        *,
        protocol_version: int = PURPLE_PROXY_CONTROL_PROTOCOL_VERSION,
        **fields: Any,
    ) -> dict[str, Any]:
        return await self.send_recv_control_message(
            PurpleProxyCommand.HELLO_CONTROL,
            **{PURPLE_PROXY_CTRL_PROTO_VERSION_KEY: protocol_version},
            **fields,
        )

    async def begin_control(
        self,
        *,
        protocol_version: int = PURPLE_PROXY_CONTROL_PROTOCOL_VERSION,
        **fields: Any,
    ) -> dict[str, Any]:
        return await self.send_recv_control_message(
            PurpleProxyCommand.BEGIN_CONTROL,
            **{PURPLE_PROXY_CTRL_PROTO_VERSION_KEY: protocol_version},
            **fields,
        )

    async def wait_socket(
        self,
        *,
        conn_port: int = PURPLE_PROXY_SOCKS_PORT,
        **fields: Any,
    ) -> dict[str, Any]:
        return await self.send_recv_control_message(
            PurpleProxyCommand.WAIT_SOCKET,
            **{PURPLE_PROXY_CONN_PORT_KEY: conn_port},
            **fields,
        )

    async def send_ping(self, **fields: Any) -> dict[str, Any]:
        return await self.send_recv_control_message(PurpleProxyCommand.PING, **fields)

    async def register_notify(self, **fields: Any) -> None:
        await self.send_command_message(PurpleProxyCommand.REGISTER_NOTIFY, **fields)

    async def set_log_level(self, level: int, **fields: Any) -> None:
        await self.send_command_message(PurpleProxyCommand.SET_LOG_LEVEL, **{PURPLE_PROXY_LEVEL_KEY: level}, **fields)


async def probe_purple_proxy_hello(
    *,
    udid: Optional[str] = None,
    usbmux_address: Optional[str] = None,
    timeout: float = 1.0,
    port: int = PURPLE_PROXY_CONTROL_PORT,
    protocol_version: int = PURPLE_PROXY_CONTROL_PROTOCOL_VERSION,
    connection_type: str = "USB",
    include_response: bool = False,
) -> dict[str, Any]:
    return await run_purple_proxy_control_command(
        PurpleProxyCommand.HELLO_CONTROL,
        udid=udid,
        usbmux_address=usbmux_address,
        timeout=timeout,
        port=port,
        protocol_version=protocol_version,
        connection_type=connection_type,
        include_response=include_response,
    )


async def run_purple_proxy_control_command(
    command: Union[str, PurpleProxyCommand],
    *,
    udid: Optional[str] = None,
    usbmux_address: Optional[str] = None,
    timeout: float = 1.0,
    port: int = PURPLE_PROXY_CONTROL_PORT,
    protocol_version: int = PURPLE_PROXY_CONTROL_PROTOCOL_VERSION,
    conn_port: int = PURPLE_PROXY_SOCKS_PORT,
    connection_type: str = "USB",
    include_response: bool = False,
    include_identifiers: bool = False,
) -> dict[str, Any]:
    if isinstance(command, str):
        command = PurpleProxyCommand(command)

    client = None
    result: dict[str, Any] = {
        "checked": True,
        "experimental": True,
        "command": command.value,
        "port": port,
        "include_response": include_response,
    }
    if command in (PurpleProxyCommand.HELLO_CONTROL, PurpleProxyCommand.BEGIN_CONTROL):
        result["protocol_version"] = protocol_version
    if command is PurpleProxyCommand.WAIT_SOCKET:
        result["conn_port"] = conn_port
    _mark_identifier_output(result, include_identifiers=include_identifiers)

    try:
        client = await asyncio.wait_for(
            PurpleProxyClient.connect_control(
                udid,
                connection_type=connection_type,
                usbmux_address=usbmux_address,
                port=port,
            ),
            timeout=timeout,
        )
        if command is PurpleProxyCommand.HELLO_CONTROL:
            response = await asyncio.wait_for(client.hello_control(protocol_version=protocol_version), timeout=timeout)
        elif command is PurpleProxyCommand.BEGIN_CONTROL:
            response = await asyncio.wait_for(client.begin_control(protocol_version=protocol_version), timeout=timeout)
        elif command is PurpleProxyCommand.WAIT_SOCKET:
            response = await asyncio.wait_for(client.wait_socket(conn_port=conn_port), timeout=timeout)
        elif command is PurpleProxyCommand.PING:
            response = await asyncio.wait_for(client.send_ping(), timeout=timeout)
        else:
            raise ValueError(f"unsupported PurpleReverseProxy control command: {command.value}")
    except Exception as e:
        result.update({
            "reachable": False,
            "error_type": e.__class__.__name__,
        })
        return result
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                await client.close()

    visible_response = _visible_purple_proxy_response(response, include_identifiers=include_identifiers)
    result.update({
        "reachable": True,
        "response_keys": sorted(str(key) for key in visible_response),
    })
    if command is PurpleProxyCommand.PING:
        result["pong"] = is_purple_proxy_pong_response(visible_response)
    if include_response:
        result["response"] = visible_response
    return result


async def collect_purple_proxy_notify_messages(
    client: PurpleProxyClient,
    *,
    listen_timeout: float,
    max_messages: int,
) -> list[dict[str, Any]]:
    messages = []
    deadline = asyncio.get_running_loop().time() + listen_timeout
    while len(messages) < max_messages:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            break
        try:
            messages.append(await asyncio.wait_for(client.read_dictionary(), timeout=remaining))
        except asyncio.TimeoutError:
            break
    return messages


async def run_purple_proxy_notify_command(
    command: Union[str, PurpleProxyCommand],
    *,
    level: Optional[int] = None,
    udid: Optional[str] = None,
    usbmux_address: Optional[str] = None,
    timeout: float = 1.0,
    port: int = PURPLE_PROXY_NOTIFY_PORT,
    connection_type: str = "USB",
    include_response: bool = False,
    expect_response: bool = False,
    listen_timeout: float = 0.0,
    max_messages: int = 8,
    include_identifiers: bool = False,
) -> dict[str, Any]:
    if isinstance(command, str):
        command = PurpleProxyCommand(command)
    if command is PurpleProxyCommand.SET_LOG_LEVEL and level is None:
        raise ValueError("level is required for SetLogLevel")

    client = None
    result: dict[str, Any] = {
        "checked": True,
        "experimental": True,
        "command": command.value,
        "port": port,
        "include_response": include_response,
        "expect_response": expect_response,
    }
    if command is PurpleProxyCommand.SET_LOG_LEVEL:
        result["level"] = level
    if listen_timeout > 0:
        result.update({
            "listen_timeout": listen_timeout,
            "max_messages": max_messages,
        })
    _mark_identifier_output(result, include_identifiers=include_identifiers)

    try:
        client = await asyncio.wait_for(
            PurpleProxyClient.connect_notify(
                udid,
                connection_type=connection_type,
                usbmux_address=usbmux_address,
                port=port,
            ),
            timeout=timeout,
        )
        if command is PurpleProxyCommand.REGISTER_NOTIFY:
            await asyncio.wait_for(client.register_notify(), timeout=timeout)
        elif command is PurpleProxyCommand.SET_LOG_LEVEL:
            await asyncio.wait_for(client.set_log_level(level), timeout=timeout)
        else:
            await asyncio.wait_for(client.send_command_message(command), timeout=timeout)

        result.update({
            "reachable": True,
            "sent": True,
        })

        if expect_response:
            response = await asyncio.wait_for(client.read_dictionary(), timeout=timeout)
            visible_response = _visible_purple_proxy_response(response, include_identifiers=include_identifiers)
            result["response_keys"] = sorted(str(key) for key in visible_response)
            if include_response:
                result["response"] = visible_response
        elif listen_timeout > 0:
            messages = await collect_purple_proxy_notify_messages(
                client,
                listen_timeout=listen_timeout,
                max_messages=max_messages,
            )
            _add_notify_messages_to_phase(
                result,
                messages,
                include_response=include_response,
                include_identifiers=include_identifiers,
            )
    except asyncio.TimeoutError as e:
        if result.get("sent"):
            result.update({
                "response_timeout": True,
            })
        else:
            result.update({
                "reachable": False,
                "error_type": e.__class__.__name__,
            })
        return result
    except Exception as e:
        result.update({
            "reachable": False,
            "error_type": e.__class__.__name__,
        })
        return result
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                await client.close()

    return result


async def run_purple_proxy_socks_probe(
    *,
    udid: Optional[str] = None,
    usbmux_address: Optional[str] = None,
    timeout: float = 1.0,
    port: int = PURPLE_PROXY_SOCKS_PORT,
    connect_host: Optional[str] = None,
    connect_port: int = 443,
    connection_type: str = "USB",
    include_response: bool = False,
    include_identifiers: bool = False,
    trace: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    _validate_socks_port(port)

    phase_start = asyncio.get_running_loop().time()
    _trace_append(trace, "phase_start", phase="socks_probe", channel="socks", port=port)
    result: dict[str, Any] = {
        "checked": True,
        "experimental": True,
        "protocol": "SOCKS5",
        "port": port,
        "include_response": include_response,
    }
    client = None

    try:
        connect_start = asyncio.get_running_loop().time()
        connect_kwargs = {
            "connection_type": connection_type,
            "usbmux_address": usbmux_address,
            "port": port,
        }
        if trace is not None:
            connect_kwargs["trace"] = trace
        if include_identifiers:
            connect_kwargs["include_identifiers"] = True
        client = await asyncio.wait_for(
            PurpleProxyClient.connect_socks(
                udid,
                **connect_kwargs,
            ),
            timeout=timeout,
        )
        _trace_append(
            trace,
            "connect",
            phase="socks_probe",
            channel="socks",
            port=port,
            duration=_trace_duration(connect_start),
        )
    except Exception as e:
        result.update({
            "reachable": False,
            "error_type": e.__class__.__name__,
            "summary": {
                "handshake_ok": False,
                "connect_succeeded": None,
                "ok": False,
            },
        })
        if trace is not None:
            result["trace_timing"] = {"duration": _trace_duration(phase_start)}
        _trace_append(
            trace,
            "connect_error",
            phase="socks_probe",
            channel="socks",
            port=port,
            error_type=e.__class__.__name__,
        )
        _trace_append(
            trace,
            "phase_end",
            phase="socks_probe",
            channel="socks",
            reachable=False,
            duration=result.get("trace_timing", {}).get("duration"),
        )
        return result

    try:
        greeting = bytes([
            PURPLE_PROXY_SOCKS_VERSION,
            1,
            PURPLE_PROXY_SOCKS_NO_AUTHENTICATION,
        ])
        send_start = asyncio.get_running_loop().time()
        await asyncio.wait_for(client.service.sendall(greeting), timeout=timeout)
        _trace_append(
            trace,
            "send_bytes",
            phase="socks_probe",
            channel="socks",
            step="greeting",
            duration=_trace_duration(send_start),
            bytes_hex=greeting.hex(),
        )
        recv_start = asyncio.get_running_loop().time()
        method_response = await asyncio.wait_for(client.service.recvall(2), timeout=timeout)
        _trace_append(
            trace,
            "recv_bytes",
            phase="socks_probe",
            channel="socks",
            step="greeting",
            duration=_trace_duration(recv_start),
            bytes_hex=method_response.hex(),
        )
        version, method = method_response
        handshake_ok = version == PURPLE_PROXY_SOCKS_VERSION and method == PURPLE_PROXY_SOCKS_NO_AUTHENTICATION
        result.update({
            "reachable": True,
            "handshake": {
                "sent": True,
                "version": version,
                "method": method,
                "method_name": _socks_method_name(method),
                "accepted": handshake_ok,
            },
        })
        if include_response:
            result["handshake"]["response_hex"] = method_response.hex()
    except Exception as e:
        result.update({
            "reachable": True,
            "handshake": {
                "sent": True,
                "accepted": False,
                "error_type": e.__class__.__name__,
            },
            "summary": {
                "handshake_ok": False,
                "connect_succeeded": None,
                "ok": False,
            },
        })
        if client is not None:
            with contextlib.suppress(Exception):
                await client.close()
        if trace is not None:
            result["trace_timing"] = {"duration": _trace_duration(phase_start)}
        _trace_append(
            trace,
            "phase_end",
            phase="socks_probe",
            channel="socks",
            reachable=True,
            duration=result.get("trace_timing", {}).get("duration"),
            error_type=e.__class__.__name__,
        )
        return result
    finally:
        if client is not None and connect_host is None:
            with contextlib.suppress(Exception):
                await client.close()

    if connect_host is None:
        result["connect"] = _purple_proxy_skipped_phase("--connect-host was not provided.")
        result["summary"] = {
            "handshake_ok": handshake_ok,
            "connect_succeeded": None,
            "ok": handshake_ok,
        }
        if trace is not None:
            result["trace_timing"] = {"duration": _trace_duration(phase_start)}
        _trace_append(
            trace,
            "phase_end",
            phase="socks_probe",
            channel="socks",
            reachable=True,
            duration=result.get("trace_timing", {}).get("duration"),
        )
        return result

    try:
        connect_request, target_address_type = _build_socks_connect_request(connect_host, connect_port)
        connect_phase: dict[str, Any] = {
            "checked": True,
            "target_address_type": target_address_type,
            "target_port": connect_port,
        }
        if include_identifiers:
            connect_phase["target_host"] = connect_host
        if not handshake_ok:
            connect_phase.update({
                "sent": False,
                "reason": "SOCKS5 greeting was not accepted.",
            })
            result["connect"] = connect_phase
            result["summary"] = {
                "handshake_ok": False,
                "connect_succeeded": False,
                "ok": False,
            }
        else:
            send_start = asyncio.get_running_loop().time()
            await asyncio.wait_for(client.service.sendall(connect_request), timeout=timeout)
            _trace_append(
                trace,
                "send_bytes",
                phase="socks_probe",
                channel="socks",
                step="connect",
                duration=_trace_duration(send_start),
                bytes_hex=connect_request.hex(),
                target_address_type=target_address_type,
                target_port=connect_port,
                **({"target_host": connect_host} if include_identifiers else {}),
            )
            recv_start = asyncio.get_running_loop().time()
            response_header = await asyncio.wait_for(client.service.recvall(4), timeout=timeout)
            response_version, reply, reserved, address_type = response_header
            if address_type == PURPLE_PROXY_SOCKS_ATYP_IPV4:
                bound_address = await asyncio.wait_for(client.service.recvall(4), timeout=timeout)
            elif address_type == PURPLE_PROXY_SOCKS_ATYP_IPV6:
                bound_address = await asyncio.wait_for(client.service.recvall(16), timeout=timeout)
            elif address_type == PURPLE_PROXY_SOCKS_ATYP_DOMAIN:
                bound_domain_size = await asyncio.wait_for(client.service.recvall(1), timeout=timeout)
                bound_address = bound_domain_size + await asyncio.wait_for(
                    client.service.recvall(bound_domain_size[0]),
                    timeout=timeout,
                )
            else:
                raise ValueError(f"unsupported SOCKS5 bind address type: {address_type}")
            bound_port = int.from_bytes(await asyncio.wait_for(client.service.recvall(2), timeout=timeout), "big")
            response_bytes = response_header + bound_address + bound_port.to_bytes(2, "big")
            _trace_append(
                trace,
                "recv_bytes",
                phase="socks_probe",
                channel="socks",
                step="connect",
                duration=_trace_duration(recv_start),
                bytes_hex=response_bytes.hex(),
            )
            connect_succeeded = response_version == PURPLE_PROXY_SOCKS_VERSION and reply == 0
            connect_phase.update({
                "sent": True,
                "version": response_version,
                "reply": reply,
                "reply_name": _socks_reply_name(reply),
                "reserved": reserved,
                "bound_address_type": _socks_address_type_name(address_type),
                "bound_address_length": len(bound_address),
                "bound_port": bound_port,
                "succeeded": connect_succeeded,
            })
            if include_response:
                connect_phase["response_hex"] = (
                    response_header.hex() + bound_address.hex() + bound_port.to_bytes(2, "big").hex()
                )
            result["connect"] = connect_phase
            result["summary"] = {
                "handshake_ok": handshake_ok,
                "connect_succeeded": connect_succeeded,
                "ok": handshake_ok and connect_succeeded,
            }
    except Exception as e:
        result["connect"] = {
            "checked": True,
            "target_port": connect_port,
            "sent": False,
            "error_type": e.__class__.__name__,
        }
        result["summary"] = {
            "handshake_ok": handshake_ok,
            "connect_succeeded": False,
            "ok": False,
        }
        if trace is not None:
            result["trace_timing"] = {"duration": _trace_duration(phase_start)}
        _trace_append(
            trace,
            "phase_end",
            phase="socks_probe",
            channel="socks",
            reachable=True,
            duration=result.get("trace_timing", {}).get("duration"),
            error_type=e.__class__.__name__,
        )
        return result
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                await client.close()
    if trace is not None:
        result["trace_timing"] = {"duration": _trace_duration(phase_start)}
    _trace_append(
        trace,
        "phase_end",
        phase="socks_probe",
        channel="socks",
        reachable=result.get("reachable"),
        duration=result.get("trace_timing", {}).get("duration"),
    )
    return result


async def run_purple_proxy_session(
    *,
    udid: Optional[str] = None,
    usbmux_address: Optional[str] = None,
    timeout: float = 1.0,
    control_port: int = PURPLE_PROXY_CONTROL_PORT,
    notify_port: int = PURPLE_PROXY_NOTIFY_PORT,
    protocol_version: int = PURPLE_PROXY_CONTROL_PROTOCOL_VERSION,
    conn_port: int = PURPLE_PROXY_SOCKS_PORT,
    log_level: Optional[int] = None,
    url: str = "https://www.apple.com/",
    proxy_host: str = PURPLE_PROXY_LOOPBACK_HOST,
    connection_type: str = "USB",
    include_response: bool = False,
    listen_timeout: float = 1.0,
    max_messages: int = 8,
    probe_socks: bool = False,
    socks_connect_host: Optional[str] = None,
    socks_connect_port: int = 443,
    include_identifiers: bool = False,
    trace: bool = False,
) -> dict[str, Any]:
    if log_level is not None and not 0 <= log_level <= 7:
        raise ValueError("log_level must be between 0 and 7")

    session_start = asyncio.get_running_loop().time()
    trace_events: Optional[list[dict[str, Any]]] = [] if trace else None
    _trace_append(
        trace_events,
        "session_start",
        timeout=timeout,
        control_port=control_port,
        notify_port=notify_port,
        conn_port=conn_port,
        protocol_version=protocol_version,
        include_identifiers=include_identifiers,
    )
    phases: dict[str, Any] = {}
    notify_client = None
    control_client = None
    notify_messages_task = None

    try:
        connect_start = asyncio.get_running_loop().time()
        connect_kwargs = {
            "connection_type": connection_type,
            "usbmux_address": usbmux_address,
            "port": notify_port,
        }
        if trace_events is not None:
            connect_kwargs["trace"] = trace_events
        if include_identifiers:
            connect_kwargs["include_identifiers"] = True
        notify_client = await asyncio.wait_for(
            PurpleProxyClient.connect_notify(
                udid,
                **connect_kwargs,
            ),
            timeout=timeout,
        )
        _trace_append(
            trace_events,
            "connect",
            phase="notify_connect",
            channel="notify",
            port=notify_port,
            duration=_trace_duration(connect_start),
        )
        if log_level is None:
            phases["set_log_level"] = _purple_proxy_skipped_phase("--log-level was not provided.")
        else:
            phases["set_log_level"] = await _run_connected_notify_phase(
                notify_client,
                PurpleProxyCommand.SET_LOG_LEVEL,
                timeout=timeout,
                port=notify_port,
                include_response=include_response,
                level=log_level,
                include_identifiers=include_identifiers,
                trace=trace_events,
                phase_name="set_log_level",
            )
        phases["register_notify"] = await _run_connected_notify_phase(
            notify_client,
            PurpleProxyCommand.REGISTER_NOTIFY,
            timeout=timeout,
            port=notify_port,
            include_response=include_response,
            listen_timeout=listen_timeout,
            max_messages=max_messages,
            include_identifiers=include_identifiers,
            trace=trace_events,
            phase_name="register_notify",
        )
        if phases["register_notify"].get("reachable") and listen_timeout > 0:
            notify_messages_task = asyncio.create_task(
                collect_purple_proxy_notify_messages(
                    notify_client,
                    listen_timeout=listen_timeout,
                    max_messages=max_messages,
                )
            )
    except Exception as e:
        _trace_append(
            trace_events,
            "connect_error",
            phase="notify_connect",
            channel="notify",
            port=notify_port,
            error_type=e.__class__.__name__,
        )
        if log_level is None:
            phases["set_log_level"] = _purple_proxy_skipped_phase("--log-level was not provided.")
        else:
            phases["set_log_level"] = _purple_proxy_unreachable_phase(
                _purple_proxy_notify_phase_result(
                    PurpleProxyCommand.SET_LOG_LEVEL,
                    port=notify_port,
                    include_response=include_response,
                    level=log_level,
                ),
                e,
            )
        phases["register_notify"] = _purple_proxy_unreachable_phase(
            _purple_proxy_notify_phase_result(
                PurpleProxyCommand.REGISTER_NOTIFY,
                port=notify_port,
                include_response=include_response,
                listen_timeout=listen_timeout,
                max_messages=max_messages,
            ),
            e,
        )

    try:
        connect_start = asyncio.get_running_loop().time()
        connect_kwargs = {
            "connection_type": connection_type,
            "usbmux_address": usbmux_address,
            "port": control_port,
        }
        if trace_events is not None:
            connect_kwargs["trace"] = trace_events
        if include_identifiers:
            connect_kwargs["include_identifiers"] = True
        control_client = await asyncio.wait_for(
            PurpleProxyClient.connect_control(
                udid,
                **connect_kwargs,
            ),
            timeout=timeout,
        )
        _trace_append(
            trace_events,
            "connect",
            phase="control_connect",
            channel="control",
            port=control_port,
            duration=_trace_duration(connect_start),
        )
        phases["begin_control"] = await _run_connected_control_phase(
            control_client,
            PurpleProxyCommand.BEGIN_CONTROL,
            timeout=timeout,
            port=control_port,
            protocol_version=protocol_version,
            conn_port=conn_port,
            include_response=include_response,
            include_identifiers=include_identifiers,
            trace=trace_events,
            phase_name="begin_control",
        )
        phases["ping"] = await _run_connected_control_phase(
            control_client,
            PurpleProxyCommand.PING,
            timeout=timeout,
            port=control_port,
            protocol_version=protocol_version,
            conn_port=conn_port,
            include_response=include_response,
            include_identifiers=include_identifiers,
            trace=trace_events,
            phase_name="ping",
        )
        phases["wait_socket"] = await _run_connected_control_phase(
            control_client,
            PurpleProxyCommand.WAIT_SOCKET,
            timeout=timeout,
            port=control_port,
            protocol_version=protocol_version,
            conn_port=conn_port,
            include_response=include_response,
            include_identifiers=include_identifiers,
            trace=trace_events,
            phase_name="wait_socket",
        )
    except Exception as e:
        _trace_append(
            trace_events,
            "connect_error",
            phase="control_connect",
            channel="control",
            port=control_port,
            error_type=e.__class__.__name__,
        )
        for key, command in (
            ("begin_control", PurpleProxyCommand.BEGIN_CONTROL),
            ("ping", PurpleProxyCommand.PING),
            ("wait_socket", PurpleProxyCommand.WAIT_SOCKET),
        ):
            phases[key] = _purple_proxy_unreachable_phase(
                _purple_proxy_control_phase_result(
                    command,
                    port=control_port,
                    protocol_version=protocol_version,
                    conn_port=conn_port,
                    include_response=include_response,
                ),
                e,
            )
    finally:
        if notify_messages_task is not None:
            try:
                messages = await notify_messages_task
            except Exception as e:
                phases["register_notify"]["message_error_type"] = e.__class__.__name__
            else:
                _add_notify_messages_to_phase(
                    phases["register_notify"],
                    messages,
                    include_response=include_response,
                    include_identifiers=include_identifiers,
                )
        if control_client is not None:
            with contextlib.suppress(Exception):
                await control_client.close()
        if notify_client is not None:
            with contextlib.suppress(Exception):
                await notify_client.close()

    phases["proxy_dictionary"] = build_purple_proxy_dictionary(
        url=url,
        host=proxy_host,
        socks_port=conn_port,
    )
    if probe_socks or socks_connect_host is not None:
        socks_kwargs = {
            "udid": udid,
            "usbmux_address": usbmux_address,
            "timeout": timeout,
            "port": conn_port,
            "connect_host": socks_connect_host,
            "connect_port": socks_connect_port,
            "connection_type": connection_type,
            "include_response": include_response,
        }
        if include_identifiers:
            socks_kwargs["include_identifiers"] = True
        if trace_events is not None:
            socks_kwargs["trace"] = trace_events
        phases["socks_probe"] = await run_purple_proxy_socks_probe(**socks_kwargs)
    else:
        phases["socks_probe"] = _purple_proxy_skipped_phase("--probe-socks was not provided.")

    session_duration = _trace_duration(session_start)
    _trace_append(trace_events, "session_end", duration=session_duration)
    result = {
        "checked": True,
        "experimental": True,
        "phases": phases,
        "summary": summarize_purple_proxy_session(phases),
    }
    _mark_identifier_output(result, include_identifiers=include_identifiers)
    if trace_events is not None:
        result["trace"] = {
            "enabled": True,
            "event_count": len(trace_events),
            "duration": session_duration,
            "events": trace_events,
        }
    return result
