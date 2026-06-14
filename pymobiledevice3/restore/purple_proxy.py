import asyncio
import contextlib
import plistlib
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
) -> dict[str, Any]:
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
        return _purple_proxy_unreachable_phase(result, e)

    sanitized_response = sanitize_purple_proxy_response(response)
    result.update({
        "reachable": True,
        "response_keys": sorted(str(key) for key in sanitized_response),
    })
    if command is PurpleProxyCommand.PING:
        result["pong"] = is_purple_proxy_pong_response(sanitized_response)
    if include_response:
        result["response"] = sanitized_response
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
) -> dict[str, Any]:
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
        return _purple_proxy_unreachable_phase(result, e)

    result.update({
        "reachable": True,
        "sent": True,
    })
    return result


def _add_notify_messages_to_phase(
    phase: dict[str, Any],
    messages: list[dict[str, Any]],
    *,
    include_response: bool,
) -> dict[str, Any]:
    sanitized_messages = [sanitize_purple_proxy_response(message) for message in messages]
    phase["message_count"] = len(sanitized_messages)
    phase["message_keys"] = [sorted(str(key) for key in message) for message in sanitized_messages]
    if include_response:
        phase["messages"] = sanitized_messages
    return phase


def summarize_purple_proxy_session(phases: dict[str, Any]) -> dict[str, Any]:
    log_phase = phases.get("set_log_level", {})
    log_level_requested = bool(log_phase.get("checked"))
    control_reachable = bool(phases.get("begin_control", {}).get("reachable"))
    ping_pong = bool(phases.get("ping", {}).get("reachable") and phases.get("ping", {}).get("pong"))
    wait_socket_reachable = bool(phases.get("wait_socket", {}).get("reachable"))
    notify_registered = bool(phases.get("register_notify", {}).get("reachable"))
    proxy_dictionary_ready = bool(phases.get("proxy_dictionary", {}).get("checked"))
    set_log_level_sent = None
    if log_level_requested:
        set_log_level_sent = bool(log_phase.get("reachable") and log_phase.get("sent"))

    required = [
        control_reachable,
        ping_pong,
        wait_socket_reachable,
        notify_registered,
        proxy_dictionary_ready,
    ]
    if log_level_requested:
        required.append(bool(set_log_level_sent))

    return {
        "control_reachable": control_reachable,
        "ping_pong": ping_pong,
        "wait_socket_reachable": wait_socket_reachable,
        "notify_registered": notify_registered,
        "set_log_level_sent": set_log_level_sent,
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

    def __init__(self, service: ServiceConnection, *, endianity: str = ">") -> None:
        self.service = service
        self.endianity = endianity

    @classmethod
    async def connect_control(
        cls,
        udid: Optional[str] = None,
        *,
        connection_type: str = "USB",
        usbmux_address: Optional[str] = None,
        port: int = PURPLE_PROXY_CONTROL_PORT,
        endianity: str = ">",
    ) -> "PurpleProxyClient":
        return cls(
            await ServiceConnection.create_using_usbmux(
                udid,
                port,
                connection_type=connection_type,
                usbmux_address=usbmux_address,
            ),
            endianity=endianity,
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
    ) -> "PurpleProxyClient":
        return cls(
            await ServiceConnection.create_using_usbmux(
                udid,
                port,
                connection_type=connection_type,
                usbmux_address=usbmux_address,
            ),
            endianity=endianity,
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
    ) -> "PurpleProxyClient":
        return cls(
            await ServiceConnection.create_using_usbmux(
                udid,
                port,
                connection_type=connection_type,
                usbmux_address=usbmux_address,
            ),
            endianity=endianity,
        )

    async def close(self) -> None:
        await self.service.close()

    async def aclose(self) -> None:
        await self.close()

    async def read_dictionary(self) -> dict[str, Any]:
        response = await self.service.recv_plist(endianity=self.endianity)
        if not isinstance(response, dict):
            raise TypeError(f"expected PurpleReverseProxy dictionary, got {type(response).__name__}")
        return response

    async def write_dictionary(self, message: dict[str, Any]) -> None:
        await self.service.send_plist(message, endianity=self.endianity, fmt=plistlib.FMT_XML)

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

    sanitized_response = sanitize_purple_proxy_response(response)
    result.update({
        "reachable": True,
        "response_keys": sorted(str(key) for key in sanitized_response),
    })
    if command is PurpleProxyCommand.PING:
        result["pong"] = is_purple_proxy_pong_response(sanitized_response)
    if include_response:
        result["response"] = sanitized_response
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
            sanitized_response = sanitize_purple_proxy_response(response)
            result["response_keys"] = sorted(str(key) for key in sanitized_response)
            if include_response:
                result["response"] = sanitized_response
        elif listen_timeout > 0:
            messages = await collect_purple_proxy_notify_messages(
                client,
                listen_timeout=listen_timeout,
                max_messages=max_messages,
            )
            sanitized_messages = [sanitize_purple_proxy_response(message) for message in messages]
            result["message_count"] = len(sanitized_messages)
            result["message_keys"] = [sorted(str(key) for key in message) for message in sanitized_messages]
            if include_response:
                result["messages"] = sanitized_messages
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
) -> dict[str, Any]:
    if log_level is not None and not 0 <= log_level <= 7:
        raise ValueError("log_level must be between 0 and 7")

    phases: dict[str, Any] = {}
    notify_client = None
    control_client = None
    notify_messages_task = None

    try:
        notify_client = await asyncio.wait_for(
            PurpleProxyClient.connect_notify(
                udid,
                connection_type=connection_type,
                usbmux_address=usbmux_address,
                port=notify_port,
            ),
            timeout=timeout,
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
            )
        phases["register_notify"] = await _run_connected_notify_phase(
            notify_client,
            PurpleProxyCommand.REGISTER_NOTIFY,
            timeout=timeout,
            port=notify_port,
            include_response=include_response,
            listen_timeout=listen_timeout,
            max_messages=max_messages,
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
        control_client = await asyncio.wait_for(
            PurpleProxyClient.connect_control(
                udid,
                connection_type=connection_type,
                usbmux_address=usbmux_address,
                port=control_port,
            ),
            timeout=timeout,
        )
        phases["begin_control"] = await _run_connected_control_phase(
            control_client,
            PurpleProxyCommand.BEGIN_CONTROL,
            timeout=timeout,
            port=control_port,
            protocol_version=protocol_version,
            conn_port=conn_port,
            include_response=include_response,
        )
        phases["ping"] = await _run_connected_control_phase(
            control_client,
            PurpleProxyCommand.PING,
            timeout=timeout,
            port=control_port,
            protocol_version=protocol_version,
            conn_port=conn_port,
            include_response=include_response,
        )
        phases["wait_socket"] = await _run_connected_control_phase(
            control_client,
            PurpleProxyCommand.WAIT_SOCKET,
            timeout=timeout,
            port=control_port,
            protocol_version=protocol_version,
            conn_port=conn_port,
            include_response=include_response,
        )
    except Exception as e:
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

    return {
        "checked": True,
        "experimental": True,
        "phases": phases,
        "summary": summarize_purple_proxy_session(phases),
    }
