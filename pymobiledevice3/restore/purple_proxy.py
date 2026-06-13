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
    PING = "Ping"


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

    async def send_control_message(self, command: Union[str, PurpleProxyCommand], **fields: Any) -> None:
        if isinstance(command, PurpleProxyCommand):
            command = command.value
        message = {"Command": command}
        message.update(fields)
        await self.write_dictionary(message)

    async def send_recv_control_message(self, command: Union[str, PurpleProxyCommand], **fields: Any) -> dict[str, Any]:
        await self.send_control_message(command, **fields)
        return await self.read_dictionary()

    async def hello_control(
        self,
        *,
        protocol_version: int = PURPLE_PROXY_CONTROL_PROTOCOL_VERSION,
        **fields: Any,
    ) -> dict[str, Any]:
        return await self.send_recv_control_message(
            PurpleProxyCommand.HELLO_CONTROL,
            CtrlProtoVersion=protocol_version,
            **fields,
        )

    async def begin_control(self, **fields: Any) -> dict[str, Any]:
        return await self.send_recv_control_message(PurpleProxyCommand.BEGIN_CONTROL, **fields)

    async def wait_socket(self, **fields: Any) -> dict[str, Any]:
        return await self.send_recv_control_message(PurpleProxyCommand.WAIT_SOCKET, **fields)

    async def send_ping(self, **fields: Any) -> dict[str, Any]:
        return await self.send_recv_control_message(PurpleProxyCommand.PING, **fields)


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
    client = None
    result: dict[str, Any] = {
        "checked": True,
        "experimental": True,
        "command": PurpleProxyCommand.HELLO_CONTROL.value,
        "port": port,
        "protocol_version": protocol_version,
        "include_response": include_response,
    }
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
        response = await asyncio.wait_for(client.hello_control(protocol_version=protocol_version), timeout=timeout)
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
    if include_response:
        result["response"] = sanitized_response
    return result
