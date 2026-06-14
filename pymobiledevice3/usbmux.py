import abc
import asyncio
import json
import plistlib
import shutil
import socket
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from construct import (
    Const,
    CString,
    Enum,
    FixedSized,
    GreedyBytes,
    Int16ul,
    Int32ul,
    Padding,
    Prefixed,
    Struct,
    Switch,
    this,
)

from pymobiledevice3.exceptions import (
    BadCommandError,
    BadDevError,
    ConnectionFailedError,
    ConnectionFailedToUsbmuxdError,
    MuxException,
    MuxVersionError,
    NotPairedError,
)
from pymobiledevice3.osu.os_utils import get_os_utils

# used on Windows
ITUNES_HOST = ("127.0.0.1", 27015)

# used for macOS and Linux
USBMUXD_PIPE = "/var/run/usbmuxd"

APPLE_VENDOR_ID = "05ac"
LINUX_USB_SYSFS = Path("/sys/bus/usb/devices")
LINUX_NET_SYSFS = Path("/sys/class/net")
APPLE_INTERFACE_ALIASES = {
    "Apple USB Multiplexor": "AppleUSBMux",
    "AppleUSBMux": "AppleUSBMux",
    "AppleUSBEthernet": "AppleUSBEthernet",
    "AppleUSBNCMControl": "AppleUSBNCMControl",
    "AppleUSBNCMData": "AppleUSBNCMData",
    "AppleUSBNCMControlAux": "AppleUSBNCMControlAux",
    "AppleUSBNCMDataAux": "AppleUSBNCMDataAux",
    "AppleUSBNCMControlDirect": "AppleUSBNCMControlDirect",
    "Valeria": "Valeria",
    "PTP": "PTP",
    "iAP": "iAP",
    "IapOverUsbHid": "IapOverUsbHid",
    "IDAMInterface": "IDAMInterface",
    "USBAudio2Control": "USBAudio2Control",
    "USBAudio2StreamIN": "USBAudio2StreamIN",
    "USBAudio2StreamOUT": "USBAudio2StreamOUT",
    "UVCControlInterface": "UVCControlInterface",
    "UVCStreamInterface": "UVCStreamInterface",
    "UVCStreamInterfaceA": "UVCStreamInterfaceA",
}
APPLE_USB_FIRMWARE_CONFIGURATION_SIGNATURES = {
    frozenset(("AppleUSBMux",)): (
        "AppleUSBTestDevice",
        "standardBringup",
        "standardMuxOnly",
        "stdMuxIAPVal",
        "stdMuxIDA",
    ),
    frozenset(("PTP",)): (
        "standardMuxPTP",
        "standardMuxPTPEthernet",
        "standardMuxPTPEthernetValeria",
        "stdMuxPTPEthValIDA",
    ),
    frozenset(("PTP", "AppleUSBMux")): (
        "standardMuxPTP",
        "standardMuxPTPEthernet",
        "standardMuxPTPEthernetValeria",
        "stdMuxPTPEthValIDA",
    ),
    frozenset(("AppleUSBMux", "AppleUSBEthernet")): ("standardMuxEthernet",),
    frozenset(("PTP", "AppleUSBMux", "AppleUSBEthernet")): (
        "standardMuxPTPEthernet",
        "standardMuxPTPEthernetValeria",
        "stdMuxPTPEthValIDA",
    ),
    frozenset(("AppleUSBMux", "AppleUSBNCMControl", "AppleUSBNCMData")): ("iBridgeBringup",),
    frozenset(("AppleUSBNCMControl", "AppleUSBNCMData")): ("ncmBringup",),
    frozenset(("AppleUSBNCMControl", "AppleUSBNCMData", "AppleUSBNCMControlAux", "AppleUSBNCMDataAux")): (
        "ncmAuxBringup",
    ),
    frozenset(("AppleUSBMux", "AppleUSBNCMControlAux", "AppleUSBNCMDataAux")): (
        "standardRestore",
        "muxNcmAux",
    ),
    frozenset((
        "PTP",
        "AppleUSBMux",
        "AppleUSBEthernet",
        "AppleUSBNCMControl",
        "AppleUSBNCMData",
        "AppleUSBNCMControlAux",
        "AppleUSBNCMDataAux",
    )): ("stdMuxPTPEthValIDA",),
    frozenset((
        "AppleUSBMux",
        "AppleUSBNCMControl",
        "AppleUSBNCMData",
        "AppleUSBNCMControlAux",
        "AppleUSBNCMDataAux",
    )): ("muxNcm", "muxNcmVal"),
    frozenset(("AppleUSBNCMControlDirect", "AppleUSBNCMData", "IapOverUsbHid")): ("DeviceModeCarplay",),
    frozenset(("AppleUSBNCMControlDirect", "AppleUSBNCMData", "IapOverUsbHid", "AppleUSBMux")): ("DeviceModeCarplay2",),
    frozenset(("AppleUSBMux", "IapOverUsbHid")): ("stdMuxIAPVal",),
    frozenset(("AppleUSBMux", "Valeria")): ("stdMuxIAPVal",),
    frozenset(("PTP", "AppleUSBMux", "Valeria")): ("standardMuxPTPEthernetValeria",),
    frozenset(("PTP", "AppleUSBMux", "Valeria", "AppleUSBNCMControlAux", "AppleUSBNCMDataAux")): (
        "stdMuxPTPEthValIDA",
    ),
    frozenset(("AppleUSBMux", "USBAudio2Control", "USBAudio2StreamIN", "USBAudio2StreamOUT", "IDAMInterface")): (
        "stdMuxIDA",
    ),
    frozenset((
        "AppleUSBMux",
        "USBAudio2Control",
        "USBAudio2StreamIN",
        "USBAudio2StreamOUT",
        "IDAMInterface",
        "AppleUSBNCMControlAux",
        "AppleUSBNCMDataAux",
    )): ("stdMuxPTPEthValIDA",),
    frozenset(("UVCControlInterface", "UVCStreamInterface", "UVCStreamInterfaceA", "AppleUSBMux")): ("muxNcmAuxVideo",),
    frozenset(("UVCControlInterface", "UVCStreamInterface", "AppleUSBMux")): ("muxNcmAuxVideo",),
    frozenset((
        "UVCControlInterface",
        "UVCStreamInterface",
        "UVCStreamInterfaceA",
        "AppleUSBMux",
        "AppleUSBNCMControlAux",
        "AppleUSBNCMDataAux",
    )): ("muxNcmAuxVideo",),
    frozenset((
        "UVCControlInterface",
        "UVCStreamInterface",
        "AppleUSBMux",
        "AppleUSBNCMControlAux",
        "AppleUSBNCMDataAux",
    )): ("muxNcmAuxVideo",),
    frozenset(("USBDeviceTester",)): ("USBDeviceTester",),
}

usbmuxd_version = Enum(
    Int32ul,
    BINARY=0,
    PLIST=1,
)

usbmuxd_result = Enum(
    Int32ul,
    OK=0,
    BADCOMMAND=1,
    BADDEV=2,
    CONNREFUSED=3,
    NOSUCHSERVICE=4,
    BADVERSION=6,
)

usbmuxd_msgtype = Enum(
    Int32ul,
    RESULT=1,
    CONNECT=2,
    LISTEN=3,
    ADD=4,
    REMOVE=5,
    PAIRED=6,
    PLIST=8,
)

usbmuxd_header = Struct(
    "version" / usbmuxd_version,
    "message" / usbmuxd_msgtype,
    "tag" / Int32ul,
)

usbmuxd_request = Prefixed(
    Int32ul,
    Struct(
        "header" / usbmuxd_header,
        "data"
        / Switch(
            this.header.message,
            {
                usbmuxd_msgtype.CONNECT: Struct(
                    "device_id" / Int32ul,
                    "port" / Int16ul,
                    "reserved" / Const(0, Int16ul),
                ),
                usbmuxd_msgtype.PLIST: GreedyBytes,
            },
        ),
    ),
    includelength=True,
)

usbmuxd_device_record = Struct(
    "device_id" / Int32ul,
    "product_id" / Int16ul,
    "serial_number" / FixedSized(256, CString("ascii")),
    Padding(2),
    "location" / Int32ul,
)

usbmuxd_response = Prefixed(
    Int32ul,
    Struct(
        "header" / usbmuxd_header,
        "data"
        / Switch(
            this.header.message,
            {
                usbmuxd_msgtype.RESULT: Struct(
                    "result" / usbmuxd_result,
                ),
                usbmuxd_msgtype.ADD: usbmuxd_device_record,
                usbmuxd_msgtype.REMOVE: Struct(
                    "device_id" / Int32ul,
                ),
                usbmuxd_msgtype.PLIST: GreedyBytes,
            },
        ),
    ),
    includelength=True,
)


@dataclass
class NetworkInterfaceState:
    name: str
    mac_address: Optional[str]
    operstate: Optional[str]
    carrier: Optional[bool]
    mtu: Optional[int]
    addresses: list[dict[str, object]]
    routes: list[dict[str, object]]
    neighbors: list[dict[str, object]]

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "mac_address": self.mac_address,
            "operstate": self.operstate,
            "carrier": self.carrier,
            "mtu": self.mtu,
            "addresses": self.addresses,
            "routes": self.routes,
            "neighbors": self.neighbors,
        }


@dataclass
class UsbEndpointDescriptor:
    address: int
    transfer_type: str
    max_packet_size: int
    interval: int

    def to_dict(self) -> dict[str, object]:
        return {
            "address": f"0x{self.address:02x}",
            "number": self.address & 0x0F,
            "direction": "in" if self.address & 0x80 else "out",
            "transfer_type": self.transfer_type,
            "max_packet_size": self.max_packet_size,
            "interval": self.interval,
        }


@dataclass
class UsbDescriptorInterface:
    number: int
    alternate_setting: int
    interface_class: str
    interface_subclass: str
    interface_protocol: str
    string_index: int
    alias: Optional[str]
    role: Optional[str]
    endpoints: list[UsbEndpointDescriptor]

    def to_dict(self) -> dict[str, object]:
        return {
            "number": self.number,
            "alternate_setting": self.alternate_setting,
            "interface_class": self.interface_class,
            "interface_subclass": self.interface_subclass,
            "interface_protocol": self.interface_protocol,
            "string_index": self.string_index,
            "alias": self.alias,
            "role": self.role,
            "endpoints": [endpoint.to_dict() for endpoint in self.endpoints],
        }


@dataclass
class UsbConfigurationDescriptor:
    value: int
    string_index: int
    num_interfaces: int
    attributes: str
    max_power_ma: int
    total_length: int
    interfaces: list[UsbDescriptorInterface]

    def to_dict(self) -> dict[str, object]:
        return {
            "value": self.value,
            "string_index": self.string_index,
            "num_interfaces": self.num_interfaces,
            "attributes": self.attributes,
            "max_power_ma": self.max_power_ma,
            "total_length": self.total_length,
            "interfaces": [interface.to_dict() for interface in self.interfaces],
        }


@dataclass
class UsbInterface:
    sysfs_name: str
    name: Optional[str]
    alias: Optional[str]
    role: Optional[str]
    number: Optional[int]
    alternate_setting: Optional[int]
    interface_class: Optional[str]
    interface_subclass: Optional[str]
    interface_protocol: Optional[str]
    endpoints: Optional[int]
    driver: Optional[str]
    network_interfaces: list[str]
    network_state: list[NetworkInterfaceState]
    modalias: Optional[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "sysfs_name": self.sysfs_name,
            "name": self.name,
            "alias": self.alias,
            "role": self.role,
            "number": self.number,
            "alternate_setting": self.alternate_setting,
            "interface_class": self.interface_class,
            "interface_subclass": self.interface_subclass,
            "interface_protocol": self.interface_protocol,
            "endpoints": self.endpoints,
            "driver": self.driver,
            "network_interfaces": self.network_interfaces,
            "network_state": [state.to_dict() for state in self.network_state],
            "modalias": self.modalias,
        }


@dataclass
class UsbDeviceInventory:
    sysfs_name: str
    vendor_id: Optional[str]
    product_id: Optional[str]
    manufacturer: Optional[str]
    product: Optional[str]
    serial: Optional[str]
    bus_number: Optional[int]
    device_address: Optional[int]
    speed: Optional[str]
    usb_version: Optional[str]
    configuration_value: Optional[int]
    configuration: Optional[str]
    num_configurations: Optional[int]
    num_interfaces: Optional[int]
    interfaces: list[UsbInterface]
    available_configurations: list[UsbConfigurationDescriptor]

    def matches_udid(self, udid: str) -> bool:
        if self.serial is None:
            return False
        return _normalize_udid(self.serial) == _normalize_udid(udid)

    def to_dict(self) -> dict[str, object]:
        return {
            "sysfs_name": self.sysfs_name,
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "manufacturer": self.manufacturer,
            "product": self.product,
            "serial": self.serial,
            "bus_number": self.bus_number,
            "device_address": self.device_address,
            "speed": self.speed,
            "usb_version": self.usb_version,
            "configuration_value": self.configuration_value,
            "configuration": self.configuration,
            "num_configurations": self.num_configurations,
            "num_interfaces": self.num_interfaces,
            "composition": usb_composition_summary(self.interfaces),
            "interfaces": [interface.to_dict() for interface in self.interfaces],
            "available_configurations": [configuration.to_dict() for configuration in self.available_configurations],
        }


@dataclass
class MuxDevice:
    devid: int
    serial: str
    connection_type: str

    async def connect(self, port: int, usbmux_address: Optional[str] = None) -> socket.socket:
        mux = await create_mux(usbmux_address=usbmux_address)
        try:
            return await mux.connect(self, port)
        except BaseException:
            await mux.close()
            raise

    @property
    def is_usb(self) -> bool:
        return self.connection_type == "USB"

    @property
    def is_network(self) -> bool:
        return self.connection_type == "Network"

    def matches_udid(self, udid: str) -> bool:
        return self.serial.replace("-", "") == udid.replace("-", "")


class MuxConnection:
    ITUNES_HOST = ITUNES_HOST
    USBMUXD_PIPE = USBMUXD_PIPE

    @staticmethod
    def _resolve_usbmux_address(usbmux_address: Optional[str] = None):
        if usbmux_address is not None:
            if ":" in usbmux_address:
                hostname, port = usbmux_address.split(":")
                return (hostname, int(port)), socket.AF_INET
            return usbmux_address, socket.AF_UNIX
        return get_os_utils().usbmux_address

    @staticmethod
    async def create_usbmux_socket(usbmux_address: Optional[str] = None) -> socket.socket:
        address, family = MuxConnection._resolve_usbmux_address(usbmux_address)
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            await asyncio.get_running_loop().sock_connect(sock, address)
        except ConnectionRefusedError as e:
            sock.close()
            raise ConnectionFailedToUsbmuxdError() from e
        except Exception:
            sock.close()
            raise
        return sock

    @staticmethod
    async def create(usbmux_address: Optional[str] = None):
        sock = await MuxConnection.create_usbmux_socket(usbmux_address=usbmux_address)
        try:
            probe_message = usbmuxd_request.build({
                "header": {"version": usbmuxd_version.PLIST, "message": usbmuxd_msgtype.PLIST, "tag": 1},
                "data": plistlib.dumps({"MessageType": "ReadBUID"}),
            })
            await asyncio.get_running_loop().sock_sendall(sock, probe_message)
            response = usbmuxd_response.parse(await MuxConnection._recv_packet(sock))
        finally:
            sock.close()

        sock = await MuxConnection.create_usbmux_socket(usbmux_address=usbmux_address)
        if response.header.version == usbmuxd_version.BINARY:
            return BinaryMuxConnection(sock)
        if response.header.version == usbmuxd_version.PLIST:
            return PlistMuxConnection(sock)
        sock.close()
        raise MuxVersionError(f"usbmuxd returned unsupported version: {response.version}")

    @staticmethod
    async def _recv_exactly(sock: socket.socket, size: int) -> bytes:
        data = b""
        loop = asyncio.get_running_loop()
        while len(data) < size:
            chunk = await loop.sock_recv(sock, size - len(data))
            if not chunk:
                raise MuxException("socket connection broken")
            data += chunk
        return data

    @staticmethod
    async def _recv_packet(sock: socket.socket) -> bytes:
        header = await MuxConnection._recv_exactly(sock, 4)
        size = struct.unpack("<L", header)[0]
        if size < 4:
            raise MuxException(f"Invalid usbmux packet size: {size}")
        payload = await MuxConnection._recv_exactly(sock, size - 4)
        return header + payload

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._connected = False
        self._tag = 1
        self.devices = []

    @abc.abstractmethod
    async def _connect(self, device_id: int, port: int):
        pass

    @abc.abstractmethod
    async def get_device_list(self, timeout: Optional[float] = None):
        pass

    @abc.abstractmethod
    async def listen(self):
        pass

    async def connect(self, device: MuxDevice, port: int) -> socket.socket:
        await self._connect(device.devid, socket.htons(port))
        self._connected = True
        self._sock.setblocking(True)
        return self._sock

    async def close(self):
        self._sock.close()

    def _assert_not_connected(self):
        if self._connected:
            raise MuxException("Mux is connected, cannot issue control packets")

    @abc.abstractmethod
    async def receive_device_state_update(self):
        pass

    def _raise_mux_exception(self, result: int, message: Optional[str] = None) -> None:
        exceptions = {
            int(usbmuxd_result.BADCOMMAND): BadCommandError,
            int(usbmuxd_result.BADDEV): BadDevError,
            int(usbmuxd_result.CONNREFUSED): ConnectionFailedError,
            int(usbmuxd_result.NOSUCHSERVICE): ConnectionFailedError,
            int(usbmuxd_result.BADVERSION): MuxVersionError,
        }
        exception = exceptions.get(result, MuxException)
        raise exception(message)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


class BinaryMuxConnection(MuxConnection):
    def __init__(self, sock: socket.socket):
        super().__init__(sock)
        self._version = usbmuxd_version.BINARY

    async def get_device_list(self, timeout: Optional[float] = None):
        self._assert_not_connected()
        timeout = timeout or 0
        end = time.time() + timeout
        await self.listen()
        while time.time() < end:
            try:
                await asyncio.wait_for(self.receive_device_state_update(), timeout=end - time.time())
            except asyncio.TimeoutError:
                continue
            except OSError as e:
                await self.close()
                raise MuxException("Exception in listener socket") from e

    async def listen(self):
        await self._send_receive(usbmuxd_msgtype.LISTEN)

    async def _connect(self, device_id: int, port: int):
        await self._send({
            "header": {"version": self._version, "message": usbmuxd_msgtype.CONNECT, "tag": self._tag},
            "data": {"device_id": device_id, "port": port},
        })
        response = await self._receive()
        if response.header.message != usbmuxd_msgtype.RESULT:
            raise MuxException(f"unexpected message type received: {response}")
        if response.data.result != usbmuxd_result.OK:
            raise self._raise_mux_exception(
                int(response.data.result),
                f"failed to connect to device: {device_id} at port: {port}. reason: {response.data.result}",
            )

    async def _send(self, data: dict):
        self._assert_not_connected()
        await asyncio.get_running_loop().sock_sendall(self._sock, usbmuxd_request.build(data))
        self._tag += 1

    async def _receive(self, expected_tag: Optional[int] = None):
        self._assert_not_connected()
        response = usbmuxd_response.parse(await self._recv_packet(self._sock))
        if expected_tag and response.header.tag != expected_tag:
            raise MuxException(f"Reply tag mismatch: expected {expected_tag}, got {response.header.tag}")
        return response

    async def receive_device_state_update(self):
        response = await self._receive()
        if response.header.message == usbmuxd_msgtype.ADD:
            self._add_device(MuxDevice(response.data.device_id, response.data.serial_number, "USB"))
        elif response.header.message == usbmuxd_msgtype.REMOVE:
            self._remove_device(response.data.device_id)
        elif response.header.message == usbmuxd_msgtype.PAIRED:
            # Pairing state updates don't change the tracked device list.
            return
        else:
            raise MuxException(f"Invalid packet type received: {response}")

    async def _send_receive(self, message_type: int):
        await self._send({"header": {"version": self._version, "message": message_type, "tag": self._tag}, "data": b""})
        response = await self._receive(self._tag - 1)
        if response.header.message != usbmuxd_msgtype.RESULT:
            raise MuxException(f"unexpected message type received: {response}")
        result = response.data.result
        if result != usbmuxd_result.OK:
            raise self._raise_mux_exception(int(result), f"{message_type} failed: error {result}")

    def _add_device(self, device: MuxDevice):
        self.devices.append(device)

    def _remove_device(self, device_id: int):
        self.devices = [device for device in self.devices if device.devid != device_id]


class PlistMuxConnection(BinaryMuxConnection):
    def __init__(self, sock: socket.socket):
        super().__init__(sock)
        self._version = usbmuxd_version.PLIST

    async def listen(self) -> None:
        await self._send_receive({"MessageType": "Listen"})

    async def get_pair_record(self, serial: str) -> dict:
        await self._send({"MessageType": "ReadPairRecord", "PairRecordID": serial})
        response = await self._receive(self._tag - 1)
        pair_record = response.get("PairRecordData")
        if pair_record is None:
            raise NotPairedError("device should be paired first")
        return plistlib.loads(pair_record)

    def _process_device_state(self, response):
        if response["MessageType"] == "Attached":
            super()._add_device(
                MuxDevice(
                    response["DeviceID"],
                    response["Properties"]["SerialNumber"],
                    response["Properties"]["ConnectionType"],
                )
            )
        elif response["MessageType"] == "Detached":
            super()._remove_device(response["DeviceID"])
        elif response["MessageType"] == "Paired":
            # Pairing notifications can arrive while listening to state updates.
            return
        else:
            raise MuxException(f"Invalid packet type received: {response}")

    async def get_device_list(self, timeout: Optional[float] = None) -> None:
        self.devices = []
        await self._send({"MessageType": "ListDevices"})
        response = await self._receive(self._tag - 1)
        device_list = response.get("DeviceList")
        if device_list is None:
            raise MuxException(f"Got an invalid response from usbmux: {response}")
        for item in device_list:
            self._process_device_state(item)

    async def get_buid(self) -> str:
        await self._send({"MessageType": "ReadBUID"})
        return (await self._receive(self._tag - 1))["BUID"]

    async def save_pair_record(self, serial: str, device_id: int, record_data: bytes):
        await self._send_receive({
            "MessageType": "SavePairRecord",
            "PairRecordID": serial,
            "PairRecordData": record_data,
            "DeviceID": device_id,
        })

    async def _connect(self, device_id: int, port: int):
        await self._send_receive({"MessageType": "Connect", "DeviceID": device_id, "PortNumber": port})

    async def _send(self, data: dict):
        request = {"ClientVersionString": "qt4i-usbmuxd", "ProgName": "pymobiledevice3", "kLibUSBMuxVersion": 3}
        request.update(data)
        await super()._send({
            "header": {"version": self._version, "message": usbmuxd_msgtype.PLIST, "tag": self._tag},
            "data": plistlib.dumps(request),
        })

    async def _receive(self, expected_tag: Optional[int] = None) -> dict:
        response = await super()._receive(expected_tag=expected_tag)
        if response.header.message != usbmuxd_msgtype.PLIST:
            raise MuxException(f"Received non-plist type {response}")
        return plistlib.loads(response.data)

    async def receive_device_state_update(self):
        response = await self._receive()
        self._process_device_state(response)

    async def _send_receive(self, data: dict):
        await self._send(data)
        response = await self._receive(self._tag - 1)
        if response["MessageType"] != "Result":
            raise MuxException(f"got an invalid message: {response}")
        if response["Number"] != 0:
            raise self._raise_mux_exception(response["Number"], f"got an error message: {response}")


def _read_sysfs_text(path: Path) -> Optional[str]:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return value or None


def _parse_sysfs_int(path: Path, base: int = 10) -> Optional[int]:
    value = _read_sysfs_text(path)
    if value is None:
        return None
    try:
        return int(value, base)
    except ValueError:
        return None


def _normalize_hex(value: Optional[str], width: int) -> Optional[str]:
    if value is None:
        return None
    value = value.strip().lower()
    if value.startswith("0x"):
        value = value[2:]
    return value.zfill(width)


def _normalize_udid(value: str) -> str:
    return value.replace("-", "").lower()


def _safe_iterdir(path: Path) -> list[Path]:
    try:
        return list(path.iterdir())
    except OSError:
        return []


def _read_driver_name(path: Path) -> Optional[str]:
    driver_path = path / "driver"
    if not driver_path.exists():
        return None
    try:
        return driver_path.resolve(strict=True).name
    except OSError:
        return None


def _read_network_interfaces(path: Path) -> list[str]:
    net_path = path / "net"
    if not net_path.is_dir():
        return []
    return sorted(child.name for child in _safe_iterdir(net_path))


def _run_ip_json(args: list[str]) -> list[dict[str, object]]:
    if shutil.which("ip") is None:
        return []
    try:
        result = subprocess.run(
            ["ip", "-j", *args],
            capture_output=True,
            check=False,
            encoding="utf-8",
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0 or not result.stdout.strip():
        return []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def _parse_carrier(value: Optional[str]) -> Optional[bool]:
    if value == "1":
        return True
    if value == "0":
        return False
    return None


def read_network_interface_state(
    name: str,
    net_sysfs_path: Union[str, Path] = LINUX_NET_SYSFS,
    include_ip_command: bool = True,
) -> NetworkInterfaceState:
    net_path = Path(net_sysfs_path) / name
    address_data = _run_ip_json(["addr", "show", "dev", name]) if include_ip_command else []
    address_info = address_data[0] if address_data else {}
    addresses = address_info.get("addr_info", [])
    if not isinstance(addresses, list):
        addresses = []

    routes = []
    neighbors = []
    if include_ip_command:
        routes.extend(_run_ip_json(["route", "show", "dev", name]))
        routes.extend(_run_ip_json(["-6", "route", "show", "dev", name]))
        neighbors.extend(_run_ip_json(["neigh", "show", "dev", name]))

    mac_address = _read_sysfs_text(net_path / "address") or address_info.get("address")
    operstate = _read_sysfs_text(net_path / "operstate") or address_info.get("operstate")

    return NetworkInterfaceState(
        name=name,
        mac_address=mac_address if isinstance(mac_address, str) else None,
        operstate=operstate.lower() if isinstance(operstate, str) else None,
        carrier=_parse_carrier(_read_sysfs_text(net_path / "carrier")),
        mtu=_parse_sysfs_int(net_path / "mtu"),
        addresses=addresses,
        routes=routes,
        neighbors=neighbors,
    )


def _read_network_interface_states(
    names: list[str],
    net_sysfs_path: Union[str, Path],
    include_ip_command: bool,
) -> list[NetworkInterfaceState]:
    return [
        read_network_interface_state(name, net_sysfs_path=net_sysfs_path, include_ip_command=include_ip_command)
        for name in names
    ]


def _dedupe_preserving_order(values: list[str]) -> list[str]:
    deduped = []
    for value in values:
        if value not in deduped:
            deduped.append(value)
    return deduped


def _composition_guess(alias_set: frozenset[str]) -> str:
    has_mux = "AppleUSBMux" in alias_set
    has_ptp = "PTP" in alias_set
    has_ethernet = "AppleUSBEthernet" in alias_set
    has_ncm = {"AppleUSBNCMControl", "AppleUSBNCMData"}.issubset(alias_set)
    has_ncm_aux = {"AppleUSBNCMControlAux", "AppleUSBNCMDataAux"}.issubset(alias_set)
    has_direct_ncm = {"AppleUSBNCMControlDirect", "AppleUSBNCMData"}.issubset(alias_set)
    has_iap = "IapOverUsbHid" in alias_set or "iAP" in alias_set
    has_uvc = bool({"UVCControlInterface", "UVCStreamInterface", "UVCStreamInterfaceA"} & alias_set)
    has_audio = any(alias.startswith("USBAudio") for alias in alias_set)

    if not alias_set:
        return "unknown"
    if has_direct_ncm and has_iap:
        return "carplay" if not has_mux else "carplay+mux"
    if has_mux and has_ptp and has_ethernet and has_ncm and has_ncm_aux:
        return "mux+ptp+ethernet+ncm+aux"
    if has_mux and has_ptp and has_ethernet:
        return "mux+ptp+ethernet"
    if has_mux and has_ptp:
        return "mux+ptp"
    if has_mux and has_ncm and has_ncm_aux:
        return "mux+ncm+aux"
    if has_mux and has_uvc and has_ncm_aux:
        return "mux+video+ncm-aux"
    if has_mux and has_ncm_aux:
        return "mux+ncm-aux"
    if has_mux and has_ncm:
        return "mux+ncm"
    if has_mux and has_uvc:
        return "mux+video"
    if has_mux and has_audio:
        return "mux+audio"
    if has_mux:
        return "mux-only"
    if has_ncm or has_direct_ncm:
        return "ncm-only"
    if has_ptp:
        return "ptp-only"
    return "unknown"


def usb_composition_summary(interfaces: list["UsbInterface"]) -> dict[str, object]:
    aliases = _dedupe_preserving_order([interface.alias for interface in interfaces if interface.alias is not None])
    roles = _dedupe_preserving_order([interface.role for interface in interfaces if interface.role is not None])
    alias_set = frozenset(aliases)
    hints = []
    if "AppleUSBMux" not in alias_set:
        hints.append("AppleUSBMux is not active; lockdown/usbmux services are not expected over this USB composition.")
    if {"AppleUSBNCMControlAux", "AppleUSBNCMDataAux"}.issubset(alias_set):
        hints.append("Aux NCM is active; remote services may also depend on a USB network interface.")
    if "Valeria" in alias_set:
        hints.append("Valeria is active; this is an extended Apple USB composition.")
    if {"AppleUSBNCMControlDirect", "AppleUSBNCMData"}.issubset(alias_set):
        hints.append("Direct NCM is active; this matches CarPlay-style USB networking compositions.")

    return {
        "guess": _composition_guess(alias_set),
        "aliases": aliases,
        "roles": roles,
        "firmware_matches": list(APPLE_USB_FIRMWARE_CONFIGURATION_SIGNATURES.get(alias_set, ())),
        "has_usbmux": "AppleUSBMux" in alias_set,
        "has_network": any(role in ("network", "network-control") for role in roles),
        "hints": hints,
    }


def _apple_interface_alias(
    name: Optional[str],
    interface_class: Optional[str] = None,
    interface_subclass: Optional[str] = None,
    interface_protocol: Optional[str] = None,
    apple_device: bool = True,
) -> Optional[str]:
    if name is not None:
        if name in APPLE_INTERFACE_ALIASES:
            return APPLE_INTERFACE_ALIASES[name]
        if name.startswith("Apple "):
            return name.replace(" ", "")
        return name
    if not apple_device:
        return None
    if interface_class == "06" and interface_subclass == "01" and interface_protocol == "01":
        return "PTP"
    if interface_class == "ff" and interface_subclass == "fe" and interface_protocol == "02":
        return "AppleUSBMux"
    if interface_class == "ff" and interface_subclass == "fd":
        return "AppleUSBEthernet"
    if interface_class == "02" and interface_subclass == "0d":
        return "AppleUSBNCMControl"
    if interface_class == "0a":
        return "AppleUSBNCMData"
    if interface_class == "01" and interface_subclass == "01":
        return "USBAudio2Control"
    if interface_class == "01" and interface_subclass == "02":
        return "USBAudio2Stream"
    if interface_class == "0e" and interface_subclass == "01":
        return "UVCControlInterface"
    if interface_class == "0e" and interface_subclass == "02":
        return "UVCStreamInterface"
    return None


def _interface_role(
    alias: Optional[str],
    name: Optional[str],
    interface_class: Optional[str],
    interface_subclass: Optional[str],
    interface_protocol: Optional[str],
) -> Optional[str]:
    name_lower = (name or alias or "").lower()
    if alias == "PTP" or (interface_class == "06" and interface_subclass == "01" and interface_protocol == "01"):
        return "ptp"
    if alias == "AppleUSBMux" or "multiplexor" in name_lower:
        return "usbmux"
    if alias in ("AppleUSBEthernet", "AppleUSBNCMData", "AppleUSBNCMDataAux") or "ethernet" in name_lower:
        return "network"
    if alias in ("AppleUSBNCMControl", "AppleUSBNCMControlAux", "AppleUSBNCMControlDirect"):
        return "network-control"
    if alias in ("iAP", "IapOverUsbHid") or name_lower == "iap":
        return "iap"
    if alias == "IDAMInterface":
        return "idam"
    if alias == "Valeria":
        return "valeria"
    if alias == "USBAudio2Control" or (interface_class == "01" and interface_subclass == "01"):
        return "audio-control"
    if (alias or "").startswith("USBAudio2Stream") or (interface_class == "01" and interface_subclass == "02"):
        return "audio-streaming"
    if alias == "UVCControlInterface" or (interface_class == "0e" and interface_subclass == "01"):
        return "video-control"
    if (alias or "").startswith("UVCStreamInterface") or (interface_class == "0e" and interface_subclass == "02"):
        return "video-streaming"
    if alias in ("USBDeviceTester", "AppleUSBTestInterface"):
        return "usb-test"
    if interface_class == "03":
        return "hid"
    return None


def _endpoint_transfer_type(attributes: int) -> str:
    return {
        0: "control",
        1: "isochronous",
        2: "bulk",
        3: "interrupt",
    }.get(attributes & 0x03, "unknown")


def _le16(data: bytes, offset: int) -> int:
    return data[offset] | (data[offset + 1] << 8)


def parse_usb_configuration_descriptors(data: bytes, apple_device: bool = True) -> list[UsbConfigurationDescriptor]:
    configurations = []
    current_configuration = None
    current_interface = None
    offset = 0
    while offset + 2 <= len(data):
        length = data[offset]
        descriptor_type = data[offset + 1]
        if length < 2 or offset + length > len(data):
            break
        descriptor = data[offset : offset + length]

        if descriptor_type == 2 and length >= 9:
            current_configuration = UsbConfigurationDescriptor(
                value=descriptor[5],
                string_index=descriptor[6],
                num_interfaces=descriptor[4],
                attributes=f"0x{descriptor[7]:02x}",
                max_power_ma=descriptor[8] * 2,
                total_length=_le16(descriptor, 2),
                interfaces=[],
            )
            configurations.append(current_configuration)
            current_interface = None
        elif descriptor_type == 4 and length >= 9 and current_configuration is not None:
            interface_class = f"{descriptor[5]:02x}"
            interface_subclass = f"{descriptor[6]:02x}"
            interface_protocol = f"{descriptor[7]:02x}"
            alias = _apple_interface_alias(
                None, interface_class, interface_subclass, interface_protocol, apple_device=apple_device
            )
            current_interface = UsbDescriptorInterface(
                number=descriptor[2],
                alternate_setting=descriptor[3],
                interface_class=interface_class,
                interface_subclass=interface_subclass,
                interface_protocol=interface_protocol,
                string_index=descriptor[8],
                alias=alias,
                role=_interface_role(alias, None, interface_class, interface_subclass, interface_protocol),
                endpoints=[],
            )
            current_configuration.interfaces.append(current_interface)
        elif descriptor_type == 5 and length >= 7 and current_interface is not None:
            current_interface.endpoints.append(
                UsbEndpointDescriptor(
                    address=descriptor[2],
                    transfer_type=_endpoint_transfer_type(descriptor[3]),
                    max_packet_size=_le16(descriptor, 4),
                    interval=descriptor[6],
                )
            )

        offset += length
    return configurations


def _read_usb_configuration_descriptors(path: Path, apple_device: bool = True) -> list[UsbConfigurationDescriptor]:
    try:
        data = (path / "descriptors").read_bytes()
    except OSError:
        return []
    return parse_usb_configuration_descriptors(data, apple_device=apple_device)


def _read_usb_interface(
    path: Path,
    include_network_state: bool = False,
    net_sysfs_path: Union[str, Path] = LINUX_NET_SYSFS,
    include_ip_command: bool = True,
    apple_device: bool = True,
) -> Optional[UsbInterface]:
    number = _parse_sysfs_int(path / "bInterfaceNumber")
    if number is None:
        return None
    name = _read_sysfs_text(path / "interface")
    interface_class = _normalize_hex(_read_sysfs_text(path / "bInterfaceClass"), 2)
    interface_subclass = _normalize_hex(_read_sysfs_text(path / "bInterfaceSubClass"), 2)
    interface_protocol = _normalize_hex(_read_sysfs_text(path / "bInterfaceProtocol"), 2)
    alias = _apple_interface_alias(
        name, interface_class, interface_subclass, interface_protocol, apple_device=apple_device
    )
    network_interfaces = _read_network_interfaces(path)
    return UsbInterface(
        sysfs_name=path.name,
        name=name,
        alias=alias,
        role=_interface_role(alias, name, interface_class, interface_subclass, interface_protocol),
        number=number,
        alternate_setting=_parse_sysfs_int(path / "bAlternateSetting"),
        interface_class=interface_class,
        interface_subclass=interface_subclass,
        interface_protocol=interface_protocol,
        endpoints=_parse_sysfs_int(path / "bNumEndpoints"),
        driver=_read_driver_name(path),
        network_interfaces=network_interfaces,
        network_state=_read_network_interface_states(network_interfaces, net_sysfs_path, include_ip_command)
        if include_network_state
        else [],
        modalias=_read_sysfs_text(path / "modalias"),
    )


def _read_usb_device_inventory(
    path: Path,
    include_network_state: bool = False,
    net_sysfs_path: Union[str, Path] = LINUX_NET_SYSFS,
    include_ip_command: bool = True,
    include_configuration_descriptors: bool = False,
) -> UsbDeviceInventory:
    vendor_id = _normalize_hex(_read_sysfs_text(path / "idVendor"), 4)
    apple_device = vendor_id == APPLE_VENDOR_ID
    interfaces = []
    interface_prefix = f"{path.name}:"
    for child in _safe_iterdir(path.parent):
        if not child.name.startswith(interface_prefix):
            continue
        interface = _read_usb_interface(
            child,
            include_network_state=include_network_state,
            net_sysfs_path=net_sysfs_path,
            include_ip_command=include_ip_command,
            apple_device=apple_device,
        )
        if interface is not None:
            interfaces.append(interface)
    interfaces.sort(
        key=lambda interface: (interface.number or -1, interface.alternate_setting or -1, interface.sysfs_name)
    )

    return UsbDeviceInventory(
        sysfs_name=path.name,
        vendor_id=vendor_id,
        product_id=_normalize_hex(_read_sysfs_text(path / "idProduct"), 4),
        manufacturer=_read_sysfs_text(path / "manufacturer"),
        product=_read_sysfs_text(path / "product"),
        serial=_read_sysfs_text(path / "serial"),
        bus_number=_parse_sysfs_int(path / "busnum"),
        device_address=_parse_sysfs_int(path / "devnum"),
        speed=_read_sysfs_text(path / "speed"),
        usb_version=_read_sysfs_text(path / "version"),
        configuration_value=_parse_sysfs_int(path / "bConfigurationValue"),
        configuration=_read_sysfs_text(path / "configuration"),
        num_configurations=_parse_sysfs_int(path / "bNumConfigurations"),
        num_interfaces=_parse_sysfs_int(path / "bNumInterfaces"),
        interfaces=interfaces,
        available_configurations=_read_usb_configuration_descriptors(path, apple_device=apple_device)
        if include_configuration_descriptors
        else [],
    )


def list_usb_device_inventory(
    sysfs_path: Union[str, Path] = LINUX_USB_SYSFS,
    vendor_id: Optional[str] = APPLE_VENDOR_ID,
    include_network_state: bool = False,
    net_sysfs_path: Union[str, Path] = LINUX_NET_SYSFS,
    include_ip_command: bool = True,
    include_configuration_descriptors: bool = False,
) -> list[UsbDeviceInventory]:
    """Return active USB configuration/interface data from Linux sysfs."""
    sysfs_root = Path(sysfs_path)
    if not sysfs_root.exists():
        return []

    normalized_vendor_id = _normalize_hex(vendor_id, 4) if vendor_id is not None else None
    devices = []
    for child in _safe_iterdir(sysfs_root):
        child_vendor_id = _normalize_hex(_read_sysfs_text(child / "idVendor"), 4)
        if child_vendor_id is None:
            continue
        if normalized_vendor_id is not None and child_vendor_id != normalized_vendor_id:
            continue
        devices.append(
            _read_usb_device_inventory(
                child,
                include_network_state=include_network_state,
                net_sysfs_path=net_sysfs_path,
                include_ip_command=include_ip_command,
                include_configuration_descriptors=include_configuration_descriptors,
            )
        )

    devices.sort(key=lambda device: (device.bus_number or -1, device.device_address or -1, device.sysfs_name))
    return devices


async def create_mux(usbmux_address: Optional[str] = None) -> MuxConnection:
    return await MuxConnection.create(usbmux_address=usbmux_address)


async def list_devices(usbmux_address: Optional[str] = None) -> list[MuxDevice]:
    mux = await create_mux(usbmux_address=usbmux_address)
    try:
        await mux.get_device_list(0.1)
        devices = mux.devices
    finally:
        await mux.close()
    return devices


async def select_device(
    udid: Optional[str] = None, connection_type: Optional[str] = None, usbmux_address: Optional[str] = None
) -> Optional[MuxDevice]:
    tmp = None
    for device in await list_devices(usbmux_address=usbmux_address):
        if connection_type is not None and device.connection_type != connection_type:
            continue
        if udid is not None and not device.matches_udid(udid):
            continue
        tmp = device
        if device.is_usb:
            return device
    return tmp


async def select_devices_by_connection_type(
    connection_type: str, usbmux_address: Optional[str] = None
) -> list[MuxDevice]:
    return [
        device
        for device in await list_devices(usbmux_address=usbmux_address)
        if device.connection_type == connection_type
    ]
