import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Annotated, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3 import usbmux
from pymobiledevice3.cli.cli_common import USBMUX_ENV_VARS, USBMUX_OPTION_HELP, async_command, print_json
from pymobiledevice3.exceptions import ConnectionFailedToUsbmuxdError, MuxException
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.tcp_forwarder import UsbmuxTcpForwarder

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="usbmux",
    help="Inspect usbmuxd-connected devices and forward TCP ports to them.",
    no_args_is_help=True,
)


@cli.command("forward")
@async_command
async def usbmux_forward(
    src_port: Annotated[
        int,
        typer.Argument(min=1, max=0xFFFF),
    ],
    dst_port: Annotated[
        int,
        typer.Argument(min=1, max=0xFFFF),
    ],
    *,
    usbmux_address: Annotated[
        Optional[str],
        typer.Option(
            "--usbmux",
            envvar=USBMUX_ENV_VARS,
            help=USBMUX_OPTION_HELP,
        ),
    ] = None,
    serial: Annotated[
        Optional[str],
        typer.Option("--serial", "--udid", help="Device serial/UDID to forward traffic to."),
    ] = None,
    host: Annotated[
        str,
        typer.Option(help="Address to bind the local port to."),
    ] = "127.0.0.1",
    daemonize: Annotated[
        bool,
        typer.Option("--daemonize", "-d", help="Run the forwarder in the background."),
    ] = False,
) -> None:
    """Forward a local TCP port to the device via usbmuxd."""
    forwarder = UsbmuxTcpForwarder(serial, dst_port, src_port, usbmux_address=usbmux_address)

    if daemonize:
        try:
            from daemonize import Daemonize
        except ImportError as e:
            raise NotImplementedError("daemonizing is only supported on unix platforms") from e

        with tempfile.NamedTemporaryFile("wt") as pid_file:
            daemon = Daemonize(
                app=f"forwarder {src_port}->{dst_port}",
                pid=pid_file.name,
                action=lambda: asyncio.run(forwarder.start(address=host)),
            )
            daemon.start()
    else:
        await forwarder.start(address=host)


def _usbmux_info_for_usb_device(
    usb_device: usbmux.UsbDeviceInventory, mux_devices: list[usbmux.MuxDevice]
) -> Optional[dict]:
    mux_device = next((device for device in mux_devices if usb_device.matches_udid(device.serial)), None)
    if mux_device is None:
        return None
    return {
        "device_id": mux_device.devid,
        "serial": mux_device.serial,
        "connection_type": mux_device.connection_type,
    }


async def _build_usb_interfaces_payload(
    usbmux_address: Optional[str],
    serial: Optional[str],
    all_devices: bool,
    sysfs: Path,
    network: bool,
    descriptors: bool,
) -> list[dict[str, object]]:
    mux_devices = []
    try:
        mux_devices = await usbmux.list_devices(usbmux_address=usbmux_address)
    except (ConnectionFailedToUsbmuxdError, MuxException, OSError) as e:
        logger.debug("failed to list usbmux devices for USB inventory enrichment: %s", e)

    vendor_id = None if all_devices else usbmux.APPLE_VENDOR_ID
    connected_devices = []
    for usb_device in usbmux.list_usb_device_inventory(
        sysfs_path=sysfs,
        vendor_id=vendor_id,
        include_network_state=network,
        include_configuration_descriptors=descriptors,
    ):
        if serial is not None and not usb_device.matches_udid(serial):
            continue

        device_info = usb_device.to_dict()
        device_info["usbmux"] = _usbmux_info_for_usb_device(usb_device, mux_devices)
        connected_devices.append(device_info)
    return connected_devices


@cli.command("interfaces")
@async_command
async def usbmux_interfaces(
    usbmux_address: Annotated[
        Optional[str],
        typer.Option(
            "--usbmux",
            envvar=USBMUX_ENV_VARS,
            help=USBMUX_OPTION_HELP,
        ),
    ] = None,
    serial: Annotated[
        Optional[str],
        typer.Option("--serial", "--udid", help="Device serial/UDID to inspect."),
    ] = None,
    all_devices: Annotated[
        bool,
        typer.Option("--all", help="Include non-Apple USB devices."),
    ] = False,
    sysfs: Annotated[
        Path,
        typer.Option("--sysfs", help="Linux USB sysfs devices directory."),
    ] = usbmux.LINUX_USB_SYSFS,
    network: Annotated[
        bool,
        typer.Option("--network/--no-network", help="Include Linux IP state for USB network interfaces."),
    ] = True,
    descriptors: Annotated[
        bool,
        typer.Option("--descriptors", help="Include all USB configuration descriptors exposed by sysfs."),
    ] = False,
    watch: Annotated[
        bool,
        typer.Option("--watch", "--wait", help="Keep polling and print a JSON snapshot when USB state changes."),
    ] = False,
    interval: Annotated[
        float,
        typer.Option("--interval", min=0.1, help="Polling interval in seconds for --watch/--wait."),
    ] = 1.0,
) -> None:
    """List active USB configurations and interfaces exposed by devices."""
    previous_signature = None
    while True:
        payload = await _build_usb_interfaces_payload(usbmux_address, serial, all_devices, sysfs, network, descriptors)
        if not watch:
            print_json(payload)
            return

        signature = json.dumps(payload, sort_keys=True)
        if signature != previous_signature:
            print_json({"event": "initial" if previous_signature is None else "changed", "devices": payload})
            previous_signature = signature
        await asyncio.sleep(interval)


@cli.command("list")
@async_command
async def usbmux_list(
    usbmux_address: Annotated[
        Optional[str],
        typer.Option(
            "--usbmux",
            envvar=USBMUX_ENV_VARS,
            help=USBMUX_OPTION_HELP,
        ),
    ] = None,
    usb: Annotated[
        bool,
        typer.Option(
            "--usb",
            "-u",
            help="show only USB devices",
        ),
    ] = False,
    network: Annotated[
        bool,
        typer.Option(
            "--network",
            "-n",
            help="show only network devices",
        ),
    ] = False,
    simple: Annotated[
        bool,
        typer.Option(
            "--simple",
            help="List only UDIDs without connecting to lockdownd.",
        ),
    ] = False,
) -> None:
    """List devices known to usbmuxd (USB and Wi-Fi)."""
    connected_devices = []
    for device in await usbmux.list_devices(usbmux_address=usbmux_address):
        udid = device.serial

        if usb and not device.is_usb:
            continue

        if network and not device.is_network:
            continue

        if simple:
            connected_devices.append(udid)
            continue

        lockdown = await create_using_usbmux(
            udid, autopair=False, connection_type=device.connection_type, usbmux_address=usbmux_address
        )
        connected_devices.append(lockdown.short_info)

    print_json(connected_devices)
