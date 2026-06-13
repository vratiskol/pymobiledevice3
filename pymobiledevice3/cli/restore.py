import asyncio
import contextlib
import logging
import plistlib
import tempfile
import time
import traceback
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Annotated, Any, Optional, Union

import click
import requests
import typer
from ipsw_parser.ipsw import IPSW
from pygments import formatters, highlight, lexers
from typer_injector import Depends, InjectingTyper

from pymobiledevice3 import usbmux
from pymobiledevice3.cli.cli_common import (
    async_command,
    cli_loop,
    is_invoked_for_completion,
    print_json,
    prompt_selection,
)
from pymobiledevice3.exceptions import (
    ConnectionFailedError,
    ConnectionFailedToUsbmuxdError,
    IncorrectModeError,
    IRecvNoDeviceConnectedError,
    PyMobileDevice3Exception,
)
from pymobiledevice3.irecv import IRecv
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.purple import (
    build_purple_reverse_proxy_info,
    collect_live_purple_reverse_proxy_probe,
    collect_live_purple_reverse_proxy_status,
)
from pymobiledevice3.restore.purple_proxy import (
    PURPLE_PROXY_CONTROL_PORT,
    PURPLE_PROXY_CONTROL_PROTOCOL_VERSION,
    PURPLE_PROXY_NOTIFY_PORT,
    PURPLE_PROXY_SOCKS_PORT,
    PurpleProxyCommand,
    run_purple_proxy_control_command,
    run_purple_proxy_notify_command,
)
from pymobiledevice3.restore.recovery import Behavior, Recovery
from pymobiledevice3.restore.restore import Restore
from pymobiledevice3.restore.restored_client import RestoredClient
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.services.diagnostics import DiagnosticsService
from pymobiledevice3.utils import file_download, start_ipython_shell

logger = logging.getLogger(__name__)


SHELL_USAGE = """
# use `irecv` variable to access Restore mode API
# for example:
print(irecv.getenv('build-version'))
"""
IPSWME_API = "https://api.ipsw.me/v4/device/"


cli = InjectingTyper(
    name="restore",
    help="Restore/erase IPSWs, fetch blobs, and manage devices in Recovery/DFU.",
    no_args_is_help=True,
)


async def _device_dependency_async(
    ecid: Annotated[
        Optional[str],
        typer.Option(
            help="Target device ECID; defaults to the first connected USB device or waits for Recovery/DFU.",
        ),
    ] = None,
) -> Optional[Device]:
    if is_invoked_for_completion():
        # prevent lockdown connection establishment when in autocomplete mode
        return None

    logger.debug("searching among connected devices via lockdownd")
    devices = [dev for dev in await usbmux.list_devices() if dev.connection_type == "USB"]
    if len(devices) > 1:
        raise click.ClickException("Multiple device detected")
    try:
        for device in devices:
            try:
                lockdown = await create_using_usbmux(serial=device.serial, connection_type="USB")
            except (ConnectionFailedError, IncorrectModeError):
                continue
            if (ecid is None) or (lockdown.ecid == ecid):
                logger.debug("found device")
                return Device(lockdown=lockdown)
            else:
                continue
    except ConnectionFailedToUsbmuxdError:
        pass

    logger.debug("waiting for device to be available in Recovery mode")
    return Device(irecv=IRecv(ecid=ecid))


def device_dependency(
    ecid: Annotated[
        Optional[str],
        typer.Option(
            help="Target device ECID; defaults to the first connected USB device or waits for Recovery/DFU.",
        ),
    ] = None,
) -> Optional[Device]:
    return cli_loop.run_until_complete(_device_dependency_async(ecid))


DeviceDep = Annotated[
    Device,
    Depends(device_dependency),
]


@contextlib.contextmanager
def tempzip_download_ctx(url: str) -> Iterator[IPSW]:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpzip = Path(tmpdir) / url.split("/")[-1]
        file_download(url, tmpzip)
        with ipsw_ctx(tmpzip) as ipsw:
            yield ipsw


@contextlib.contextmanager
def ipsw_ctx(path: Union[str, Path]) -> Iterator[IPSW]:
    yield IPSW.create_from_path(path)


def ipsw_ctx_dependency(
    device: DeviceDep,
    ipsw: Annotated[
        Optional[str],
        typer.Option(
            "--ipsw",
            "-i",
            help="Path or URL to an IPSW. If omitted, choose a signed build interactively.",
        ),
    ] = None,
) -> contextlib.AbstractContextManager[IPSW]:
    if ipsw and not ipsw.startswith(("http://", "https://")):
        return ipsw_ctx(ipsw)

    url = ipsw
    if url is None:
        url = query_ipswme(cli_loop.run_until_complete(device.get_product_type()))
    return tempzip_download_ctx(url)


IPSWCtxDep = Annotated[
    contextlib.AbstractContextManager[IPSW],
    Depends(ipsw_ctx_dependency),
]


def tss_dependency(
    tss: Annotated[
        Optional[Path],
        typer.Option(help="Path to SHSH blob plist to use for signing requests."),
    ] = None,
) -> None:
    if tss is None:
        return
    with tss.open("rb") as tss_file:
        return plistlib.load(tss_file)


TSSDep = Annotated[
    Optional[dict],
    Depends(tss_dependency),
]


BehaviorOption = Annotated[
    Behavior,
    typer.Option(help="Restore behavior to use when selecting the BuildIdentity."),
]

RestoreExitState = dict[str, Any]


def query_ipswme(identifier: str) -> str:
    resp = requests.get(IPSWME_API + identifier, headers={"Accept": "application/json"})
    firmwares = resp.json()["firmwares"]
    display_list = [f"{entry['version']}: {entry['buildid']}" for entry in firmwares if entry["signed"]]
    idx = prompt_selection(display_list, "Choose version", idx=True)
    return firmwares[idx]["url"]


async def restore_update_task(device: Device, ipsw: IPSW, tss: Optional[dict], erase: bool, ignore_fdr: bool) -> None:
    behavior = Behavior.Update
    if erase:
        behavior = Behavior.Erase

    try:
        await Restore(ipsw, device, tss=tss, behavior=behavior, ignore_fdr=ignore_fdr).update()
    except Exception:
        # click may "swallow" several exception types so we try to catch them all here
        traceback.print_exc()
        raise


def _lockdown_public_state(lockdown: Any) -> RestoreExitState:
    state: RestoreExitState = {"state": "normal"}
    for attr, key in (
        ("product_type", "product_type"),
        ("product_version", "product_version"),
        ("build_version", "build_version"),
    ):
        value = getattr(lockdown, attr, None)
        if value:
            state[key] = value
    return state


def _irecv_public_state() -> Optional[RestoreExitState]:
    try:
        irecv = IRecv(timeout=0.2)
    except IRecvNoDeviceConnectedError:
        return None
    except Exception:
        logger.debug("failed to probe irecv state", exc_info=True)
        return None

    mode = irecv.mode
    if mode is None:
        return None

    state: RestoreExitState = {
        "state": "recovery" if mode.is_recovery else "dfu",
        "mode": mode.name,
    }
    with contextlib.suppress(Exception):
        state["product_type"] = irecv.product_type
    return state


async def _usbmux_query_type_state(device: Any) -> Optional[RestoreExitState]:
    service: Optional[ServiceConnection] = None
    try:
        service = await ServiceConnection.create_using_usbmux(
            device.serial,
            RestoredClient.SERVICE_PORT,
            connection_type=device.connection_type,
        )
        await service.start()
        query_type = await service.send_recv_plist({"Request": "QueryType"})
    except Exception:
        logger.debug("failed to query usbmux QueryType state", exc_info=True)
        return None
    finally:
        if service is not None:
            with contextlib.suppress(Exception):
                await service.close()

    response_type = query_type.get("Type")
    if response_type == "com.apple.mobile.restored":
        return {
            "state": "restored",
            "restore_protocol_version": query_type.get("RestoreProtocolVersion"),
        }
    if response_type == "com.apple.mobile.lockdown":
        return {"state": "normal"}

    return None


async def detect_restore_exit_state() -> RestoreExitState:
    """
    Return a redacted post-exit device state.

    Recovery/DFU devices are not visible through usbmuxd, so both irecv and usbmuxd
    are probed. Identifiers such as UDID, serial number, and ECID are intentionally
    omitted from the returned structure.
    """
    irecv_state = _irecv_public_state()
    if irecv_state is not None:
        return irecv_state

    try:
        devices = [device for device in await usbmux.list_devices() if device.connection_type == "USB"]
    except ConnectionFailedToUsbmuxdError:
        return {"state": "not_seen", "reason": "usbmuxd_unavailable"}
    except OSError as e:
        return {"state": "not_seen", "reason": f"usbmuxd_error:{e.__class__.__name__}"}

    for device in devices:
        query_type_state = await _usbmux_query_type_state(device)
        if query_type_state is None:
            continue
        if query_type_state["state"] == "restored":
            return query_type_state

        try:
            lockdown = await create_using_usbmux(
                serial=device.serial,
                connection_type="USB",
                autopair=False,
            )
        except (PyMobileDevice3Exception, OSError) as e:
            query_type_state["lockdown_available"] = False
            query_type_state["reason"] = f"lockdown_error:{e.__class__.__name__}"
            return query_type_state
        return _lockdown_public_state(lockdown)

    for device in devices:
        try:
            lockdown = await create_using_usbmux(
                serial=device.serial,
                connection_type="USB",
                autopair=False,
            )
        except (PyMobileDevice3Exception, OSError):
            continue
        return _lockdown_public_state(lockdown)

    return {"state": "not_seen", "usb_device_count": len(devices)}


async def wait_for_restore_exit_state(timeout: float, poll_interval: float = 1.0) -> RestoreExitState:
    start = time.monotonic()
    deadline = start + timeout
    last_state: RestoreExitState = {"state": "not_seen"}

    while time.monotonic() < deadline:
        last_state = await detect_restore_exit_state()
        if last_state["state"] not in ("not_seen", "not_seen_timeout"):
            last_state["elapsed"] = round(time.monotonic() - start, 3)
            return last_state
        await asyncio.sleep(min(poll_interval, max(0.0, deadline - time.monotonic())))

    return {
        "state": "not_seen_timeout",
        "timeout": timeout,
        "last_probe": last_state,
    }


@cli.command("shell")
def restore_shell(device: DeviceDep) -> None:
    """create an IPython shell for interacting with iBoot"""
    start_ipython_shell(
        header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.Terminal256Formatter(style="native")),
        user_ns={
            "irecv": device,
        },
    )


@cli.command("enter")
@async_command
async def restore_enter(device: DeviceDep) -> None:
    """enter Recovery mode"""
    if await device.get_is_lockdown():
        await device.lockdown.enter_recovery()


@cli.command("exit")
def restore_exit(
    wait: Annotated[
        bool,
        typer.Option("--wait", help="Wait for the device to reappear and report its post-exit mode."),
    ] = False,
    timeout: Annotated[
        float,
        typer.Option("--timeout", min=1.0, help="Maximum seconds to wait when --wait is used."),
    ] = 120.0,
    poll_interval: Annotated[
        float,
        typer.Option("--poll-interval", min=0.1, help="Seconds between post-exit state probes."),
    ] = 1.0,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print a machine-readable result."),
    ] = False,
) -> None:
    """exit Recovery mode"""
    result: RestoreExitState = {
        "command": "restore exit",
        "reboot_command_sent": False,
        "waited": wait,
    }

    irecv = IRecv()
    irecv.set_autoboot(True)
    irecv.reboot()
    result["reboot_command_sent"] = True

    if wait:
        result["post_exit"] = cli_loop.run_until_complete(
            wait_for_restore_exit_state(timeout=timeout, poll_interval=poll_interval)
        )

    if json_output:
        print_json(result, colored=False)
    elif wait:
        click.echo(result["post_exit"]["state"])

    if wait and result["post_exit"]["state"] == "not_seen_timeout":
        raise typer.Exit(1)


@cli.command("restart")
@async_command
async def restore_restart(device: DeviceDep) -> None:
    """restarts device"""
    if await device.get_is_lockdown():
        async with DiagnosticsService(device.lockdown) as diagnostics:
            await diagnostics.restart()
    else:
        device.irecv.reboot()


async def restore_tss_task(
    device: Device,
    ipsw_ctx: contextlib.AbstractContextManager[IPSW],
    out: Optional[IO],
    behavior: Behavior = Behavior.Update,
) -> None:
    with ipsw_ctx as ipsw:
        tss = await Recovery(ipsw, device, behavior=behavior).fetch_tss_record()
    if out:
        plistlib.dump(tss, out)
    print_json(tss)


@cli.command("tss")
@async_command
async def restore_tss(
    device: DeviceDep,
    ipsw_ctx: IPSWCtxDep,
    out: Optional[Path] = None,
    behavior: BehaviorOption = Behavior.Update,
) -> None:
    """query SHSH blobs"""
    with out.open("wb") if out else contextlib.nullcontext() as out_file:
        await restore_tss_task(device, ipsw_ctx, out_file, behavior=behavior)


async def restore_ramdisk_task(device: Device, ipsw_ctx: contextlib.AbstractContextManager[IPSW]) -> None:
    with ipsw_ctx as ipsw:
        await Recovery(ipsw, device).boot_ramdisk()


@cli.command("ramdisk")
@async_command
async def restore_ramdisk(device: DeviceDep, ipsw_ctx: IPSWCtxDep) -> None:
    """
    Boot only the update ramdisk without performing a restore (IPSW path or URL accepted).
    """
    await restore_ramdisk_task(device, ipsw_ctx)


@cli.command("purple-info")
@async_command
async def restore_purple_info(
    firmware_root: Annotated[
        Optional[Path],
        typer.Option(
            "--firmware-root",
            help="Path to an extracted RestoreOS ramdisk root to inspect for PurpleReverseProxy artifacts.",
        ),
    ] = None,
    no_device: Annotated[
        bool,
        typer.Option("--no-device", help="Skip live usbmux inspection and print only static/firmware information."),
    ] = False,
    deep: Annotated[
        bool,
        typer.Option("--deep", help="Include hashes, Mach-O UUIDs, and grouped PurpleReverseProxy string evidence."),
    ] = False,
    ecid: Annotated[
        Optional[str],
        typer.Option(help="Filter live USB inspection to a specific device ECID."),
    ] = None,
    usbmux_address: Annotated[
        Optional[str],
        typer.Option("--usbmux-address", help="Address of the usbmuxd daemon (unix socket path or HOST:PORT)."),
    ] = None,
) -> None:
    """
    Inspect PurpleReverseProxy RestoreOS ramdisk support without booting or restoring a device.
    """
    info = build_purple_reverse_proxy_info(firmware_root=firmware_root, deep=deep)
    if no_device:
        info["live"] = {"checked": False, "reason": "--no-device was provided."}
    else:
        info["live"] = await collect_live_purple_reverse_proxy_status(ecid=ecid, usbmux_address=usbmux_address)
    print_json(info)


@cli.command("purple-probe")
@async_command
async def restore_purple_probe(
    timeout: Annotated[
        float,
        typer.Option("--timeout", min=0.1, help="Per-connection timeout for usbmux port and QueryType probes."),
    ] = 1.0,
    include_services: Annotated[
        bool,
        typer.Option(
            "--include-services",
            help="Also try starting PurpleReverseProxy lockdown service names when lockdownd is reachable.",
        ),
    ] = False,
    usbmux_address: Annotated[
        Optional[str],
        typer.Option("--usbmux-address", help="Address of the usbmuxd daemon (unix socket path or HOST:PORT)."),
    ] = None,
) -> None:
    """
    Probe PurpleReverseProxy RestoreOS ports through usbmux without restoring a device.
    """
    print_json(
        await collect_live_purple_reverse_proxy_probe(
            usbmux_address=usbmux_address,
            timeout=timeout,
            include_services=include_services,
        )
    )


@cli.command("purple-control")
@async_command
async def restore_purple_control(
    hello: Annotated[
        bool,
        typer.Option(
            "--hello",
            help="Send the legacy experimental HelloCtrl message to the PurpleReverseProxy control port.",
        ),
    ] = False,
    begin: Annotated[
        bool,
        typer.Option("--begin", help="Send BeginCtrl with CtrlProtoVersion to the PurpleReverseProxy control port."),
    ] = False,
    wait_socket: Annotated[
        bool,
        typer.Option("--wait-socket", help="Send WaitSocket with ConnPort to the PurpleReverseProxy control port."),
    ] = False,
    timeout: Annotated[
        float,
        typer.Option("--timeout", min=0.1, help="Timeout for connecting and waiting for a control reply."),
    ] = 1.0,
    port: Annotated[
        int,
        typer.Option("--port", min=1, max=0xFFFF, help="Device-side PurpleReverseProxy control port."),
    ] = PURPLE_PROXY_CONTROL_PORT,
    protocol_version: Annotated[
        int,
        typer.Option("--protocol-version", min=0, help="CtrlProtoVersion value to send with HelloCtrl or BeginCtrl."),
    ] = PURPLE_PROXY_CONTROL_PROTOCOL_VERSION,
    conn_port: Annotated[
        int,
        typer.Option("--conn-port", min=1, max=0xFFFF, help="ConnPort value to send with WaitSocket."),
    ] = PURPLE_PROXY_SOCKS_PORT,
    include_response: Annotated[
        bool,
        typer.Option("--include-response", help="Include the sanitized response dictionary in JSON output."),
    ] = False,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Exit non-zero when the control operation is not reachable."),
    ] = False,
    udid: Annotated[
        Optional[str],
        typer.Option("--udid", "--serial", help="Target device serial/UDID; never printed in command output."),
    ] = None,
    usbmux_address: Annotated[
        Optional[str],
        typer.Option("--usbmux-address", help="Address of the usbmuxd daemon (unix socket path or HOST:PORT)."),
    ] = None,
) -> None:
    """
    Send experimental PurpleReverseProxy control messages without restoring a device.
    """
    operation_count = int(hello) + int(begin) + int(wait_socket)
    if operation_count != 1:
        raise click.ClickException("Choose exactly one control operation: --hello, --begin, or --wait-socket.")

    if hello:
        command = PurpleProxyCommand.HELLO_CONTROL
    elif begin:
        command = PurpleProxyCommand.BEGIN_CONTROL
    else:
        command = PurpleProxyCommand.WAIT_SOCKET

    result = await run_purple_proxy_control_command(
        command,
        udid=udid,
        usbmux_address=usbmux_address,
        timeout=timeout,
        port=port,
        protocol_version=protocol_version,
        conn_port=conn_port,
        include_response=include_response,
    )
    print_json(result, colored=False)
    if strict and not result["reachable"]:
        raise typer.Exit(1)


@cli.command("purple-notify")
@async_command
async def restore_purple_notify(
    register: Annotated[
        bool,
        typer.Option("--register", help="Send RegisterNotify to the PurpleReverseProxy notify port."),
    ] = False,
    set_log_level: Annotated[
        Optional[int],
        typer.Option("--set-log-level", min=0, max=7, help="Send SetLogLevel with a firmware log level value."),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option("--timeout", min=0.1, help="Timeout for connecting and sending the notify command."),
    ] = 1.0,
    port: Annotated[
        int,
        typer.Option("--port", min=1, max=0xFFFF, help="Device-side PurpleReverseProxy notify port."),
    ] = PURPLE_PROXY_NOTIFY_PORT,
    include_response: Annotated[
        bool,
        typer.Option(
            "--include-response", help="Include sanitized response or notification dictionaries in JSON output."
        ),
    ] = False,
    expect_response: Annotated[
        bool,
        typer.Option("--expect-response", help="Wait for one immediate response dictionary after sending the command."),
    ] = False,
    listen_timeout: Annotated[
        float,
        typer.Option(
            "--listen-timeout", min=0.0, help="Seconds to collect asynchronous notify dictionaries after send."
        ),
    ] = 0.0,
    max_messages: Annotated[
        int,
        typer.Option("--max-messages", min=1, help="Maximum notify dictionaries to collect when listening."),
    ] = 8,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Exit non-zero when the notify operation is not reachable."),
    ] = False,
    udid: Annotated[
        Optional[str],
        typer.Option("--udid", "--serial", help="Target device serial/UDID; never printed in command output."),
    ] = None,
    usbmux_address: Annotated[
        Optional[str],
        typer.Option("--usbmux-address", help="Address of the usbmuxd daemon (unix socket path or HOST:PORT)."),
    ] = None,
) -> None:
    """
    Send experimental PurpleReverseProxy notify/logging messages without restoring a device.
    """
    operation_count = int(register) + int(set_log_level is not None)
    if operation_count != 1:
        raise click.ClickException("Choose exactly one notify operation: --register or --set-log-level.")

    command = PurpleProxyCommand.REGISTER_NOTIFY if register else PurpleProxyCommand.SET_LOG_LEVEL
    result = await run_purple_proxy_notify_command(
        command,
        level=set_log_level,
        udid=udid,
        usbmux_address=usbmux_address,
        timeout=timeout,
        port=port,
        include_response=include_response,
        expect_response=expect_response,
        listen_timeout=listen_timeout,
        max_messages=max_messages,
    )
    print_json(result, colored=False)
    if strict and not result["reachable"]:
        raise typer.Exit(1)


@cli.command("update")
@async_command
async def restore_update(
    device: DeviceDep,
    ipsw_ctx: IPSWCtxDep,
    tss: TSSDep,
    erase: Annotated[
        bool,
        typer.Option(help="Erase and restore (factory reset) instead of updating in place."),
    ] = False,
    ignore_fdr: Annotated[
        bool,
        typer.Option(help="Connect to the FDR service only (debug mode; no traffic proxying)."),
    ] = False,
) -> None:
    """
    Update or restore the device using an IPSW (local path or URL).
    """
    with ipsw_ctx as ipsw:
        await restore_update_task(device, ipsw, tss, erase, ignore_fdr)
