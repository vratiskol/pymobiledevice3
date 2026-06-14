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
    build_purple_reverse_proxy_capabilities,
    build_purple_reverse_proxy_info,
    build_purple_reverse_proxy_port_config,
    build_purple_reverse_proxy_restore_options,
    collect_live_purple_reverse_proxy_probe,
    collect_live_purple_reverse_proxy_status,
)
from pymobiledevice3.restore.purple_proxy import (
    PURPLE_PROXY_CONTROL_PORT,
    PURPLE_PROXY_CONTROL_PROTOCOL_VERSION,
    PURPLE_PROXY_LOOPBACK_HOST,
    PURPLE_PROXY_NOTIFY_PORT,
    PURPLE_PROXY_SOCKS_PORT,
    PurpleProxyCommand,
    build_purple_proxy_dictionary,
    run_purple_proxy_control_command,
    run_purple_proxy_notify_command,
    run_purple_proxy_session,
    run_purple_proxy_socks_probe,
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


async def restore_update_task(
    device: Device,
    ipsw: IPSW,
    tss: Optional[dict],
    erase: bool,
    ignore_fdr: bool,
    purple_restore_options: Optional[dict[str, Any]] = None,
) -> None:
    behavior = Behavior.Update
    if erase:
        behavior = Behavior.Erase

    try:
        await Restore(
            ipsw,
            device,
            tss=tss,
            behavior=behavior,
            ignore_fdr=ignore_fdr,
            purple_restore_options=purple_restore_options,
        ).update()
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


@cli.command("purple-capabilities")
@async_command
async def restore_purple_capabilities(
    firmware_root: Annotated[
        Optional[Path],
        typer.Option(
            "--firmware-root",
            help="Path to an extracted RestoreOS ramdisk root to inspect for PurpleReverseProxy artifacts.",
        ),
    ] = None,
    deep: Annotated[
        bool,
        typer.Option("--deep", help="Include deep firmware evidence in the capability matrix."),
    ] = False,
    no_live: Annotated[
        bool,
        typer.Option("--no-live", help="Skip the redacted live usbmux port probe."),
    ] = False,
    timeout: Annotated[
        float,
        typer.Option("--timeout", min=0.1, help="Per-connection timeout for the live usbmux port probe."),
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
    Print the PurpleReverseProxy static/model/live capability matrix.
    """
    result = build_purple_reverse_proxy_capabilities(firmware_root=firmware_root, deep=deep)
    if no_live:
        result["live_probe"] = {"checked": False, "reason": "--no-live was provided."}
    else:
        probe_kwargs = {
            "usbmux_address": usbmux_address,
            "timeout": timeout,
            "include_services": include_services,
        }
        port_config = result.get("port_config")
        if port_config is not None:
            probe_kwargs["ports"] = port_config["probe_ports"]
        live_probe = await collect_live_purple_reverse_proxy_probe(**probe_kwargs)
        result["live_probe"] = live_probe
        result["summary"].update({
            "live_probe_mode": live_probe.get("mode"),
            "live_probe_device_count": live_probe.get("device_count", 0),
        })
    print_json(result, colored=False)


def _purple_port_config(firmware_root: Optional[Path]) -> Optional[dict[str, Any]]:
    if firmware_root is None:
        return None
    return build_purple_reverse_proxy_port_config(firmware_root)


def _purple_configured_port(
    port_config: Optional[dict[str, Any]],
    name: str,
    cli_value: int,
    default_value: int,
) -> int:
    if port_config is not None and cli_value == default_value:
        return port_config["ports"][name]
    return cli_value


def _annotate_port_config(result: dict[str, Any], port_config: Optional[dict[str, Any]]) -> None:
    if port_config is not None:
        result["port_config"] = port_config


@cli.command("purple-probe")
@async_command
async def restore_purple_probe(
    timeout: Annotated[
        float,
        typer.Option("--timeout", min=0.1, help="Per-connection timeout for usbmux port and QueryType probes."),
    ] = 1.0,
    firmware_root: Annotated[
        Optional[Path],
        typer.Option(
            "--firmware-root",
            help="Read PurpleReverseProxy socket ports from an extracted RestoreOS ramdisk root.",
        ),
    ] = None,
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
    port_config = _purple_port_config(firmware_root)
    probe_kwargs = {
        "usbmux_address": usbmux_address,
        "timeout": timeout,
        "include_services": include_services,
    }
    if port_config is not None:
        probe_kwargs["ports"] = port_config["probe_ports"]
    result = await collect_live_purple_reverse_proxy_probe(**probe_kwargs)
    _annotate_port_config(result, port_config)
    print_json(result, colored=False)


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
    ping: Annotated[
        bool,
        typer.Option("--ping", help="Send Ping and validate a Pong response from the PurpleReverseProxy control port."),
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
    firmware_root: Annotated[
        Optional[Path],
        typer.Option(
            "--firmware-root",
            help="Read PurpleReverseProxy control and SOCKS ports from an extracted RestoreOS ramdisk root.",
        ),
    ] = None,
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
    operation_count = int(hello) + int(begin) + int(wait_socket) + int(ping)
    if operation_count != 1:
        raise click.ClickException("Choose exactly one control operation: --hello, --begin, --wait-socket, or --ping.")

    if hello:
        command = PurpleProxyCommand.HELLO_CONTROL
    elif begin:
        command = PurpleProxyCommand.BEGIN_CONTROL
    elif wait_socket:
        command = PurpleProxyCommand.WAIT_SOCKET
    else:
        command = PurpleProxyCommand.PING

    port_config = _purple_port_config(firmware_root)
    effective_port = _purple_configured_port(port_config, "ctrl", port, PURPLE_PROXY_CONTROL_PORT)
    effective_conn_port = _purple_configured_port(port_config, "socks", conn_port, PURPLE_PROXY_SOCKS_PORT)
    result = await run_purple_proxy_control_command(
        command,
        udid=udid,
        usbmux_address=usbmux_address,
        timeout=timeout,
        port=effective_port,
        protocol_version=protocol_version,
        conn_port=effective_conn_port,
        include_response=include_response,
    )
    _annotate_port_config(result, port_config)
    print_json(result, colored=False)
    if strict and (not result["reachable"] or (command is PurpleProxyCommand.PING and not result.get("pong"))):
        raise typer.Exit(1)


@cli.command("purple-proxy-dict")
@async_command
async def restore_purple_proxy_dict(
    url: Annotated[
        str,
        typer.Option("--url", help="URL passed to the modeled CopyProxyDictionaryWithOptions path."),
    ] = "https://www.apple.com/",
    socks_port: Annotated[
        int,
        typer.Option("--socks-port", min=1, max=0xFFFF, help="SOCKS port to place in the proxy dictionary."),
    ] = PURPLE_PROXY_SOCKS_PORT,
    proxy_host: Annotated[
        str,
        typer.Option("--proxy-host", help="SOCKS proxy host to place in the proxy dictionary."),
    ] = PURPLE_PROXY_LOOPBACK_HOST,
    no_test_reachability: Annotated[
        bool,
        typer.Option("--no-test-reachability", help="Model CopyProxyDictionaryWithOptions with TestReachability off."),
    ] = False,
    ping: Annotated[
        bool,
        typer.Option("--ping", help="Also send Ping to the PurpleReverseProxy control port."),
    ] = False,
    timeout: Annotated[
        float,
        typer.Option("--timeout", min=0.1, help="Timeout for the optional Ping operation."),
    ] = 1.0,
    control_port: Annotated[
        int,
        typer.Option("--control-port", min=1, max=0xFFFF, help="Device-side PurpleReverseProxy control port."),
    ] = PURPLE_PROXY_CONTROL_PORT,
    include_response: Annotated[
        bool,
        typer.Option("--include-response", help="Include the sanitized Ping response dictionary in JSON output."),
    ] = False,
    firmware_root: Annotated[
        Optional[Path],
        typer.Option(
            "--firmware-root",
            help="Read PurpleReverseProxy SOCKS and control ports from an extracted RestoreOS ramdisk root.",
        ),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Exit non-zero when --ping is used and Ping is not reachable or not Pong."),
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
    Model libReverseProxyDevice CopyProxyDictionaryWithOptions output for PurpleReverseProxy.
    """
    port_config = _purple_port_config(firmware_root)
    effective_socks_port = _purple_configured_port(port_config, "socks", socks_port, PURPLE_PROXY_SOCKS_PORT)
    effective_control_port = _purple_configured_port(port_config, "ctrl", control_port, PURPLE_PROXY_CONTROL_PORT)
    result = build_purple_proxy_dictionary(
        url=url,
        host=proxy_host,
        socks_port=effective_socks_port,
        test_reachability=not no_test_reachability,
    )
    if ping:
        result["ping"] = await run_purple_proxy_control_command(
            PurpleProxyCommand.PING,
            udid=udid,
            usbmux_address=usbmux_address,
            timeout=timeout,
            port=effective_control_port,
            include_response=include_response,
        )
    _annotate_port_config(result, port_config)
    print_json(result, colored=False)
    if strict and ping and (not result["ping"]["reachable"] or not result["ping"].get("pong")):
        raise typer.Exit(1)


@cli.command("purple-socks-probe")
@async_command
async def restore_purple_socks_probe(
    timeout: Annotated[
        float,
        typer.Option("--timeout", min=0.1, help="Timeout for connecting and waiting for SOCKS replies."),
    ] = 1.0,
    port: Annotated[
        int,
        typer.Option("--port", min=1, max=0xFFFF, help="Device-side PurpleReverseProxy SOCKS port."),
    ] = PURPLE_PROXY_SOCKS_PORT,
    connect_host: Annotated[
        Optional[str],
        typer.Option(
            "--connect-host",
            help="Optionally send a SOCKS5 CONNECT request; the host value is not printed in JSON output.",
        ),
    ] = None,
    connect_port: Annotated[
        int,
        typer.Option("--connect-port", min=1, max=0xFFFF, help="Port for the optional SOCKS5 CONNECT request."),
    ] = 443,
    include_response: Annotated[
        bool,
        typer.Option("--include-response", help="Include raw SOCKS response bytes as hex in JSON output."),
    ] = False,
    firmware_root: Annotated[
        Optional[Path],
        typer.Option(
            "--firmware-root",
            help="Read PurpleReverseProxy SOCKS port from an extracted RestoreOS ramdisk root.",
        ),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Exit non-zero when the SOCKS probe summary is not ok."),
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
    Probe the PurpleReverseProxy SOCKS data plane without restoring a device.
    """
    port_config = _purple_port_config(firmware_root)
    effective_port = _purple_configured_port(port_config, "socks", port, PURPLE_PROXY_SOCKS_PORT)
    try:
        result = await run_purple_proxy_socks_probe(
            udid=udid,
            usbmux_address=usbmux_address,
            timeout=timeout,
            port=effective_port,
            connect_host=connect_host,
            connect_port=connect_port,
            include_response=include_response,
        )
    except ValueError as e:
        raise click.ClickException(str(e)) from None
    _annotate_port_config(result, port_config)
    print_json(result, colored=False)
    if strict and not result["summary"]["ok"]:
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
    firmware_root: Annotated[
        Optional[Path],
        typer.Option(
            "--firmware-root",
            help="Read PurpleReverseProxy notify port from an extracted RestoreOS ramdisk root.",
        ),
    ] = None,
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
    port_config = _purple_port_config(firmware_root)
    effective_port = _purple_configured_port(port_config, "notify", port, PURPLE_PROXY_NOTIFY_PORT)
    result = await run_purple_proxy_notify_command(
        command,
        level=set_log_level,
        udid=udid,
        usbmux_address=usbmux_address,
        timeout=timeout,
        port=effective_port,
        include_response=include_response,
        expect_response=expect_response,
        listen_timeout=listen_timeout,
        max_messages=max_messages,
    )
    _annotate_port_config(result, port_config)
    print_json(result, colored=False)
    if strict and not result["reachable"]:
        raise typer.Exit(1)


def _purple_session_reachable_ports(probe: dict[str, Any]) -> list[str]:
    reachable_ports = set()
    for device in probe.get("devices", []):
        for port in device.get("ports", []):
            if port.get("reachable") and port.get("name") is not None:
                reachable_ports.add(str(port["name"]))
    return sorted(reachable_ports)


@cli.command("purple-session")
@async_command
async def restore_purple_session(
    timeout: Annotated[
        float,
        typer.Option("--timeout", min=0.1, help="Timeout for each PurpleReverseProxy connection and reply."),
    ] = 1.0,
    control_port: Annotated[
        int,
        typer.Option("--control-port", min=1, max=0xFFFF, help="Device-side PurpleReverseProxy control port."),
    ] = PURPLE_PROXY_CONTROL_PORT,
    notify_port: Annotated[
        int,
        typer.Option("--notify-port", min=1, max=0xFFFF, help="Device-side PurpleReverseProxy notify port."),
    ] = PURPLE_PROXY_NOTIFY_PORT,
    protocol_version: Annotated[
        int,
        typer.Option("--protocol-version", min=0, help="CtrlProtoVersion value to send with BeginCtrl."),
    ] = PURPLE_PROXY_CONTROL_PROTOCOL_VERSION,
    conn_port: Annotated[
        int,
        typer.Option("--conn-port", min=1, max=0xFFFF, help="ConnPort value to send with WaitSocket."),
    ] = PURPLE_PROXY_SOCKS_PORT,
    log_level: Annotated[
        Optional[int],
        typer.Option("--log-level", min=0, max=7, help="Optionally send SetLogLevel before RegisterNotify."),
    ] = None,
    url: Annotated[
        str,
        typer.Option("--url", help="URL passed to the modeled CopyProxyDictionaryWithOptions path."),
    ] = "https://www.apple.com/",
    proxy_host: Annotated[
        str,
        typer.Option("--proxy-host", help="SOCKS proxy host to place in the proxy dictionary."),
    ] = PURPLE_PROXY_LOOPBACK_HOST,
    include_response: Annotated[
        bool,
        typer.Option(
            "--include-response", help="Include sanitized response or notification dictionaries in JSON output."
        ),
    ] = False,
    listen_timeout: Annotated[
        float,
        typer.Option(
            "--listen-timeout", min=0.0, help="Seconds to collect asynchronous notify dictionaries during the session."
        ),
    ] = 1.0,
    max_messages: Annotated[
        int,
        typer.Option("--max-messages", min=1, help="Maximum notify dictionaries to collect while listening."),
    ] = 8,
    probe_socks: Annotated[
        bool,
        typer.Option("--probe-socks", help="Also run a SOCKS5 data-plane probe on --conn-port after WaitSocket."),
    ] = False,
    socks_connect_host: Annotated[
        Optional[str],
        typer.Option(
            "--socks-connect-host",
            help="Optionally send a SOCKS5 CONNECT request during --probe-socks; the host is not printed.",
        ),
    ] = None,
    socks_connect_port: Annotated[
        int,
        typer.Option("--socks-connect-port", min=1, max=0xFFFF, help="Port for the optional session SOCKS CONNECT."),
    ] = 443,
    firmware_root: Annotated[
        Optional[Path],
        typer.Option(
            "--firmware-root",
            help="Read PurpleReverseProxy socket ports from an extracted RestoreOS ramdisk root.",
        ),
    ] = None,
    include_services: Annotated[
        bool,
        typer.Option(
            "--include-services",
            help="Also try starting PurpleReverseProxy lockdown service names when lockdownd is reachable.",
        ),
    ] = False,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Exit non-zero when the session summary is not ok."),
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
    Run the PurpleReverseProxy restore-session probe sequence.
    """
    port_config = _purple_port_config(firmware_root)
    effective_control_port = _purple_configured_port(
        port_config,
        "ctrl",
        control_port,
        PURPLE_PROXY_CONTROL_PORT,
    )
    effective_notify_port = _purple_configured_port(
        port_config,
        "notify",
        notify_port,
        PURPLE_PROXY_NOTIFY_PORT,
    )
    effective_conn_port = _purple_configured_port(port_config, "socks", conn_port, PURPLE_PROXY_SOCKS_PORT)
    probe_kwargs = {
        "usbmux_address": usbmux_address,
        "timeout": timeout,
        "include_services": include_services,
    }
    if port_config is not None:
        probe_kwargs["ports"] = port_config["probe_ports"]
    probe = await collect_live_purple_reverse_proxy_probe(**probe_kwargs)
    result = await run_purple_proxy_session(
        udid=udid,
        usbmux_address=usbmux_address,
        timeout=timeout,
        control_port=effective_control_port,
        notify_port=effective_notify_port,
        protocol_version=protocol_version,
        conn_port=effective_conn_port,
        log_level=log_level,
        url=url,
        proxy_host=proxy_host,
        include_response=include_response,
        listen_timeout=listen_timeout,
        max_messages=max_messages,
        probe_socks=probe_socks,
        socks_connect_host=socks_connect_host,
        socks_connect_port=socks_connect_port,
    )
    _annotate_port_config(result, port_config)
    result["phases"] = {
        "probe": probe,
        **result["phases"],
    }
    result["summary"].update({
        "probe_mode": probe.get("mode"),
        "probe_reachable_ports": _purple_session_reachable_ports(probe),
    })
    print_json(result, colored=False)
    if strict and not result["summary"]["ok"]:
        raise typer.Exit(1)


@cli.command("purple-restore-options")
@async_command
async def restore_purple_restore_options(
    enable: Annotated[
        bool,
        typer.Option("--enable", help="Set UsePurpleReverseProxy in the modeled RestoreOptions patch."),
    ] = False,
    disable: Annotated[
        bool,
        typer.Option("--disable", help="Set DisableReverseProxy in the modeled RestoreOptions patch."),
    ] = False,
    log_level: Annotated[
        Optional[int],
        typer.Option("--log-level", min=0, max=7, help="Set restored_update PRPLogLevel in RestoreOptions."),
    ] = None,
    socks_host: Annotated[
        Optional[str],
        typer.Option("--socks-host", help="Set ARUService SOCKSHost in RestoreOptions."),
    ] = None,
    socks_port: Annotated[
        Optional[int],
        typer.Option("--socks-port", min=1, max=0xFFFF, help="Set ARUService SOCKSPort in RestoreOptions."),
    ] = None,
) -> None:
    """
    Build the experimental PurpleReverseProxy RestoreOptions patch without restoring a device.
    """
    try:
        result = build_purple_reverse_proxy_restore_options(
            enable=enable,
            disable=disable,
            log_level=log_level,
            socks_host=socks_host,
            socks_port=socks_port,
        )
    except ValueError as e:
        raise click.ClickException(str(e)) from None
    print_json(result, colored=False)


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
    use_purple_reverse_proxy: Annotated[
        bool,
        typer.Option(
            "--use-purple-reverse-proxy",
            help="Set UsePurpleReverseProxy in RestoreOptions (experimental; iOS 27 RestoreOS evidence).",
        ),
    ] = False,
    disable_purple_reverse_proxy: Annotated[
        bool,
        typer.Option(
            "--disable-purple-reverse-proxy",
            help="Set DisableReverseProxy in RestoreOptions (experimental; iOS 27 RestoreOS evidence).",
        ),
    ] = False,
    purple_log_level: Annotated[
        Optional[int],
        typer.Option("--purple-log-level", min=0, max=7, help="Set restored_update PRPLogLevel in RestoreOptions."),
    ] = None,
    purple_socks_host: Annotated[
        Optional[str],
        typer.Option("--purple-socks-host", help="Set ARUService SOCKSHost in RestoreOptions."),
    ] = None,
    purple_socks_port: Annotated[
        Optional[int],
        typer.Option("--purple-socks-port", min=1, max=0xFFFF, help="Set ARUService SOCKSPort in RestoreOptions."),
    ] = None,
) -> None:
    """
    Update or restore the device using an IPSW (local path or URL).
    """
    purple_restore_options = None
    if (
        use_purple_reverse_proxy
        or disable_purple_reverse_proxy
        or purple_log_level is not None
        or purple_socks_host is not None
        or purple_socks_port is not None
    ):
        try:
            purple_restore_options = build_purple_reverse_proxy_restore_options(
                enable=use_purple_reverse_proxy,
                disable=disable_purple_reverse_proxy,
                log_level=purple_log_level,
                socks_host=purple_socks_host,
                socks_port=purple_socks_port,
            )["restore_options"]
        except ValueError as e:
            raise click.ClickException(str(e)) from None
    with ipsw_ctx as ipsw:
        await restore_update_task(device, ipsw, tss, erase, ignore_fdr, purple_restore_options=purple_restore_options)
