import asyncio
import contextlib
import logging
import plistlib
import tempfile
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
    USBMUX_ENV_VARS,
    USBMUX_OPTION_HELP,
    async_command,
    cli_loop,
    is_invoked_for_completion,
    print_json,
    prompt_selection,
)
from pymobiledevice3.exceptions import ConnectionFailedError, ConnectionFailedToUsbmuxdError, IncorrectModeError
from pymobiledevice3.irecv import (
    IBOOT_FLAG_EFFECTIVE_PRODUCTION_MODE,
    IBOOT_FLAG_EFFECTIVE_SECURITY_MODE,
    IBOOT_FLAG_IMAGE4_AWARE,
    IRecv,
)
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.protocol import collect_restore_protocol_info
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


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _int_info(value: Optional[int]) -> Optional[dict]:
    if value is None:
        return None
    return {
        "decimal": value,
        "hex": f"0x{value:x}",
    }


def _parse_ecid(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    value = value.strip()
    if value.lower().startswith("0x"):
        return int(value, 16)
    try:
        return int(value, 10)
    except ValueError:
        return int(value, 16)


def _error_info(error: Exception) -> dict:
    return {
        "type": error.__class__.__name__,
        "message": str(error),
    }


def _matches_ecid(ecid: Optional[int], found_ecid: Optional[int]) -> bool:
    return ecid is None or found_ecid == ecid


def _lockdown_restore_info(lockdown, connection_type: str) -> dict:
    all_values = lockdown.all_values
    ap_parameters = all_values.get("ApParameters") or {}
    unique_chip_id = all_values.get("UniqueChipID")
    return {
        "source": "lockdown",
        "mode": "normal",
        "transport": connection_type,
        "identifier": lockdown.udid or all_values.get("UniqueDeviceID"),
        "ecid": _int_info(unique_chip_id),
        "product": {
            "type": lockdown.product_type or all_values.get("ProductType"),
            "version": all_values.get("ProductVersion"),
            "build_version": all_values.get("BuildVersion"),
        },
        "hardware": {
            "model": all_values.get("HardwareModel"),
            "platform": all_values.get("HardwarePlatform"),
            "device_class": all_values.get("DeviceClass"),
            "image4_supported": all_values.get("Image4Supported"),
        },
        "nonces": {
            "ap_nonce": _json_safe(ap_parameters.get("ApNonce") or all_values.get("ApNonce")),
            "sep_nonce": _json_safe(ap_parameters.get("SepNonce") or all_values.get("SEPNonce")),
        },
        "preflight": {
            "ap_parameters_available": bool(ap_parameters),
            "firmware_preflight_info_available": "FirmwarePreflightInfo" in all_values,
        },
    }


def _irecv_restore_info(irecv: IRecv) -> dict:
    mode = irecv.mode
    iboot_flags = irecv.ibfl
    return {
        "source": "irecv",
        "mode": {
            "name": mode.name,
            "value": f"0x{mode.value:04x}",
            "is_recovery": mode.is_recovery,
        },
        "ecid": _int_info(irecv.ecid),
        "product": {
            "type": irecv.product_type,
            "hardware_model": irecv.hardware_model,
            "display_name": irecv.display_name,
        },
        "hardware": {
            "chip_id": _int_info(irecv.chip_id),
            "board_id": _int_info(irecv.board_id),
            "serial_number": irecv.serial_number,
        },
        "iboot": {
            "version": irecv.iboot_version,
            "image4_supported": bool(irecv.is_image4_supported),
            "flags": {
                "raw": _int_info(iboot_flags),
                "image4_aware": bool(iboot_flags & IBOOT_FLAG_IMAGE4_AWARE),
                "effective_security_mode": bool(iboot_flags & IBOOT_FLAG_EFFECTIVE_SECURITY_MODE),
                "effective_production_mode": bool(iboot_flags & IBOOT_FLAG_EFFECTIVE_PRODUCTION_MODE),
            },
        },
        "nonces": {
            "ap_nonce": _json_safe(irecv.ap_nonce),
            "sep_nonce": _json_safe(irecv.sep_nonce),
        },
    }


def _restored_restore_info(restored_client: RestoredClient, query_type: dict, connection_type: Optional[str]) -> dict:
    return {
        "source": "restored",
        "mode": "restored",
        "transport": connection_type,
        "identifier": restored_client.udid,
        "ecid": _int_info(restored_client.ecid),
        "restore_protocol_version": restored_client.version,
        "query_type": _json_safe(query_type),
        "hardware_info": _json_safe(restored_client.hardware_info),
        "saved_debug_info": _json_safe(restored_client.saved_debug_info),
    }


async def _inspect_lockdown_devices(ecid: Optional[int], include_errors: bool) -> tuple[list[dict], list[dict]]:
    devices = []
    errors = []
    try:
        mux_devices = await usbmux.list_devices()
    except Exception as e:
        return [], [{"source": "usbmux", "error": _error_info(e)}] if include_errors else []

    for mux_device in mux_devices:
        if mux_device.connection_type != "USB":
            continue
        lockdown = None
        try:
            lockdown = await create_using_usbmux(
                serial=mux_device.serial,
                connection_type=mux_device.connection_type,
                autopair=False,
            )
            unique_chip_id = lockdown.all_values.get("UniqueChipID")
            if _matches_ecid(ecid, unique_chip_id):
                devices.append(_lockdown_restore_info(lockdown, mux_device.connection_type))
        except Exception as e:
            if include_errors:
                errors.append({
                    "source": "lockdown",
                    "identifier": mux_device.serial,
                    "error": _error_info(e),
                })
        finally:
            if lockdown is not None:
                await lockdown.close()
    return devices, errors


async def _inspect_restored_devices(
    ecid: Optional[int], include_errors: bool, timeout: float
) -> tuple[list[dict], list[dict]]:
    devices = []
    errors = []
    try:
        mux_devices = await usbmux.list_devices()
    except Exception as e:
        return [], [{"source": "usbmux", "error": _error_info(e)}] if include_errors else []

    for mux_device in mux_devices:
        if mux_device.connection_type != "USB":
            continue
        service = None
        try:
            service = await asyncio.wait_for(
                ServiceConnection.create_using_usbmux(
                    mux_device.serial,
                    RestoredClient.SERVICE_PORT,
                    connection_type=mux_device.connection_type,
                ),
                timeout=timeout,
            )
            await asyncio.wait_for(service.start(), timeout=timeout)
            query_type = await asyncio.wait_for(service.send_recv_plist({"Request": "QueryType"}), timeout=timeout)
            if query_type.get("Type") != "com.apple.mobile.restored":
                continue
            restored_client = RestoredClient(mux_device.serial, query_type.get("RestoreProtocolVersion"), service)
            await asyncio.wait_for(restored_client._connect(), timeout=timeout)
            if _matches_ecid(ecid, restored_client.ecid):
                devices.append(_restored_restore_info(restored_client, query_type, mux_device.connection_type))
        except Exception as e:
            if include_errors:
                errors.append({
                    "source": "restored",
                    "identifier": mux_device.serial,
                    "error": _error_info(e),
                })
        finally:
            if service is not None:
                await service.close()
    return devices, errors


def _inspect_irecv_device(ecid: Optional[int], include_errors: bool, timeout: float) -> tuple[list[dict], list[dict]]:
    try:
        irecv = IRecv(ecid=ecid, timeout=timeout)
    except Exception as e:
        return [], [{"source": "irecv", "error": _error_info(e)}] if include_errors else []

    if not _matches_ecid(ecid, irecv.ecid):
        return [], []
    return [_irecv_restore_info(irecv)], []


async def restore_info_task(ecid: Optional[str], wait: float, include_errors: bool) -> None:
    parsed_ecid = _parse_ecid(ecid)
    timeout = max(wait, 0.1)
    lockdown_devices, lockdown_errors = await _inspect_lockdown_devices(parsed_ecid, include_errors)
    restored_devices, restored_errors = await _inspect_restored_devices(parsed_ecid, include_errors, timeout)
    irecv_devices, irecv_errors = _inspect_irecv_device(parsed_ecid, include_errors, timeout)
    devices = lockdown_devices + restored_devices + irecv_devices
    print_json({
        "ecid_filter": _int_info(parsed_ecid),
        "summary": {
            "devices": len(devices),
            "normal": sum(1 for device in devices if device["source"] == "lockdown"),
            "restored": sum(1 for device in devices if device["source"] == "restored"),
            "irecv": sum(1 for device in devices if device["source"] == "irecv"),
            "errors": len(lockdown_errors + restored_errors + irecv_errors),
        },
        "devices": devices,
        "errors": lockdown_errors + restored_errors + irecv_errors,
    })


@cli.command("info")
@async_command
async def restore_info(
    ecid: Annotated[
        Optional[str],
        typer.Option(help="Target ECID as decimal, 0xHEX, or plain hex."),
    ] = None,
    wait: Annotated[
        float,
        typer.Option("--wait", min=0.0, help="Seconds to wait while scanning for Recovery/DFU USB mode."),
    ] = 0.1,
    include_errors: Annotated[
        bool,
        typer.Option("--include-errors", help="Include per-transport discovery errors in the JSON output."),
    ] = False,
) -> None:
    """Inspect normal, restored, Recovery, or DFU restore-mode state without changing the device."""
    await restore_info_task(ecid, wait, include_errors)


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
def restore_exit() -> None:
    """exit Recovery mode"""
    irecv = IRecv()
    irecv.set_autoboot(True)
    irecv.reboot()


@cli.command("restart")
@async_command
async def restore_restart(device: DeviceDep) -> None:
    """restarts device"""
    if await device.get_is_lockdown():
        async with DiagnosticsService(device.lockdown) as diagnostics:
            await diagnostics.restart()
    else:
        device.irecv.reboot()


@cli.command("protocol-info")
@async_command
async def restore_protocol_info(
    udid: Annotated[
        Optional[str],
        typer.Option("--udid", "-u", help="Target usbmux UDID; defaults to all connected USB devices."),
    ] = None,
    usbmux_address: Annotated[
        Optional[str],
        typer.Option("--usbmux-address", envvar=USBMUX_ENV_VARS, help=USBMUX_OPTION_HELP),
    ] = None,
    timeout: Annotated[float, typer.Option(help="Timeout, in seconds, for each restored plist request.")] = 1.0,
    include_values: Annotated[
        bool,
        typer.Option(help="Also query common restored values such as HardwareInfo and SavedDebugInfo."),
    ] = False,
    query_key: Annotated[
        Optional[list[str]],
        typer.Option("--query-key", "-q", help="Additional restored QueryValue key to request."),
    ] = None,
    include_identifiers: Annotated[
        bool,
        typer.Option(help="Include raw device identifiers and nonce-like values in the JSON output."),
    ] = False,
    trace: Annotated[
        bool,
        typer.Option(help="Include sanitized request/response trace records."),
    ] = False,
    strict: Annotated[
        bool,
        typer.Option(help="Exit with status 1 unless a restored-mode device is detected."),
    ] = False,
) -> None:
    """Probe the restored protocol over usbmux port 62078."""
    output = await collect_restore_protocol_info(
        udid=udid,
        usbmux_address=usbmux_address,
        timeout=timeout,
        include_values=include_values,
        query_keys=query_key,
        include_identifiers=include_identifiers,
        include_trace=trace,
    )
    print_json(output, colored=False)
    if strict and not any(device.get("mode") == "restored" for device in output["devices"]):
        raise typer.Exit(1)


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
