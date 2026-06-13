import ast
import asyncio
import datetime
import logging
import plistlib
from pathlib import Path
from typing import Annotated, Literal, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import (
    DEVICE_OPTIONS_PANEL_TITLE,
    USBMUX_ENV_VARS,
    USBMUX_OPTION_HELP,
    NoAutoPairServiceProviderDep,
    ServiceProviderDep,
    async_command,
    load_pair_record_file,
    print_json,
    sudo_required,
)
from pymobiledevice3.cli.remote import tunnel_task
from pymobiledevice3.lockdown import SERVICE_PORT, TcpLockdownClient, create_using_usbmux
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.pair_records import (
    create_pairing_records_cache_folder,
    delete_lockdown_pairing_record,
    generate_host_id,
    get_itunes_pairing_record,
    get_local_pairing_record,
    get_lockdown_pairing_record_summary,
    get_usbmux_pairing_record,
    list_lockdown_pairing_record_summaries,
)
from pymobiledevice3.remote.common import TunnelProtocol
from pymobiledevice3.remote.tunnel_service import CoreDeviceTunnelProxy
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.services.heartbeat import HeartbeatService
from pymobiledevice3.utils import run_in_loop

logger = logging.getLogger(__name__)

cli = InjectingTyper(
    name="lockdown",
    help="Pair/Unpair device or access other lockdown services",
    no_args_is_help=True,
)


def _diagnose_error(error: Exception) -> dict:
    return {"ok": False, "error_type": error.__class__.__name__, "error": str(error)}


def _pair_record_diagnostic(source: Optional[str], pair_record: Optional[dict]) -> dict:
    if pair_record is None:
        return {"found": False, "source": None}
    return {
        "found": True,
        "source": source,
        "keys": sorted(pair_record.keys()),
        "has_escrow_bag": "EscrowBag" in pair_record,
        "has_host_private_key": "HostPrivateKey" in pair_record,
        "has_wifi_mac_address": "WiFiMACAddress" in pair_record,
    }


async def _find_pair_record(
    udid: str, pairing_records_cache_folder: Optional[Path] = None, usbmux_address: Optional[str] = None
) -> tuple[Optional[str], Optional[dict]]:
    pair_record = await get_usbmux_pairing_record(identifier=udid, usbmux_address=usbmux_address)
    if pair_record is not None:
        return "usbmux", pair_record

    pair_record = get_itunes_pairing_record(udid)
    if pair_record is not None:
        return "itunes", pair_record

    pairing_records_cache_folder = create_pairing_records_cache_folder(pairing_records_cache_folder)
    pair_record = get_local_pairing_record(udid, pairing_records_cache_folder)
    if pair_record is not None:
        return "local", pair_record

    return None, None


async def diagnose_tcp_lockdown(
    host: str,
    port: int = SERVICE_PORT,
    udid: Optional[str] = None,
    pairing_records_cache_folder: Optional[Path] = None,
    pair_record_file: Optional[Path] = None,
    timeout: float = 5.0,
    usbmux_address: Optional[str] = None,
) -> dict:
    output = {
        "transport": "tcp",
        "host": host,
        "port": port,
        "tcp_connect": None,
        "pair_record": {"found": False, "source": None},
        "query_type": None,
        "device_info": None,
        "pair_validation": None,
    }

    service = None
    client = None
    try:
        service = await asyncio.wait_for(ServiceConnection.create_using_tcp(host, port), timeout=timeout)
        output["tcp_connect"] = {"ok": True}
    except Exception as e:
        output["tcp_connect"] = _diagnose_error(e)
        return output

    try:
        if pair_record_file is not None:
            try:
                pair_record = load_pair_record_file(pair_record_file)
                output["pair_record"] = _pair_record_diagnostic("file", pair_record)
            except Exception as e:
                output["pair_record"] = {"source": "file", **_diagnose_error(e)}
                return output
        elif udid is None:
            output["pair_record"] = {"found": False, "source": None, "required": True, "error": "--udid is required"}
            return output
        else:
            try:
                source, pair_record = await _find_pair_record(
                    udid, pairing_records_cache_folder=pairing_records_cache_folder, usbmux_address=usbmux_address
                )
                output["pair_record"] = _pair_record_diagnostic(source, pair_record)
            except Exception as e:
                output["pair_record"] = _diagnose_error(e)
                return output

        client = TcpLockdownClient(
            service,
            host_id=generate_host_id(),
            hostname=host,
            identifier=udid,
            pair_record=pair_record,
            pairing_records_cache_folder=create_pairing_records_cache_folder(pairing_records_cache_folder),
            port=port,
            keep_alive=False,
        )

        try:
            output["query_type"] = {"ok": True, "type": await client.query_type()}
        except Exception as e:
            output["query_type"] = _diagnose_error(e)
            return output

        try:
            client.all_values = await client.get_value()
            output["device_info"] = {
                "ok": True,
                "device_class": client.all_values.get("DeviceClass"),
                "product_type": client.all_values.get("ProductType"),
                "product_version": client.all_values.get("ProductVersion"),
            }
        except Exception as e:
            output["device_info"] = _diagnose_error(e)

        if pair_record is None:
            output["pair_validation"] = {"ok": False, "skipped": True, "error": "pair record not found"}
            return output

        try:
            output["pair_validation"] = {"ok": await client.validate_pairing()}
        except Exception as e:
            output["pair_validation"] = _diagnose_error(e)
    finally:
        if client is not None:
            await client.close()
        elif service is not None:
            await service.close()

    return output


async def diagnose_usbmux_lockdown(
    udid: Optional[str] = None,
    usbmux_address: Optional[str] = None,
    pairing_records_cache_folder: Optional[Path] = None,
) -> dict:
    output = {
        "transport": "usbmux",
        "udid": udid,
        "pair_record": {"found": False, "source": None},
        "query_type": None,
        "pair_validation": None,
    }

    if udid is not None:
        try:
            source, pair_record = await _find_pair_record(
                udid, pairing_records_cache_folder=pairing_records_cache_folder, usbmux_address=usbmux_address
            )
            output["pair_record"] = _pair_record_diagnostic(source, pair_record)
        except Exception as e:
            output["pair_record"] = _diagnose_error(e)

    client = None
    try:
        client = await create_using_usbmux(
            serial=udid,
            autopair=False,
            usbmux_address=usbmux_address,
            pairing_records_cache_folder=pairing_records_cache_folder,
        )
        output["udid"] = client.identifier
        output["query_type"] = {"ok": True, "type": await client.query_type()}
        output["pair_validation"] = {"ok": client.paired}
        if not output["pair_record"].get("found"):
            output["pair_record"] = _pair_record_diagnostic("client", client.pair_record)
    except Exception as e:
        output["connection"] = _diagnose_error(e)
    finally:
        if client is not None:
            await client.close()

    return output


@cli.command("recovery")
@async_command
async def lockdown_recovery(service_provider: ServiceProviderDep) -> None:
    """enter recovery"""
    print_json(await service_provider.enter_recovery())


@cli.command("service")
def lockdown_service(service_provider: ServiceProviderDep, service_name: str) -> None:
    """send-receive raw service messages with a given service name"""
    service = run_in_loop(service_provider.start_lockdown_service(service_name))
    try:
        service.shell()
    finally:
        run_in_loop(service.close())


@cli.command("developer-service")
def lockdown_developer_service(service_provider: ServiceProviderDep, service_name: str) -> None:
    """send-receive raw service messages with a given developer service name"""
    service = run_in_loop(service_provider.start_lockdown_developer_service(service_name))
    try:
        service.shell()
    finally:
        run_in_loop(service.close())


@cli.command("info")
def lockdown_info(service_provider: ServiceProviderDep) -> None:
    """query all lockdown values"""
    print_json(service_provider.all_values)


@cli.command("get")
@async_command
async def lockdown_get(
    service_provider: ServiceProviderDep, domain: Optional[str] = None, key: Optional[str] = None
) -> None:
    """query lockdown values by their domain and key names"""
    print_json(await service_provider.get_value(domain=domain, key=key))


@cli.command("diagnose")
@async_command
async def lockdown_diagnose(
    host: Annotated[
        Optional[str],
        typer.Option(
            help="Connect to lockdownd over TCP at this host/IP instead of usbmux.",
            rich_help_panel=DEVICE_OPTIONS_PANEL_TITLE,
        ),
    ] = None,
    port: Annotated[
        int,
        typer.Option(
            help="TCP lockdownd port to use with --host.",
            rich_help_panel=DEVICE_OPTIONS_PANEL_TITLE,
        ),
    ] = SERVICE_PORT,
    udid: Annotated[
        Optional[str],
        typer.Option(
            help="Target device UDID. Required with --host unless --pair-record is provided.",
            rich_help_panel=DEVICE_OPTIONS_PANEL_TITLE,
        ),
    ] = None,
    usbmux: Annotated[
        Optional[str],
        typer.Option(
            envvar=USBMUX_ENV_VARS,
            help=USBMUX_OPTION_HELP,
            rich_help_panel=DEVICE_OPTIONS_PANEL_TITLE,
        ),
    ] = None,
    pairing_records_cache_folder: Annotated[
        Optional[Path],
        typer.Option(help="Directory containing pymobiledevice3 lockdown pairing records."),
    ] = None,
    pair_record_file: Annotated[
        Optional[Path],
        typer.Option(
            "--pair-record",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Lockdown pair record plist to use with --host instead of cache lookup.",
        ),
    ] = None,
    timeout: Annotated[float, typer.Option(help="TCP connection timeout in seconds.")] = 5.0,
) -> None:
    """diagnose lockdown connectivity, discovery, and pair validation"""
    if host is None and pair_record_file is not None:
        raise typer.BadParameter("--pair-record requires --host")

    if host is None:
        if port != SERVICE_PORT:
            raise typer.BadParameter("--port requires --host")
        print_json(
            await diagnose_usbmux_lockdown(
                udid=udid, usbmux_address=usbmux, pairing_records_cache_folder=pairing_records_cache_folder
            )
        )
        return

    print_json(
        await diagnose_tcp_lockdown(
            host,
            port=port,
            udid=udid,
            pairing_records_cache_folder=pairing_records_cache_folder,
            pair_record_file=pair_record_file,
            timeout=timeout,
            usbmux_address=usbmux,
        )
    )


@cli.command("set")
@async_command
async def lockdown_set(
    service_provider: ServiceProviderDep,
    value: str,
    domain: Optional[str] = None,
    key: Optional[str] = None,
) -> None:
    """set a lockdown value using python's ast.literal_eval()"""
    print_json(await service_provider.set_value(value=ast.literal_eval(value), domain=domain, key=key))


@cli.command("remove")
@async_command
async def lockdown_remove(service_provider: ServiceProviderDep, domain: str, key: str) -> None:
    """remove a domain/key pair"""
    print_json(await service_provider.remove_value(domain=domain, key=key))


@cli.command("unpair")
@async_command
async def lockdown_unpair(service_provider: NoAutoPairServiceProviderDep, host_id: Optional[str] = None) -> None:
    """unpair from connected device"""
    await service_provider.unpair(host_id=host_id)


@cli.command("pair")
@async_command
async def lockdown_pair(service_provider: NoAutoPairServiceProviderDep) -> None:
    """pair device"""
    await service_provider.pair()


@cli.command("pair-records")
def lockdown_pair_records(
    pairing_records_cache_folder: Annotated[
        Optional[Path],
        typer.Option(help="Directory containing pymobiledevice3 lockdown pairing records."),
    ] = None,
    include_itunes: Annotated[
        bool,
        typer.Option("--include-itunes/--no-include-itunes", help="Include iTunes/libimobiledevice pair records."),
    ] = True,
    include_secrets: Annotated[
        bool,
        typer.Option(help="Include base64-encoded secret material in the JSON output."),
    ] = False,
    include_path: Annotated[
        bool,
        typer.Option("--include-path/--no-include-path", help="Include local filesystem paths in output."),
    ] = True,
) -> None:
    """list local lockdown pair records"""
    print_json(
        list_lockdown_pairing_record_summaries(
            pairing_records_cache_folder=pairing_records_cache_folder,
            include_itunes=include_itunes,
            include_secrets=include_secrets,
            include_path=include_path,
        )
    )


@cli.command("pair-record")
def lockdown_pair_record(
    udid: str,
    pairing_records_cache_folder: Annotated[
        Optional[Path],
        typer.Option(help="Directory containing pymobiledevice3 lockdown pairing records."),
    ] = None,
    include_itunes: Annotated[
        bool,
        typer.Option("--include-itunes/--no-include-itunes", help="Include iTunes/libimobiledevice pair records."),
    ] = True,
    include_secrets: Annotated[
        bool,
        typer.Option(help="Include base64-encoded secret material in the JSON output."),
    ] = False,
    include_path: Annotated[
        bool,
        typer.Option("--include-path/--no-include-path", help="Include local filesystem paths in output."),
    ] = True,
) -> None:
    """show local lockdown pair records for a device"""
    print_json(
        get_lockdown_pairing_record_summary(
            udid,
            pairing_records_cache_folder=pairing_records_cache_folder,
            include_itunes=include_itunes,
            include_secrets=include_secrets,
            include_path=include_path,
        )
    )


@cli.command("delete-pair-record")
def lockdown_delete_pair_record(
    udid: str,
    pairing_records_cache_folder: Annotated[
        Optional[Path],
        typer.Option(help="Directory containing pymobiledevice3 lockdown pairing records."),
    ] = None,
    include_itunes: Annotated[
        bool,
        typer.Option(
            "--include-itunes/--no-include-itunes",
            help="Also delete matching iTunes/libimobiledevice pair records.",
        ),
    ] = False,
    missing_ok: Annotated[
        bool,
        typer.Option(help="Do not fail if no matching record exists."),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option(help="Report matching records without deleting them."),
    ] = False,
    include_path: Annotated[
        bool,
        typer.Option("--include-path/--no-include-path", help="Include local filesystem paths in output."),
    ] = True,
) -> None:
    """delete local lockdown pair records for a device"""
    try:
        print_json(
            delete_lockdown_pairing_record(
                udid,
                pairing_records_cache_folder=pairing_records_cache_folder,
                include_itunes=include_itunes,
                missing_ok=missing_ok,
                dry_run=dry_run,
                include_path=include_path,
            )
        )
    except FileNotFoundError as e:
        raise typer.BadParameter(f"pair record not found: {udid}") from e


@cli.command("pair-supervised")
@async_command
async def lockdown_pair_supervised(
    service_provider: NoAutoPairServiceProviderDep,
    keybag: Annotated[
        Path,
        typer.Argument(file_okay=True, dir_okay=False, exists=True),
    ],
) -> None:
    """pair supervised device"""
    await service_provider.pair_supervised(keybag)


@cli.command("save-pair-record")
def lockdown_save_pair_record(service_provider: NoAutoPairServiceProviderDep, output: Path) -> None:
    """save pair record to specified location"""
    if service_provider.pair_record is None:
        logger.error("no pairing record was found")
        return
    output.write_bytes(plistlib.dumps(service_provider.pair_record))


@cli.command("date")
@async_command
async def lockdown_date(service_provider: ServiceProviderDep) -> None:
    """get device date"""
    timestamp = await service_provider.get_value(key="TimeIntervalSince1970")
    print(datetime.datetime.fromtimestamp(timestamp))


@cli.command("heartbeat")
@async_command
async def lockdown_heartbeat(service_provider: ServiceProviderDep) -> None:
    """start heartbeat service"""
    await HeartbeatService(service_provider).start()


@cli.command("language")
@async_command
async def lockdown_language(
    service_provider: ServiceProviderDep, language: Annotated[Optional[str], typer.Argument()] = None
) -> None:
    """Get/Set current language settings"""
    if language is not None:
        await service_provider.set_language(language)
    print_json(await service_provider.get_language())


@cli.command("locale")
@async_command
async def lockdown_locale(
    service_provider: ServiceProviderDep, locale: Annotated[Optional[str], typer.Argument()] = None
) -> None:
    """Get/Set current language settings"""
    if locale is not None:
        await service_provider.set_locale(locale)
    print_json(await service_provider.get_locale())


@cli.command("device-name")
@async_command
async def lockdown_device_name(service_provider: ServiceProviderDep, new_name: Optional[str] = None) -> None:
    """get/set current device name"""
    if new_name:
        await service_provider.set_value(new_name, key="DeviceName")
    else:
        print(f"{await service_provider.get_value(key='DeviceName')}")


@cli.command("wifi-connections")
@async_command
async def lockdown_wifi_connections(
    service_provider: ServiceProviderDep, state: Optional[Literal["on", "off"]] = None
) -> None:
    """get/set wifi connections state"""
    if not state:
        # show current state
        print_json({"EnableWifiConnections": await service_provider.get_enable_wifi_connections()})
    else:
        # enable/disable
        await service_provider.set_enable_wifi_connections(state == "on")


async def async_cli_start_tunnel(service_provider: LockdownServiceProvider, script_mode: bool) -> None:
    await tunnel_task(
        await CoreDeviceTunnelProxy.create(service_provider),
        script_mode=script_mode,
        secrets=None,
        protocol=TunnelProtocol.TCP,
    )


@cli.command("start-tunnel")
@sudo_required
@async_command
async def cli_start_tunnel(
    service_provider: ServiceProviderDep,
    script_mode: Annotated[
        bool,
        typer.Option(help="Show only HOST and port number to allow easy parsing from external shell scripts"),
    ] = False,
) -> None:
    """start tunnel"""
    await async_cli_start_tunnel(service_provider, script_mode)


@cli.command("assistive-touch")
@async_command
async def lockdown_assistive_touch(
    service_provider: ServiceProviderDep, state: Optional[Literal["on", "off"]] = None
) -> None:
    """get/set assistive touch icon state (visibility)"""
    if not state:
        print_json({"AssistiveTouchEnabledByiTunes": await service_provider.get_assistive_touch()})
    else:
        # enable/disable
        await service_provider.set_assistive_touch(state == "on")
