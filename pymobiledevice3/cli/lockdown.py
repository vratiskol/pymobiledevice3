import ast
import datetime
import logging
import plistlib
from pathlib import Path
from typing import Annotated, Any, Literal, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import (
    NoAutoPairServiceProviderDep,
    ServiceProviderDep,
    async_command,
    print_json,
    sudo_required,
)
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.heartbeat import HeartbeatService
from pymobiledevice3.utils import run_in_loop

logger = logging.getLogger(__name__)

CELLULAR_LOCKDOWN_KEYS = (
    "TelephonyCapability",
    "HasBaseband",
    "DataPlanCapability",
    "DualSIMActivationPolicyCapable",
    "EUICCChipID",
    "SIMCapability",
    "SIMPhonebookCapability",
    "SIMStatus",
    "SIMStatus2",
    "SIMTrayStatus",
    "SIMTrayStatus2",
    "BasebandAPTimeSync",
    "BasebandBoardSnum",
    "BasebandCertId",
    "BasebandChipId",
    "BasebandChipset",
    "BasebandClass",
    "BasebandFirmwareManifestData",
    "BasebandFirmwareUpdateInfo",
    "BasebandFirmwareVersion",
    "BasebandKeyHashInformation",
    "BasebandPostponementStatus",
    "BasebandPostponementStatusBlob",
    "BasebandRegionSKU",
    "BasebandRegionSKURadioTechnology",
    "BasebandSecurityInfoBlob",
    "BasebandSerialNumber",
    "BasebandSkeyId",
    "BasebandStatus",
    "BasebandUniqueId",
    "InternationalMobileEquipmentIdentity",
    "InternationalMobileEquipmentIdentity2",
    "InternationalMobileSubscriberIdentity",
    "IntegratedCircuitCardIdentity",
    "IntegratedCircuitCardIdentifier",
    "IntegratedCircuitCardIdentifier2",
    "MobileEquipmentIdentifier",
    "PhoneNumber",
)

CELLULAR_FIRMWARE_PREFLIGHT_KEYS = (
    "ChipID",
    "CertID",
    "ChipSerialNo",
    "Nonce",
    "EUICCChipID",
    "EUICCCSN",
    "EUICCCertIdentifier",
    "EUICCGoldNonce",
    "EUICCMainNonce",
)

CELLULAR_SENSITIVE_KEYS = {
    "basebandboardsnum",
    "basebandfirmwaremanifestdata",
    "basebandkeyhashinformation",
    "basebandpostponementstatusblob",
    "basebandserialnumber",
    "basebandsecurityinfoblob",
    "basebanduniqueid",
    "chipserialno",
    "euicccertidentifier",
    "euicccsn",
    "euiccgoldnonce",
    "euiccmainnonce",
    "integratedcircuitcardidentity",
    "integratedcircuitcardidentifier",
    "integratedcircuitcardidentifier2",
    "internationalmobileequipmentidentity",
    "internationalmobileequipmentidentity2",
    "internationalmobilesubscriberidentity",
    "mobileequipmentidentifier",
    "nonce",
    "phonenumber",
}

CELLULAR_RESTORE_TSS_MAPPING = {
    "EUICCChipID": "eUICC,ChipID",
    "EUICCCSN": "eUICC,EID",
    "EUICCCertIdentifier": "eUICC,RootKeyIdentifier",
    "EUICCGoldNonce": "EUICCGoldNonce",
    "EUICCMainNonce": "EUICCMainNonce",
}

cli = InjectingTyper(
    name="lockdown",
    help="Pair/Unpair device or access other lockdown services",
    no_args_is_help=True,
)


def _normalized_cellular_key(key: str) -> str:
    return "".join(character for character in key.lower() if character.isalnum())


def _is_sensitive_cellular_key(key: str) -> bool:
    return _normalized_cellular_key(key) in CELLULAR_SENSITIVE_KEYS


def _redact_cellular_value(key: str, value: Any, include_sensitive: bool) -> Any:
    if include_sensitive or not _is_sensitive_cellular_key(key):
        return value
    return "<redacted>"


def _collect_present_cellular_values(source: dict[str, Any], keys: tuple[str, ...], include_sensitive: bool) -> dict:
    return {
        key: _redact_cellular_value(key, source[key], include_sensitive)
        for key in keys
        if source.get(key) is not None
    }


def _build_cellular_restore_tss_parameters(firmware_preflight_info: dict[str, Any], include_sensitive: bool) -> dict:
    parameters = {
        tss_key: _redact_cellular_value(preflight_key, firmware_preflight_info[preflight_key], include_sensitive)
        for preflight_key, tss_key in CELLULAR_RESTORE_TSS_MAPPING.items()
        if firmware_preflight_info.get(preflight_key) is not None
    }
    return {
        "available": bool(parameters),
        "parameters": {"@eUICC,Ticket": True, **parameters} if parameters else {},
        "source": "FirmwarePreflightInfo",
    }


def build_cellular_info(service_provider: LockdownServiceProvider, include_sensitive: bool = False) -> dict:
    all_values = getattr(service_provider, "all_values", {}) or {}
    firmware_preflight_info = all_values.get("FirmwarePreflightInfo") or {}
    preflight_info = all_values.get("PreflightInfo") or {}
    if not isinstance(firmware_preflight_info, dict):
        firmware_preflight_info = {}
    if not isinstance(preflight_info, dict):
        preflight_info = {}
    lockdown_values = _collect_present_cellular_values(all_values, CELLULAR_LOCKDOWN_KEYS, include_sensitive)
    firmware_preflight_values = _collect_present_cellular_values(
        firmware_preflight_info, CELLULAR_FIRMWARE_PREFLIGHT_KEYS, include_sensitive
    )

    return {
        "checked": True,
        "redacted": not include_sensitive,
        "sources": {
            "lockdown": True,
            "preflight_info": bool(preflight_info),
            "firmware_preflight_info": bool(firmware_preflight_info),
        },
        "summary": {
            "telephony_capability": all_values.get("TelephonyCapability"),
            "has_baseband": all_values.get("HasBaseband"),
            "data_plan_capability": all_values.get("DataPlanCapability"),
            "dual_sim_activation_policy_capable": all_values.get("DualSIMActivationPolicyCapable"),
            "sim_status": all_values.get("SIMStatus"),
            "sim_status2": all_values.get("SIMStatus2"),
            "euicc_present": all_values.get("EUICCChipID") is not None
            or firmware_preflight_info.get("EUICCChipID") is not None,
        },
        "lockdown": lockdown_values,
        "firmware_preflight_info": firmware_preflight_values,
        "restore_tss_parameters": _build_cellular_restore_tss_parameters(firmware_preflight_info, include_sensitive),
    }


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


@cli.command("cellular-info")
def lockdown_cellular_info(
    service_provider: ServiceProviderDep,
    include_sensitive: Annotated[
        bool,
        typer.Option(
            "--include-sensitive",
            help="Include raw IMEI, IMSI, ICCID, EID, phone number, serial, and nonce values.",
        ),
    ] = False,
) -> None:
    """query cellular, SIM, baseband, and eUICC restore-preflight values"""
    print_json(build_cellular_info(service_provider, include_sensitive=include_sensitive))


@cli.command("get")
@async_command
async def lockdown_get(
    service_provider: ServiceProviderDep, domain: Optional[str] = None, key: Optional[str] = None
) -> None:
    """query lockdown values by their domain and key names"""
    print_json(await service_provider.get_value(domain=domain, key=key))


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
    from pymobiledevice3.cli.remote import tunnel_task
    from pymobiledevice3.remote.common import TunnelProtocol
    from pymobiledevice3.remote.tunnel_service import CoreDeviceTunnelProxy

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
