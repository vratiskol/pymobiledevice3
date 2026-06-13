import base64
import hashlib
import logging
import platform
import plistlib
import uuid
from collections.abc import Generator
from contextlib import suppress
from pathlib import Path
from typing import Optional

from pymobiledevice3 import usbmux
from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import MuxException, NotPairedError
from pymobiledevice3.osu.os_utils import get_os_utils
from pymobiledevice3.usbmux import PlistMuxConnection

logger = logging.getLogger(__name__)
OSUTILS = get_os_utils()
PAIRING_RECORD_EXT = "plist"


def generate_host_id(hostname: Optional[str] = None) -> str:
    """
    Generate a unique host ID based on the hostname.

    :param hostname: The hostname to use for generating the host ID.
                     If None, the current hostname is used.
    :type hostname: str, optional
    :return: The generated host ID.
    :rtype: str
    """
    hostname = platform.node() if hostname is None else hostname
    host_id = uuid.uuid3(uuid.NAMESPACE_DNS, hostname)
    return str(host_id).upper()


async def get_usbmux_pairing_record(identifier: str, usbmux_address: Optional[str] = None):
    """
    Retrieve the pairing record from usbmuxd.

    :param identifier: The identifier of the device.
    :type identifier: str
    :param usbmux_address: The address of the usbmuxd server.
    :type usbmux_address: Optional[str], optional
    :return: The pairing record if found, otherwise None.
    :rtype: dict or None
    """
    with suppress(NotPairedError, MuxException):
        mux = await usbmux.create_mux(usbmux_address=usbmux_address)
        try:
            if isinstance(mux, PlistMuxConnection):
                pair_record = await mux.get_pair_record(identifier)
                if pair_record is not None:
                    return pair_record
        finally:
            await mux.close()
    return None


def get_itunes_pairing_record(identifier: str) -> Optional[dict]:
    """
    Retrieve the pairing record from iTunes.

    :param identifier: The identifier of the device.
    :type identifier: str
    :return: The pairing record if found, otherwise None.
    :rtype: Optional[dict]
    """
    filename = OSUTILS.pair_record_path / f"{identifier}.plist"
    try:
        with open(filename, "rb") as f:
            pair_record = plistlib.load(f)
    except (PermissionError, FileNotFoundError, plistlib.InvalidFileException):
        return None
    return pair_record


def get_local_pairing_record(identifier: str, pairing_records_cache_folder: Path) -> Optional[dict]:
    """
    Retrieve the pairing record from local storage.

    :param identifier: The identifier of the device.
    :type identifier: str
    :param pairing_records_cache_folder: The path to the local pairing records cache folder.
    :type pairing_records_cache_folder: Path
    :return: The pairing record if found, otherwise None.
    :rtype: Optional[dict]
    """
    logger.debug("Looking for pymobiledevice3 pairing record")
    path = pairing_records_cache_folder / f"{identifier}.{PAIRING_RECORD_EXT}"
    if not path.exists():
        logger.debug(f"No pymobiledevice3 pairing record found for device {identifier}")
        return None
    return plistlib.loads(path.read_bytes())


def get_local_pairing_record_path(identifier: str, pairing_records_cache_folder: Optional[Path] = None) -> Path:
    pairing_records_cache_folder = (
        get_home_folder() if pairing_records_cache_folder is None else pairing_records_cache_folder
    )
    return pairing_records_cache_folder / f"{identifier}.{PAIRING_RECORD_EXT}"


def iter_local_pair_records(pairing_records_cache_folder: Optional[Path] = None) -> Generator[Path, None, None]:
    pairing_records_cache_folder = (
        get_home_folder() if pairing_records_cache_folder is None else pairing_records_cache_folder
    )
    with suppress(OSError):
        for file in pairing_records_cache_folder.glob(f"*.{PAIRING_RECORD_EXT}"):
            if not file.name.startswith("remote_"):
                yield file


def get_itunes_pairing_record_path(identifier: str) -> Path:
    return OSUTILS.pair_record_path / f"{identifier}.{PAIRING_RECORD_EXT}"


def iter_itunes_pair_records() -> Generator[Path, None, None]:
    with suppress(OSError):
        yield from OSUTILS.pair_record_path.glob(f"*.{PAIRING_RECORD_EXT}")


def _lockdown_pairing_record_identifier(path: Path) -> str:
    return path.stem


def _summarize_pairing_record_value(value, include_value: bool = False) -> dict:
    if isinstance(value, bytes):
        summary = {
            "type": "bytes",
            "length": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        }
        if include_value:
            summary["base64"] = base64.b64encode(value).decode()
        return summary

    summary = {"type": type(value).__name__}
    if include_value:
        summary["value"] = value
    return summary


def describe_lockdown_pairing_record(
    path: Path,
    source: str,
    include_secrets: bool = False,
    include_path: bool = True,
) -> dict:
    identifier = _lockdown_pairing_record_identifier(path)
    result = {
        "identifier": identifier,
        "source": source,
        "exists": path.exists(),
    }
    if include_path:
        result["path"] = str(path)
    if not path.exists():
        result["valid"] = False
        result["error"] = "not found"
        return result

    try:
        record = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError) as e:
        result["valid"] = False
        result["error"] = str(e)
        return result

    if not isinstance(record, dict):
        result["valid"] = False
        result["error"] = "pair record is not a plist dictionary"
        return result

    result.update({
        "valid": True,
        "keys": sorted(record.keys()),
        "values": {key: _summarize_pairing_record_value(record[key]) for key in sorted(record.keys())},
        "has_escrow_bag": "EscrowBag" in record,
        "has_host_id": "HostID" in record,
        "has_host_private_key": "HostPrivateKey" in record,
        "has_root_private_key": "RootPrivateKey" in record,
        "has_system_buid": "SystemBUID" in record,
        "has_wifi_mac_address": "WiFiMACAddress" in record,
    })
    if include_secrets:
        result["record"] = {
            key: _summarize_pairing_record_value(value, include_value=True) for key, value in record.items()
        }
    return result


def list_lockdown_pairing_record_summaries(
    pairing_records_cache_folder: Optional[Path] = None,
    include_itunes: bool = True,
    include_secrets: bool = False,
    include_path: bool = True,
) -> list[dict]:
    summaries = [
        describe_lockdown_pairing_record(path, "local", include_secrets=include_secrets, include_path=include_path)
        for path in iter_local_pair_records(pairing_records_cache_folder)
    ]
    if include_itunes:
        summaries.extend(
            describe_lockdown_pairing_record(path, "itunes", include_secrets=include_secrets, include_path=include_path)
            for path in iter_itunes_pair_records()
        )
    return sorted(summaries, key=lambda summary: (summary["identifier"], summary["source"]))


def get_lockdown_pairing_record_summary(
    identifier: str,
    pairing_records_cache_folder: Optional[Path] = None,
    include_itunes: bool = True,
    include_secrets: bool = False,
    include_path: bool = True,
) -> dict:
    records = []
    local_path = get_local_pairing_record_path(identifier, pairing_records_cache_folder)
    if local_path.exists():
        records.append(
            describe_lockdown_pairing_record(
                local_path, "local", include_secrets=include_secrets, include_path=include_path
            )
        )

    if include_itunes:
        itunes_path = get_itunes_pairing_record_path(identifier)
        if itunes_path.exists():
            records.append(
                describe_lockdown_pairing_record(
                    itunes_path, "itunes", include_secrets=include_secrets, include_path=include_path
                )
            )

    return {
        "identifier": identifier,
        "exists": bool(records),
        "records": records,
    }


def delete_lockdown_pairing_record(
    identifier: str,
    pairing_records_cache_folder: Optional[Path] = None,
    include_itunes: bool = False,
    missing_ok: bool = False,
    dry_run: bool = False,
    include_path: bool = True,
) -> dict:
    targets = [("local", get_local_pairing_record_path(identifier, pairing_records_cache_folder))]
    if include_itunes:
        targets.append(("itunes", get_itunes_pairing_record_path(identifier)))

    records = []
    for source, path in targets:
        entry = {
            "identifier": identifier,
            "source": source,
            "exists": path.exists(),
            "deleted": False,
            "dry_run": dry_run,
        }
        if include_path:
            entry["path"] = str(path)
        if entry["exists"] and not dry_run:
            path.unlink()
            entry["deleted"] = True
            entry["exists"] = False
        records.append(entry)

    if not any(record["deleted"] or (record["exists"] and dry_run) for record in records) and not missing_ok:
        raise FileNotFoundError(get_local_pairing_record_path(identifier, pairing_records_cache_folder))

    return {
        "identifier": identifier,
        "exists": any(record["exists"] for record in records),
        "deleted": any(record["deleted"] for record in records),
        "dry_run": dry_run,
        "records": records,
    }


async def get_preferred_pair_record(
    identifier: str, pairing_records_cache_folder: Path, usbmux_address: Optional[str] = None
) -> dict:
    """
    Look for an existing pair record for the connected device in the following order:
    - usbmuxd
    - iTunes
    - local storage

    :param identifier: The identifier of the device.
    :type identifier: str
    :param pairing_records_cache_folder: The path to the local pairing records cache folder.
    :type pairing_records_cache_folder: Path
    :param usbmux_address: The address of the usbmuxd server.
    :type usbmux_address: Optional[str], optional
    :return: The preferred pairing record.
    :rtype: dict
    """
    # usbmuxd
    pair_record = await get_usbmux_pairing_record(identifier=identifier, usbmux_address=usbmux_address)
    if pair_record is not None:
        return pair_record

    # iTunes
    pair_record = get_itunes_pairing_record(identifier)
    if pair_record is not None:
        return pair_record

    # local storage
    return get_local_pairing_record(identifier, pairing_records_cache_folder)


def create_pairing_records_cache_folder(pairing_records_cache_folder: Optional[Path] = None) -> Path:
    """
    Create the pairing records cache folder if it does not exist.

    :param pairing_records_cache_folder: The path to the local pairing records cache folder.
                                         If None, the home folder is used.
    :type pairing_records_cache_folder: Path, optional
    :return: The path to the pairing records cache folder.
    :rtype: Path
    """
    if pairing_records_cache_folder is None:
        pairing_records_cache_folder = get_home_folder()
    else:
        pairing_records_cache_folder.mkdir(parents=True, exist_ok=True)
    OSUTILS.chown_to_non_sudo_if_needed(pairing_records_cache_folder)
    return pairing_records_cache_folder


def get_remote_pairing_record_filename(identifier: str) -> str:
    """
    Generate the filename for the remote pairing record.

    :param identifier: The identifier of the device.
    :type identifier: str
    :return: The filename for the remote pairing record.
    :rtype: str
    """
    return f"remote_{identifier}"


def iter_remote_pair_records() -> Generator[Path, None, None]:
    """
    Iterate over the remote pairing records in the home folder.

    :return: A generator yielding paths to the remote pairing records.
    :rtype: Generator[Path, None, None]
    """
    return get_home_folder().glob("remote_*")


def iter_remote_paired_identifiers() -> Generator[str, None, None]:
    """
    Iterate over the identifiers of the remote paired devices.

    :return: A generator yielding the identifiers of the remote paired devices.
    :rtype: Generator[str, None, None]
    """
    for file in iter_remote_pair_records():
        yield file.parts[-1].split("remote_", 1)[1].split(".", 1)[0]
