import datetime
import hashlib
import plistlib
from pathlib import Path
from typing import Any, Optional

MANIFEST_SCHEMA_VERSION = 1
DIRECTORY_DIGEST_ALGORITHM = "sha256-relative-path-manifest-v1"
BACKUP_MARKER_FILES = {"Info.plist", "Manifest.plist", "Status.plist"}
PACKET_CAPTURE_SUFFIXES = {".pcap", ".pcapng"}
ARCHIVE_SUFFIX_CHAINS = {".tar", ".tar.bz2", ".tar.gz", ".tar.xz", ".tgz", ".zip"}
FILE_RELAY_ARCHIVE_SUFFIX_CHAINS = {".cpio", ".cpio.gz"}
FILE_RELAY_ARCHIVE_NAME_HINTS = {
    "accounts",
    "addressbook",
    "applesupport",
    "baseband",
    "corelocation",
    "crashreporter",
    "hfsmeta",
    "keyboard",
    "lockdown",
    "mobileasset",
    "mobilebackup",
    "mobilecal",
    "mobiledelete",
    "mobileinstallation",
    "mobilenotes",
    "nanddebuginfo",
    "network",
    "photos",
    "systemconfiguration",
    "tmp",
    "ubiquity",
    "userdatabases",
    "varfs",
    "voicemail",
    "vpn",
    "wifi",
    "wirelessautomation",
}
DIAGNOSTICS_ARCHIVE_NAME_HINTS = (
    "diagnostic",
    "diagnostics",
    "os_trace",
    "os-trace",
)
DEVICE_CONTEXT_KEYS = {
    "BuildVersion": "build_version",
    "DeviceClass": "device_class",
    "ProductType": "product_type",
    "ProductVersion": "product_version",
}
DEVICE_IDENTIFIER_KEYS = {
    "DeviceName": "device_name",
    "SerialNumber": "serial_number",
    "UniqueChipID": "unique_chip_id",
    "UniqueDeviceID": "unique_device_id",
}


def build_acquisition_manifest(
    artifacts: list[Path],
    *,
    device: Optional[dict] = None,
    hash_files: bool = True,
) -> dict:
    manifest = {
        "artifacts": [summarize_artifact(artifact, hash_files=hash_files) for artifact in artifacts],
        "generated_at": _utc_now(),
        "schema_version": MANIFEST_SCHEMA_VERSION,
    }
    if device is not None:
        manifest["device"] = device
    return manifest


def build_device_context(values: dict[str, Any], *, include_identifiers: bool = False) -> dict:
    context = _copy_selected_keys(values, DEVICE_CONTEXT_KEYS)
    if include_identifiers:
        context.update(_copy_selected_keys(values, DEVICE_IDENTIFIER_KEYS))
    return context


def summarize_artifact(path: Path, *, hash_files: bool = True) -> dict:
    resolved_path = path.expanduser()
    if resolved_path.is_dir():
        return _summarize_directory(resolved_path, hash_files=hash_files)
    return _summarize_file(resolved_path, hash_file=hash_files)


def classify_artifact(path: Path) -> str:
    name = path.name.lower()
    if path.is_dir():
        if name.endswith(".logarchive"):
            return "logarchive"
        if _is_itunes_backup(path):
            return "itunes_backup"
        if any(child.is_dir() and _is_itunes_backup(child) for child in path.iterdir()):
            return "itunes_backup_root"
        return "directory"

    suffixes = [suffix.lower() for suffix in path.suffixes]
    suffix_chain = "".join(suffixes)
    if any(suffix in {".crash", ".ips", ".panic"} for suffix in suffixes):
        return "crash_report"
    if path.suffix.lower() in PACKET_CAPTURE_SUFFIXES:
        return "packet_capture"
    if name.endswith(".logarchive"):
        return "logarchive"
    if _is_mobilebackup_domains_plist(path):
        return "mobilebackup_domains_plist"
    if "sysdiagnose" in name and suffixes:
        return "sysdiagnose_archive"
    if _is_file_relay_archive(name, suffix_chain):
        return "file_relay_archive"
    if _is_diagnostics_archive(name, suffix_chain):
        return "diagnostics_archive"
    if path.suffix.lower() == ".plist":
        return "plist"
    return "file"


def _is_file_relay_archive(name: str, suffix_chain: str) -> bool:
    if suffix_chain not in FILE_RELAY_ARCHIVE_SUFFIX_CHAINS:
        return False
    if "file_relay" in name or "file-relay" in name:
        return True
    archive_name = name.removesuffix(suffix_chain)
    return _normalize_artifact_name(archive_name) in FILE_RELAY_ARCHIVE_NAME_HINTS


def _is_diagnostics_archive(name: str, suffix_chain: str) -> bool:
    return suffix_chain in ARCHIVE_SUFFIX_CHAINS and any(hint in name for hint in DIAGNOSTICS_ARCHIVE_NAME_HINTS)


def _is_mobilebackup_domains_plist(path: Path) -> bool:
    if path.name.lower() != "domains.plist":
        return False
    try:
        data = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException, TypeError, ValueError):
        return False
    return isinstance(data, dict) and isinstance(data.get("SystemDomains"), dict) and "Version" in data


def _normalize_artifact_name(name: str) -> str:
    return name.replace("-", "").replace("_", "")


def _summarize_file(path: Path, *, hash_file: bool) -> dict:
    stat = path.stat()
    summary = {
        "kind": classify_artifact(path),
        "modified_at": _timestamp(stat.st_mtime),
        "name": path.name,
        "path": str(path),
        "size": stat.st_size,
        "type": "file",
    }
    if hash_file:
        summary["sha256"] = _hash_file(path)
    return summary


def _summarize_directory(path: Path, *, hash_files: bool) -> dict:
    stat = path.stat()
    file_count = 0
    directory_count = 0
    total_size = 0
    digest = hashlib.sha256()

    for child in _iter_directory(path):
        relative_path = child.relative_to(path).as_posix()
        if child.is_dir():
            directory_count += 1
            if hash_files:
                digest.update(b"D\0")
                digest.update(relative_path.encode())
                digest.update(b"\0")
            continue

        file_count += 1
        child_stat = child.stat()
        total_size += child_stat.st_size
        if not hash_files:
            continue
        file_hash = _hash_file(child)
        digest.update(b"F\0")
        digest.update(relative_path.encode())
        digest.update(b"\0")
        digest.update(str(child_stat.st_size).encode())
        digest.update(b"\0")
        digest.update(file_hash.encode())
        digest.update(b"\0")

    summary = {
        "directory_count": directory_count,
        "file_count": file_count,
        "kind": classify_artifact(path),
        "modified_at": _timestamp(stat.st_mtime),
        "name": path.name,
        "path": str(path),
        "total_size": total_size,
        "type": "directory",
    }
    if hash_files:
        summary["digest_algorithm"] = DIRECTORY_DIGEST_ALGORITHM
        summary["sha256"] = digest.hexdigest()
    return summary


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as infile:
        while chunk := infile.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _iter_directory(path: Path):
    yield from sorted(path.rglob("*"), key=lambda child: child.relative_to(path).as_posix())


def _is_itunes_backup(path: Path) -> bool:
    return all((path / marker).is_file() for marker in BACKUP_MARKER_FILES)


def _copy_selected_keys(values: dict[str, Any], keys: dict[str, str]) -> dict:
    return {output_key: values[source_key] for source_key, output_key in keys.items() if source_key in values}


def _timestamp(timestamp: float) -> str:
    return datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).isoformat()


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()
