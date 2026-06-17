import plistlib
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Optional

RESTOREOS_LAUNCHD_DIR = Path("System/Library/LaunchDaemons")
FDR_SEALING_MAP = Path("System/Library/FDR/FDRSealingMap.plist")
FDR_REPAIR_CONFIG = Path("System/Library/FDR/FDRSealingMapRepairConfiguration.plist")
UPDATERS_DIR = Path("usr/lib/updaters")
STANDALONE_FIRMWARE_DIR = Path("usr/standalone/firmware")

RESTOREOS_SERVICE_MARKERS = {
    "apple_restore_utils": (
        "com.apple.AppleRestoreUtils",
        "com.apple.AppleRestoreUtils.task.async",
        "com.apple.AppleRestoreUtils.task.serial.update",
        "com.apple.ARUService",
        "com.apple.ARUService.async",
        "com.apple.ARUService.sealingMetadataUpdate",
    ),
    "fdr_wkms": (
        "com.apple.libFDR",
        "com.apple.libFDRDecode",
        "com.apple.restored.WKMS",
        "com.apple.restored.WKMS.BAACertificate.request",
        "com.apple.wkms.url",
        "com.apple.wkms.auth-data",
    ),
    "nfc_secure_element": (
        "com.apple.libnfrestore",
        "com.apple.nfrestore",
        "com.apple.stockholm",
        "com.apple.stockholm.NCILog",
    ),
    "baseband_euicc": (
        "com.apple.restored.basebandupdaters",
        "com.apple.EmbeddedSoftwareRestore.Baseband.ChipId",
        "com.apple.EmbeddedSoftwareRestore.Baseband.SBLVersion",
        "com.apple.EmbeddedSoftwareRestore.Baseband.RestoreSBLVersion",
        "com.apple.EmbeddedSoftwareRestore.eUICC.bootloaderVersionsSupported",
        "com.apple.EmbeddedSoftwareRestore.eUICC.firmwareMac",
    ),
    "component_restore": (
        "com.apple.restored.roseupdater",
        "com.apple.restored.mantaupdater",
        "com.apple.restored.veridian",
        "com.apple.Manta.MantaRestoreUtils",
    ),
    "restored_internals": (
        "com.apple.mobile.restored",
        "com.apple.restored.connection.fd",
        "com.apple.restored.large-file-readback",
        "com.apple.restored.cliupdaters",
        "com.apple.restored.log.queue",
    ),
}


def _relative_to_root(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _load_plist(path: Path) -> Optional[Any]:
    if not path.is_file():
        return None
    with path.open("rb") as f:
        return plistlib.load(f)


def _stringify_scalar(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _safe_info_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _safe_info_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_safe_info_value(item) for item in value]
    return _stringify_scalar(value)


def _component_family(name: str) -> str:
    if name.startswith("Wireless1,"):
        return "Wireless1"
    if name.startswith("Ap,Restore") or name.startswith("Restore"):
        return "Restore"
    if "," in name:
        return name.split(",", 1)[0]
    return name


def _manifest_info_value(item: dict[str, Any], key: str, default: Any = None) -> Any:
    info = item.get("Info")
    if isinstance(info, dict):
        return info.get(key, default)
    return default


def _manifest_component_summary(name: str, item: dict[str, Any]) -> dict[str, Any]:
    info = item.get("Info") if isinstance(item.get("Info"), dict) else {}
    return {
        "name": name,
        "family": _component_family(name),
        "path": info.get("Path"),
        "personalize": info.get("Personalize"),
        "is_ftab": info.get("IsFTAB"),
        "is_fud_firmware": info.get("IsFUDFirmware", False),
        "is_firmware_payload": info.get("IsFirmwarePayload", False),
        "is_loaded_by_iboot": info.get("IsLoadedByiBoot"),
        "iboot_ean_firmware": info.get("IsiBootEANFirmware", False),
        "iboot_non_essential_firmware": info.get("IsiBootNonEssentialFirmware", False),
        "restore_request_rule_count": len(info.get("RestoreRequestRules") or []),
    }


def _summarize_build_identity(index: int, identity: dict[str, Any], include_components: bool) -> dict[str, Any]:
    info = identity.get("Info") if isinstance(identity.get("Info"), dict) else {}
    manifest = identity.get("Manifest") if isinstance(identity.get("Manifest"), dict) else {}

    components = [
        _manifest_component_summary(name, item)
        for name, item in sorted(manifest.items())
        if isinstance(item, dict)
    ]
    family_counts = Counter(component["family"] for component in components)
    flag_counts = Counter()
    restore_request_rule_count = 0
    restore_request_rule_component_count = 0

    for item in manifest.values():
        if not isinstance(item, dict):
            continue
        for flag in (
            "IsFUDFirmware",
            "IsFirmwarePayload",
            "IsiBootEANFirmware",
            "IsiBootNonEssentialFirmware",
        ):
            if _manifest_info_value(item, flag):
                flag_counts[flag] += 1
        restore_request_rules = _manifest_info_value(item, "RestoreRequestRules", []) or []
        restore_request_rule_count += len(restore_request_rules)
        if restore_request_rules:
            restore_request_rule_component_count += 1

    output = {
        "index": index,
        "variant": info.get("Variant"),
        "restore_behavior": info.get("RestoreBehavior"),
        "device_class": info.get("DeviceClass"),
        "build_number": info.get("BuildNumber"),
        "fdr_support": info.get("FDRSupport"),
        "restore_attestation_mode": info.get("RestoreAttestationMode"),
        "manifest_item_count": len(manifest),
        "restore_request_rule_count": restore_request_rule_count,
        "restore_request_rule_component_count": restore_request_rule_component_count,
        "component_family_counts": dict(sorted(family_counts.items())),
        "flag_counts": dict(sorted(flag_counts.items())),
        "variant_contents": _safe_info_value(info.get("VariantContents", {})),
    }
    if include_components:
        output["components"] = components
    return output


def build_restore_manifest_info(ipsw_root: Path, *, include_components: bool = False) -> dict[str, Any]:
    ipsw_root = ipsw_root.expanduser().resolve()
    if not ipsw_root.is_dir():
        raise FileNotFoundError(f"{ipsw_root} is not a directory")

    build_manifest = _load_plist(ipsw_root / "BuildManifest.plist")
    restore_plist = _load_plist(ipsw_root / "Restore.plist")

    if build_manifest is None and restore_plist is None:
        return {
            "available": False,
            "ipsw_root": None,
            "build_manifest": None,
            "restore_plist": None,
        }

    build_identities = []
    if isinstance(build_manifest, dict):
        build_identities = [
            _summarize_build_identity(index, identity, include_components)
            for index, identity in enumerate(build_manifest.get("BuildIdentities") or [])
            if isinstance(identity, dict)
        ]

    restore_device_map = []
    if isinstance(restore_plist, dict):
        for entry in restore_plist.get("DeviceMap") or []:
            if not isinstance(entry, dict):
                continue
            restore_device_map.append(
                {
                    "board_config": entry.get("BoardConfig"),
                    "platform": entry.get("Platform"),
                    "cpid": entry.get("CPID"),
                    "bdid": entry.get("BDID"),
                    "sdom": entry.get("SDOM"),
                    "scep": entry.get("SCEP"),
                }
            )

    return {
        "available": True,
        "ipsw_root": None,
        "build_manifest": None
        if not isinstance(build_manifest, dict)
        else {
            "product_version": build_manifest.get("ProductVersion"),
            "product_build_version": build_manifest.get("ProductBuildVersion"),
            "manifest_version": build_manifest.get("ManifestVersion"),
            "supported_product_types": build_manifest.get("SupportedProductTypes", []),
            "build_identity_count": len(build_manifest.get("BuildIdentities") or []),
            "build_identities": build_identities,
        },
        "restore_plist": None
        if not isinstance(restore_plist, dict)
        else {
            "product_version": restore_plist.get("ProductVersion"),
            "product_build_version": restore_plist.get("ProductBuildVersion"),
            "supported_product_types": restore_plist.get("SupportedProductTypes", []),
            "supported_product_type_ids": _safe_info_value(restore_plist.get("SupportedProductTypeIDs", {})),
            "system_restore_image_file_systems": _safe_info_value(
                restore_plist.get("SystemRestoreImageFileSystems", {})
            ),
            "device_map": restore_device_map,
        },
    }


def _iter_candidate_files(root: Path) -> Iterable[Path]:
    for relative in (
        Path("usr/local/bin/restored_update"),
        Path("System/Library/PrivateFrameworks/AppleRestoreUtils.framework/AppleRestoreUtils"),
        Path("System/Library/PrivateFrameworks/AppleRestoreUtils.framework/XPCServices/ARUService.xpc/ARUService"),
        Path("usr/lib/libauthinstall.dylib"),
        Path("usr/lib/libnfrestore.dylib"),
        Path("usr/libexec/restorecameraispd"),
    ):
        path = root / relative
        if path.is_file():
            yield path


def _service_marker_hits(path: Path, chunk_size: int) -> dict[str, list[str]]:
    marker_bytes = [
        (category, marker, marker.encode())
        for category, markers in RESTOREOS_SERVICE_MARKERS.items()
        for marker in markers
    ]
    max_marker_len = max(len(marker) for _, _, marker in marker_bytes)
    hits = {category: [] for category in RESTOREOS_SERVICE_MARKERS}
    previous = b""

    try:
        with path.open("rb") as f:
            while chunk := f.read(chunk_size):
                data = previous + chunk
                for category, marker, encoded_marker in marker_bytes:
                    if marker not in hits[category] and encoded_marker in data:
                        hits[category].append(marker)
                previous = data[-max_marker_len:]
    except OSError:
        return {}

    return {category: markers for category, markers in hits.items() if markers}


def _launch_daemon_info(root: Path) -> list[dict[str, Any]]:
    launch_daemons = []
    launchd_dir = root / RESTOREOS_LAUNCHD_DIR
    if not launchd_dir.is_dir():
        return launch_daemons

    for path in sorted(launchd_dir.glob("*.plist")):
        plist = _load_plist(path)
        if not isinstance(plist, dict):
            continue
        label = plist.get("Label") or path.stem
        joined = " ".join(
            [
                label,
                " ".join(plist.get("ProgramArguments") or []),
                " ".join((plist.get("MachServices") or {}).keys()),
                " ".join((plist.get("Sockets") or {}).keys()),
            ]
        ).lower()
        if not any(term in joined for term in ("restore", "purple", "aru", "fdr", "nf", "baseband", "camera", "wkms")):
            continue
        launch_daemons.append(
            {
                "label": label,
                "path": _relative_to_root(path, root),
                "program_arguments": plist.get("ProgramArguments") or [],
                "mach_services": sorted((plist.get("MachServices") or {}).keys()),
                "sockets": sorted((plist.get("Sockets") or {}).keys()),
                "run_at_load": plist.get("RunAtLoad"),
            }
        )
    return launch_daemons


def _standalone_firmware_counts(root: Path) -> dict[str, Any]:
    base = root / STANDALONE_FIRMWARE_DIR
    if not base.is_dir():
        return {"available": False, "total_files": 0, "by_family": {}, "by_extension": {}}

    by_family = Counter()
    by_extension = Counter()
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(base)
        family = relative.parts[0] if len(relative.parts) > 1 else "<root>"
        by_family[family] += 1
        by_extension[path.suffix or "<none>"] += 1

    return {
        "available": True,
        "total_files": sum(by_family.values()),
        "by_family": dict(sorted(by_family.items())),
        "by_extension": dict(sorted(by_extension.items())),
    }


def _fdr_attribute_counts(entries: list[dict[str, Any]]) -> Counter:
    counts = Counter()
    for entry in entries:
        counts.update(entry.get("Attributes") or [])
        for sub_entry in entry.get("SubCCList") or []:
            if isinstance(sub_entry, dict):
                counts.update(sub_entry.get("Attributes") or [])
    return counts


def _fdr_data_identifier_counts(entries: list[dict[str, Any]]) -> Counter:
    counts = Counter()
    for entry in entries:
        for key in ("DataInstanceIdentifier", "AssemblyIdentifier"):
            if key in entry:
                counts[str(entry[key])] += 1
        for key in ("DataInstanceIdentifierList", "AssemblyIdentifierList"):
            for value in entry.get(key) or []:
                counts[str(value)] += 1
    return counts


def _fdr_tag_counts(entries: list[dict[str, Any]]) -> Counter:
    counts = Counter()
    for entry in entries:
        if "Tag" in entry:
            counts[str(entry["Tag"])] += 1
        for sub_entry in entry.get("SubCCList") or []:
            if isinstance(sub_entry, dict) and "Tag" in sub_entry:
                counts[str(sub_entry["Tag"])] += 1
    return counts


def _resolve_fdr_entries(sealing_map: Any, product: Optional[str]) -> tuple[Optional[str], list[dict[str, Any]]]:
    if not isinstance(sealing_map, dict):
        return None, []
    key = product
    if key is None:
        key = next((item for item, value in sealing_map.items() if isinstance(value, str)), None)
    if key is None:
        return None, []
    value = sealing_map.get(key)
    resolved_key = value if isinstance(value, str) else key
    entries = sealing_map.get(resolved_key) if isinstance(value, str) else value
    if not isinstance(entries, list):
        return resolved_key, []
    return resolved_key, [entry for entry in entries if isinstance(entry, dict)]


def _fdr_info(root: Path, product: Optional[str]) -> dict[str, Any]:
    sealing_map = _load_plist(root / FDR_SEALING_MAP)
    repair_config = _load_plist(root / FDR_REPAIR_CONFIG)
    resolved_key, entries = _resolve_fdr_entries(sealing_map, product)
    subcomponent_count = sum(len(entry.get("SubCCList") or []) for entry in entries)

    repair_reference = None
    if product and isinstance(repair_config, dict):
        repair_reference = repair_config.get(product)

    return {
        "available": isinstance(sealing_map, dict),
        "product": product,
        "resolved_key": resolved_key,
        "repair_reference": repair_reference,
        "sealing_entry_count": len(entries),
        "subcomponent_entry_count": subcomponent_count,
        "top_attributes": dict(_fdr_attribute_counts(entries).most_common(20)),
        "top_data_identifiers": dict(_fdr_data_identifier_counts(entries).most_common(20)),
        "top_tags": dict(_fdr_tag_counts(entries).most_common(40)),
    }


def build_restoreos_component_inventory(
    firmware_root: Path,
    *,
    product: Optional[str] = None,
    chunk_size: int = 1024 * 1024,
) -> dict[str, Any]:
    firmware_root = firmware_root.expanduser().resolve()
    if not firmware_root.is_dir():
        raise FileNotFoundError(f"{firmware_root} is not a directory")

    service_files = []
    aggregate_markers = {category: [] for category in RESTOREOS_SERVICE_MARKERS}
    for path in _iter_candidate_files(firmware_root):
        hits = _service_marker_hits(path, chunk_size)
        for category, markers in hits.items():
            for marker in markers:
                if marker not in aggregate_markers[category]:
                    aggregate_markers[category].append(marker)
        service_files.append(
            {
                "path": _relative_to_root(path, firmware_root),
                "markers": hits,
            }
        )

    updaters_dir = firmware_root / UPDATERS_DIR
    updater_libraries = []
    if updaters_dir.is_dir():
        updater_libraries = [
            _relative_to_root(path, firmware_root) for path in sorted(updaters_dir.glob("*.dylib")) if path.is_file()
        ]

    return {
        "available": True,
        "firmware_root": None,
        "launch_daemons": _launch_daemon_info(firmware_root),
        "service_files": service_files,
        "service_markers": {category: markers for category, markers in aggregate_markers.items() if markers},
        "updater_libraries": updater_libraries,
        "standalone_firmware": _standalone_firmware_counts(firmware_root),
        "fdr": _fdr_info(firmware_root, product),
        "host_api": {
            "mode": "inventory-only",
            "updater_commands_exposed": False,
        },
    }


def build_restore_firmware_inventory(
    ipsw_root: Optional[Path] = None,
    firmware_root: Optional[Path] = None,
    *,
    product: Optional[str] = None,
    include_components: bool = False,
    chunk_size: int = 1024 * 1024,
) -> dict[str, Any]:
    if ipsw_root is None and firmware_root is None:
        raise ValueError("ipsw_root or firmware_root is required")

    manifest_info = None
    if ipsw_root is not None:
        manifest_info = build_restore_manifest_info(ipsw_root, include_components=include_components)

    if product is None and manifest_info:
        product = next(
            iter((manifest_info.get("build_manifest") or {}).get("supported_product_types") or []),
            None,
        )

    restoreos_info = None
    if firmware_root is not None:
        restoreos_info = build_restoreos_component_inventory(firmware_root, product=product, chunk_size=chunk_size)

    return {
        "product": product,
        "manifest": manifest_info,
        "restoreos": restoreos_info,
        "host_api": {
            "mode": "inventory-only",
            "updater_commands_exposed": False,
        },
    }
