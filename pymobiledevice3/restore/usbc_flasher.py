from pathlib import Path


USBC_FLASHER_FILES = {
    "tool": Path("usr/bin/usbcfwflasher"),
    "library": Path("usr/lib/libUSBCfwflasher.dylib"),
}

USBC_FLASHER_MARKERS = {
    "services": (
        "com.apple.usbcfwflasher",
        "com.apple.libUSBCfwflasher",
        "com.apple.usbcfwflasher.SleepAssertionID",
    ),
    "functions": (
        "_USBCFlasherCreate",
        "_USBCFlasherExecCmd",
        "_USBCFlasherIsDone",
        "_USBCFlasherSupported",
    ),
    "diagnostic_operations": (
        "query:andErrorResponse:",
        "_USBCFlasherIsDone",
        "_USBCFlasherSupported",
    ),
    "controller_operations": (
        "execCmd:withInput:andOutput:andErrorResponse:",
        "flash:andErrorResponse:",
        "reset:",
        "next:",
        "SWDFlashWrite",
        "SWDFlashRead",
        "SWDFlashErase",
        "attemptIECSCommand:flags:withData:dataLength:retData:retDataLength:timeout:andErrorResponse:",
        "iecsAtomicCommand:data:dataLength:retData:retDataLength:flags:timeout:",
    ),
}


def _relative_to_root(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _find_usbc_flasher_files(firmware_root: Path) -> list[Path]:
    paths = []
    for relative_path in USBC_FLASHER_FILES.values():
        path = firmware_root / relative_path
        if path.is_file():
            paths.append(path)

    seen = set(paths)
    for path in firmware_root.rglob("*"):
        if not path.is_file():
            continue
        name = path.name.lower()
        if name in {"usbcfwflasher", "libusbcfwflasher.dylib"} and path not in seen:
            paths.append(path)
            seen.add(path)

    return sorted(paths, key=lambda item: _relative_to_root(item, firmware_root))


def _marker_hits(path: Path, chunk_size: int) -> dict[str, list[str]]:
    marker_bytes = [
        (category, marker, marker.encode()) for category, markers in USBC_FLASHER_MARKERS.items() for marker in markers
    ]
    max_marker_len = max(len(marker) for _, _, marker in marker_bytes)
    hits = {category: [] for category in USBC_FLASHER_MARKERS}
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


def build_usbc_flasher_inventory(firmware_root: Path, *, chunk_size: int = 1024 * 1024) -> dict:
    firmware_root = firmware_root.expanduser().resolve()
    if not firmware_root.is_dir():
        raise FileNotFoundError(f"{firmware_root} is not a directory")

    files = []
    aggregate_hits = {category: [] for category in USBC_FLASHER_MARKERS}

    for path in _find_usbc_flasher_files(firmware_root):
        role = next(
            (name for name, relative_path in USBC_FLASHER_FILES.items() if path == firmware_root / relative_path),
            "candidate",
        )
        hits = _marker_hits(path, chunk_size)
        for category, markers in hits.items():
            for marker in markers:
                if marker not in aggregate_hits[category]:
                    aggregate_hits[category].append(marker)

        files.append(
            {
                "role": role,
                "path": _relative_to_root(path, firmware_root),
                "markers": hits,
            }
        )

    return {
        "available": bool(files),
        "files": files,
        "markers": {category: markers for category, markers in aggregate_hits.items() if markers},
        "restore_options": {
            "USBCFWData": "firmware-backed data type marker",
            "USBCOverride": "firmware-backed data type marker",
        },
        "host_api": {
            "flash_commands_exposed": False,
            "mode": "inventory-only",
        },
    }
