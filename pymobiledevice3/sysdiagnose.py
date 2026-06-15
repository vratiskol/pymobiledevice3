import hashlib
import json
import plistlib
import re
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Callable, Optional

from pymobiledevice3.tracev3 import DEFAULT_MAX_TRACEV3_FILE_BYTES, Tracev3CatalogScanner, is_logarchive_member

DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_SOURCES_PER_FINDING = 5
MAX_VALUES_PER_SECTION = 50

TEXT_SUFFIXES = {
    ".ips",
    ".json",
    ".log",
    ".plist",
    ".txt",
}

PATH_CATEGORY_PATTERNS = {
    "accounts": ("accounts", "appleaccount", "identityservices"),
    "apps": ("mobileinstallation", "installd", "applicationstate", "appconduit"),
    "baseband": ("baseband", "bbticket", "commcenter"),
    "cellular": ("cellular", "carrier", "commcenter", "coretelephony", "simstatus"),
    "crash": ("crashreporter", ".crash", ".ips", ".panic"),
    "location": ("locationd", "geod", "geolocation", "location"),
    "lockdown": ("lockdown", "pairing", "mobileactivation"),
    "network": ("network", "networkextension", "mDNSResponder", "ipconfig", "ifconfig"),
    "power": ("battery", "powerlog", "powerd", "thermal"),
    "profiles": ("managedconfiguration", "configurationprofiles", "profiles"),
    "security": ("tcc", "keychain", "trustd", "lockdownmode", "security"),
    "syslog": ("system_logs.logarchive", "logarchive", "os_trace", "diagnostics"),
    "wifi": ("wifi", "wi-fi", "airport", "wifid"),
}

MCC_COUNTRIES = {
    "202": "Greece",
    "204": "Netherlands",
    "206": "Belgium",
    "208": "France",
    "214": "Spain",
    "222": "Italy",
    "228": "Switzerland",
    "234": "United Kingdom",
    "235": "United Kingdom",
    "238": "Denmark",
    "242": "Norway",
    "244": "Finland",
    "262": "Germany",
    "268": "Portugal",
    "270": "Luxembourg",
    "272": "Ireland",
    "274": "Iceland",
    "302": "Canada",
    "310": "United States",
    "311": "United States",
    "312": "United States",
    "313": "United States",
    "314": "United States",
    "315": "United States",
    "316": "United States",
    "334": "Mexico",
    "404": "India",
    "405": "India",
    "440": "Japan",
    "450": "South Korea",
    "454": "Hong Kong",
    "460": "China",
    "466": "Taiwan",
    "505": "Australia",
    "510": "Indonesia",
    "520": "Thailand",
    "525": "Singapore",
    "530": "New Zealand",
    "602": "Egypt",
    "604": "Morocco",
    "655": "South Africa",
    "724": "Brazil",
}

IDENTIFIER_PATTERNS = {
    "eid": re.compile(r"\bEID\b\D{0,20}([0-9A-Fa-f]{16,32})"),
    "iccid": re.compile(r"\bICCID\b\D{0,20}([0-9]{18,22})", re.IGNORECASE),
    "imei": re.compile(r"\bIMEI(?:\d)?\b\D{0,20}([0-9]{14,16})", re.IGNORECASE),
    "imsi": re.compile(r"\bIMSI\b\D{0,20}([0-9]{14,16})", re.IGNORECASE),
}
PHONE_NUMBER_PATTERN = re.compile(
    r"\b(?:MSISDN|MDN|CTN|phone(?: number)?|line number|subscriber number)\b"
    r"[^+\d]{0,30}(\+?[0-9][0-9 .()/-]{6,}[0-9])",
    re.IGNORECASE,
)
MCC_MNC_PATTERNS = (
    re.compile(r"\bMCC\b\D{0,12}(?P<mcc>[0-9]{3}).{0,50}\bMNC\b\D{0,12}(?P<mnc>[0-9]{2,3})", re.I),
    re.compile(r"\bMNC\b\D{0,12}(?P<mnc>[0-9]{2,3}).{0,50}\bMCC\b\D{0,12}(?P<mcc>[0-9]{3})", re.I),
    re.compile(r"\bPLMN\b\D{0,12}(?P<mcc>[0-9]{3})[-_ ]?(?P<mnc>[0-9]{2,3})", re.I),
)
PROVIDER_PATTERN = re.compile(
    r"\b(?:carrier(?: name)?|operator(?: name)?|provider|network name|sim operator|service provider)\b"
    r"\s*[:=]\s*['\"]?(?P<value>[^'\"\n\r,;<>]{2,80})",
    re.IGNORECASE,
)
RAT_PATTERN = re.compile(r"\b(?:5G|NR|LTE|4G|UMTS|WCDMA|GSM|EDGE|GPRS|CDMA|eHRPD)\b", re.IGNORECASE)
COORDINATE_PATTERNS = (
    re.compile(
        r"\b(?:lat|latitude)\b\D{0,20}(?P<lat>[+-]?[0-9]{1,2}\.[0-9]{3,}).{0,80}"
        r"\b(?:lon|lng|longitude)\b\D{0,20}(?P<lon>[+-]?[0-9]{1,3}\.[0-9]{3,})",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:lon|lng|longitude)\b\D{0,20}(?P<lon>[+-]?[0-9]{1,3}\.[0-9]{3,}).{0,80}"
        r"\b(?:lat|latitude)\b\D{0,20}(?P<lat>[+-]?[0-9]{1,2}\.[0-9]{3,})",
        re.IGNORECASE,
    ),
)
CELL_FIELD_PATTERNS = {
    "cell_id": re.compile(r"\b(?:cell(?:ular)?[ _-]?(?:id|identity)|ci|eci|ecgi)\b\D{0,12}([0-9A-Fa-fx]+)", re.I),
    "lac": re.compile(r"\bLAC\b\D{0,12}([0-9A-Fa-fx]+)", re.I),
    "mcc": re.compile(r"\bMCC\b\D{0,12}([0-9]{3})", re.I),
    "mnc": re.compile(r"\bMNC\b\D{0,12}([0-9]{2,3})", re.I),
    "pci": re.compile(r"\bPCI\b\D{0,12}([0-9A-Fa-fx]+)", re.I),
    "tac": re.compile(r"\bTAC\b\D{0,12}([0-9A-Fa-fx]+)", re.I),
}
DEVICE_INFO_KEYS = {
    "BuildVersion": "build_version",
    "DeviceClass": "device_class",
    "HardwareModel": "hardware_model",
    "ProductName": "product_name",
    "ProductType": "product_type",
    "ProductVersion": "product_version",
}
SENSITIVE_DEVICE_KEYS = {
    "DeviceName": "device_name",
    "InternationalMobileEquipmentIdentity": "imei",
    "SerialNumber": "serial_number",
    "UniqueDeviceID": "unique_device_id",
}


class SysdiagnoseEntry:
    def __init__(self, path: str, size: int, reader: Callable[[], bytes]) -> None:
        self.path = path
        self.size = size
        self.reader = reader


class SysdiagnoseAnalyzer:
    def __init__(
        self,
        *,
        include_sensitive: bool = False,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_tracev3_file_bytes: int = DEFAULT_MAX_TRACEV3_FILE_BYTES,
        max_values: int = MAX_VALUES_PER_SECTION,
        scan_unified_log: bool = True,
    ) -> None:
        self.include_sensitive = include_sensitive
        self.max_file_bytes = max_file_bytes
        self.max_tracev3_file_bytes = max_tracev3_file_bytes
        self.max_values = max_values
        self.artifact_categories: dict[str, dict[str, Any]] = {}
        self.cell_towers: dict[tuple[tuple[str, str], ...], dict[str, Any]] = {}
        self.coordinates: dict[str, dict[str, Any]] = {}
        self.device: dict[str, Any] = {}
        self.errors: list[dict[str, str]] = []
        self.identifier_values: dict[str, dict[str, dict[str, Any]]] = {}
        self.phone_numbers: dict[str, dict[str, Any]] = {}
        self.plmns: dict[str, dict[str, Any]] = {}
        self.providers: dict[str, dict[str, Any]] = {}
        self.radio_access_technologies: dict[str, dict[str, Any]] = {}
        self.scan_unified_log = scan_unified_log
        self.skipped_large_files = 0
        self.text_files_scanned = 0
        self.total_bytes = 0
        self.total_entries = 0
        self.tracev3_catalog = Tracev3CatalogScanner(include_sensitive=include_sensitive, max_values=max_values)

    def analyze(self, source: Path) -> dict:
        source = source.expanduser()
        archive_type = _archive_type(source)
        for entry in _iter_entries(source, archive_type):
            self.total_entries += 1
            self.total_bytes += max(entry.size, 0)
            self._record_artifact_categories(entry.path)
            if self.scan_unified_log and is_logarchive_member(entry.path):
                if entry.size > self.max_tracev3_file_bytes:
                    self.tracev3_catalog.record_skipped_file(entry.path)
                else:
                    try:
                        self.tracev3_catalog.scan_payload(entry.path, entry.reader())
                    except (OSError, tarfile.TarError, zipfile.BadZipFile) as e:
                        self.errors.append({"path": entry.path, "error": str(e)})
                continue
            if entry.size > self.max_file_bytes:
                self.skipped_large_files += 1
                continue
            try:
                data = entry.reader()
            except (OSError, tarfile.TarError, zipfile.BadZipFile) as e:
                self.errors.append({"path": entry.path, "error": str(e)})
                continue
            self._scan_payload(entry.path, data)

        return {
            "archive": {
                "path": str(source),
                "type": archive_type,
            },
            "artifact_categories": _finalize_category_map(self.artifact_categories, self.max_values),
            "device": self.device,
            "errors": self.errors[: self.max_values],
            "generated_by": "pymobiledevice3 sysdiagnose forensic parser",
            "gsm": self._build_gsm_report(),
            "privacy": {
                "include_sensitive": self.include_sensitive,
                "redaction": None if self.include_sensitive else "sensitive values replaced by sha256_12 digests",
            },
            "summary": {
                "skipped_large_files": self.skipped_large_files,
                "total_bytes": self.total_bytes,
                "total_entries": self.total_entries,
                "text_files_scanned": self.text_files_scanned,
            },
        }

    def _build_gsm_report(self) -> dict:
        return {
            "cell_towers": _top_records(self.cell_towers, self.max_values),
            "geo": {
                "coordinates": _top_records(self.coordinates, self.max_values) if self.include_sensitive else {
                    "count": sum(item["count"] for item in self.coordinates.values()),
                    "redacted": True,
                    "sources": _merge_sources(self.coordinates.values()),
                    "unique_count": len(self.coordinates),
                },
                "mcc_countries": _top_records(_country_records_from_plmns(self.plmns), self.max_values),
            },
            "identifiers": {
                key: _top_records(values, self.max_values) for key, values in sorted(self.identifier_values.items())
            },
            "phone_numbers": _top_records(self.phone_numbers, self.max_values),
            "plmns": _top_records(self.plmns, self.max_values),
            "providers": _top_records(self.providers, self.max_values),
            "radio_access_technologies": _top_records(self.radio_access_technologies, self.max_values),
            "unified_log": self.tracev3_catalog.build_report(),
        }

    def _scan_payload(self, path: str, data: bytes) -> None:
        plist_obj = _try_load_plist(data)
        if plist_obj is not None:
            self._scan_object(path, plist_obj)
            self._scan_text(path, "\n".join(_flatten_object(plist_obj)))
            return

        json_obj = _try_load_json(data)
        if json_obj is not None:
            self._scan_object(path, json_obj)
            self._scan_text(path, "\n".join(_flatten_object(json_obj)))
            return

        if _looks_like_text(path, data):
            self._scan_text(path, data.decode("utf-8", errors="replace"))

    def _scan_object(self, path: str, obj: Any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_text = str(key)
                if key_text in DEVICE_INFO_KEYS and _simple_value(value):
                    self.device.setdefault(DEVICE_INFO_KEYS[key_text], value)
                elif key_text in SENSITIVE_DEVICE_KEYS and _simple_value(value):
                    output_key = SENSITIVE_DEVICE_KEYS[key_text]
                    self.device.setdefault(output_key, self._sensitive_value(str(value)))
                elif key_text.lower() in {"carriername", "carrier name", "operatorname", "network name"}:
                    self._record_value(self.providers, str(value), path)
                elif key_text.lower() in {"mcc", "mobilecountrycode", "mobile country code"}:
                    self._record_plmn(str(value), None, path)
                elif key_text.lower() in {"mnc", "mobilenetworkcode", "mobile network code"}:
                    self._record_plmn(None, str(value), path)
                self._scan_object(path, value)
        elif isinstance(obj, list):
            for item in obj:
                self._scan_object(path, item)

    def _scan_text(self, path: str, text: str) -> None:
        self.text_files_scanned += 1
        for pattern_name, pattern in IDENTIFIER_PATTERNS.items():
            for match in pattern.finditer(text):
                self._record_sensitive(self.identifier_values.setdefault(pattern_name, {}), match.group(1), path)

        for match in PHONE_NUMBER_PATTERN.finditer(text):
            self._record_sensitive(self.phone_numbers, _normalize_phone_number(match.group(1)), path)

        for pattern in MCC_MNC_PATTERNS:
            for match in pattern.finditer(text):
                self._record_plmn(match.group("mcc"), match.group("mnc"), path)

        for match in PROVIDER_PATTERN.finditer(text):
            provider = _clean_provider(match.group("value"))
            if provider:
                self._record_value(self.providers, provider, path)

        for match in RAT_PATTERN.finditer(text):
            self._record_value(self.radio_access_technologies, match.group(0).upper(), path)

        for pattern in COORDINATE_PATTERNS:
            for match in pattern.finditer(text):
                self._record_coordinate(match.group("lat"), match.group("lon"), path)

        for line in text.splitlines():
            self._scan_cell_tower_line(path, line)

    def _scan_cell_tower_line(self, path: str, line: str) -> None:
        lowered = line.lower()
        if not any(token in lowered for token in ("cell", "mcc", "mnc", "lac", "tac", "pci", "ecgi")):
            return
        fields = {}
        for field, pattern in CELL_FIELD_PATTERNS.items():
            match = pattern.search(line)
            if match:
                fields[field] = match.group(1)
        rat = RAT_PATTERN.search(line)
        if rat:
            fields["rat"] = rat.group(0).upper()
        if len(fields) < 2:
            return
        if "mcc" in fields:
            fields["country"] = MCC_COUNTRIES.get(fields["mcc"], "unknown")
        key = tuple(sorted(fields.items()))
        record = self.cell_towers.setdefault(key, {"count": 0, "sources": [], **fields})
        record["count"] += 1
        _append_source(record["sources"], path)

    def _record_artifact_categories(self, path: str) -> None:
        lowered = path.lower()
        for category, patterns in PATH_CATEGORY_PATTERNS.items():
            if any(pattern.lower() in lowered for pattern in patterns):
                record = self.artifact_categories.setdefault(category, {"count": 0, "examples": []})
                record["count"] += 1
                _append_source(record["examples"], path)

    def _record_coordinate(self, lat_text: str, lon_text: str, source: str) -> None:
        lat = _safe_float(lat_text)
        lon = _safe_float(lon_text)
        if lat is None or lon is None or not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
            return
        value = f"{lat:.6f},{lon:.6f}"
        if not self.include_sensitive:
            value = _sensitive_digest(value)["sha256_12"]
        record = self.coordinates.setdefault(value, {"count": 0, "sources": []})
        if self.include_sensitive:
            record.update({"latitude": lat, "longitude": lon})
        record["count"] += 1
        _append_source(record["sources"], source)

    def _record_plmn(self, mcc: Optional[str], mnc: Optional[str], source: str) -> None:
        mcc = mcc.strip() if mcc else None
        mnc = mnc.strip() if mnc else None
        if mcc is None and mnc is None:
            return
        key = f"{mcc or 'unknown'}-{mnc or 'unknown'}"
        record = self.plmns.setdefault(
            key,
            {
                "count": 0,
                "country": MCC_COUNTRIES.get(mcc, "unknown") if mcc else "unknown",
                "mcc": mcc,
                "mnc": mnc,
                "sources": [],
            },
        )
        if mcc and record.get("mcc") is None:
            record["mcc"] = mcc
            record["country"] = MCC_COUNTRIES.get(mcc, "unknown")
        if mnc and record.get("mnc") is None:
            record["mnc"] = mnc
        record["count"] += 1
        _append_source(record["sources"], source)

    def _record_sensitive(self, records: dict[str, dict[str, Any]], value: str, source: str) -> None:
        display_value = self._sensitive_value(value)
        key = display_value if isinstance(display_value, str) else display_value["sha256_12"]
        record = records.setdefault(key, {"count": 0, "sources": [], "value": display_value})
        record["count"] += 1
        _append_source(record["sources"], source)

    def _record_value(self, records: dict[str, dict[str, Any]], value: str, source: str) -> None:
        value = value.strip()
        if not value:
            return
        record = records.setdefault(value, {"count": 0, "sources": [], "value": value})
        record["count"] += 1
        _append_source(record["sources"], source)

    def _sensitive_value(self, value: str) -> Any:
        return value if self.include_sensitive else _sensitive_digest(value)


def analyze_sysdiagnose(
    source: Path,
    *,
    include_sensitive: bool = False,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_tracev3_file_bytes: int = DEFAULT_MAX_TRACEV3_FILE_BYTES,
    max_values: int = MAX_VALUES_PER_SECTION,
    scan_unified_log: bool = True,
) -> dict:
    return SysdiagnoseAnalyzer(
        include_sensitive=include_sensitive,
        max_file_bytes=max_file_bytes,
        max_tracev3_file_bytes=max_tracev3_file_bytes,
        max_values=max_values,
        scan_unified_log=scan_unified_log,
    ).analyze(source)


def _archive_type(source: Path) -> str:
    if source.is_dir():
        return "directory"
    if tarfile.is_tarfile(source):
        return "tar"
    if zipfile.is_zipfile(source):
        return "zip"
    raise ValueError(f"unsupported sysdiagnose input: {source}")


def _iter_entries(source: Path, archive_type: str):
    if archive_type == "directory":
        for child in sorted(source.rglob("*")):
            if child.is_file():
                yield SysdiagnoseEntry(
                    child.relative_to(source).as_posix(),
                    child.stat().st_size,
                    child.read_bytes,
                )
        return

    if archive_type == "tar":
        with tarfile.open(source, "r:*") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue

                def read_member(member=member):
                    extracted = archive.extractfile(member)
                    return b"" if extracted is None else extracted.read()

                yield SysdiagnoseEntry(member.name, member.size, read_member)
        return

    with zipfile.ZipFile(source) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            yield SysdiagnoseEntry(info.filename, info.file_size, lambda info=info: archive.read(info))


def _try_load_plist(data: bytes) -> Optional[Any]:
    if not (data.startswith(b"bplist") or data.lstrip().startswith(b"<?xml")):
        return None
    try:
        return plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, TypeError):
        return None


def _try_load_json(data: bytes) -> Optional[Any]:
    stripped = data.lstrip()
    if not stripped.startswith((b"{", b"[")):
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _looks_like_text(path: str, data: bytes) -> bool:
    suffix = Path(path).suffix.lower()
    if suffix in TEXT_SUFFIXES:
        return True
    return b"\x00" not in data[:4096]


def _flatten_object(obj: Any, prefix: str = "") -> list[str]:
    rows = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            rows.extend(_flatten_object(value, child_prefix))
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            rows.extend(_flatten_object(value, f"{prefix}[{index}]"))
    else:
        rows.append(f"{prefix}: {obj}")
    return rows


def _simple_value(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool))


def _sensitive_digest(value: str) -> dict:
    return {
        "redacted": True,
        "sha256_12": hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12],
    }


def _normalize_phone_number(value: str) -> str:
    value = value.strip()
    if value.startswith("+"):
        return "+" + re.sub(r"\D", "", value)
    return re.sub(r"\D", "", value)


def _clean_provider(value: str) -> Optional[str]:
    value = value.strip().strip("'\"")
    if not value or value.lower() in {"null", "none", "unknown", "false", "true"}:
        return None
    if len(value) > 80:
        return None
    return value


def _safe_float(value: str) -> Optional[float]:
    try:
        return float(value)
    except ValueError:
        return None


def _append_source(sources: list[str], source: str) -> None:
    if source not in sources and len(sources) < MAX_SOURCES_PER_FINDING:
        sources.append(source)


def _top_records(records: dict[str, dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    return [
        _copy_record(record)
        for record in sorted(records.values(), key=lambda item: (-item["count"], str(item.get("value", ""))))[:limit]
    ]


def _copy_record(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if value not in (None, [], {})}


def _merge_sources(records) -> list[str]:
    sources = []
    for record in records:
        for source in record.get("sources", []):
            _append_source(sources, source)
    return sources


def _country_records_from_plmns(plmns: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    countries: dict[str, dict[str, Any]] = {}
    for plmn in plmns.values():
        country = plmn.get("country") or "unknown"
        record = countries.setdefault(country, {"count": 0, "sources": [], "value": country})
        record["count"] += plmn["count"]
        for source in plmn.get("sources", []):
            _append_source(record["sources"], source)
    return countries


def _finalize_category_map(records: dict[str, dict[str, Any]], limit: int) -> dict:
    return {
        category: {"count": record["count"], "examples": record["examples"][:MAX_SOURCES_PER_FINDING]}
        for category, record in sorted(records.items(), key=lambda item: (-item[1]["count"], item[0]))[:limit]
    }
