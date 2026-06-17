import csv
import hashlib
import json
import math
import plistlib
import re
import tarfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from pymobiledevice3.tracev3 import DEFAULT_MAX_TRACEV3_FILE_BYTES, Tracev3CatalogScanner, is_logarchive_member

DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_SOURCES_PER_FINDING = 5
MAX_VALUES_PER_SECTION = 50
OPENCELLID_COLUMNS = (
    "radio",
    "mcc",
    "net",
    "area",
    "cell",
    "unit",
    "lon",
    "lat",
    "range",
    "samples",
    "changeable",
    "created",
    "updated",
    "average_signal",
)
CELL_DB_COLUMN_ALIASES = {
    "area": {"area", "lac", "tac", "location_area_code", "locationareacode"},
    "cell": {"cell", "cellid", "cell_id", "cid", "ci", "eci", "nci"},
    "lat": {"lat", "latitude"},
    "lon": {"lon", "lng", "longitude"},
    "mcc": {"mcc", "mobile_country_code", "mobilecountrycode"},
    "mnc": {"mnc", "net", "mobile_network_code", "mobilenetworkcode"},
    "radio": {"radio", "rat", "technology", "type"},
}
CELL_DB_EXTRA_COLUMNS = {
    "accuracy": {"accuracy", "accuracy_meters", "radius"},
    "average_signal": {"averagesignal", "average_signal", "avg_signal"},
    "changeable": {"changeable"},
    "created": {"created", "first_seen", "firstseen"},
    "range": {"range", "range_meters"},
    "samples": {"samples"},
    "updated": {"updated", "last_seen", "lastseen"},
}
CELL_DB_RADIO_ALIASES = {
    "4G": "LTE",
    "5G": "NR",
    "GPRS": "GSM",
    "WCDMA": "UMTS",
}
CELL_JOURNEY_RAT_RANKS = {
    "NR": 5,
    "LTE": 4,
    "UMTS": 3,
    "WCDMA": 3,
    "CDMA": 2,
    "EHRPD": 2,
    "EDGE": 1,
    "GPRS": 1,
    "GSM": 1,
}
CELL_JOURNEY_IMPOSSIBLE_SPEED_KMH = 1000
CELL_JOURNEY_SUSPICIOUS_SPEED_KMH = 350
CELL_JOURNEY_SHORT_WINDOW_SECONDS = 300
CELL_JOURNEY_CHURN_WINDOW_SECONDS = 120
CELL_JOURNEY_CHURN_UNIQUE_CELLS = 4
TIMELINE_EVIDENCE_MAX_LENGTH = 320
TIMELINE_TIMESTAMP_PATTERNS = (
    re.compile(
        r"\b(?P<value>[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}:[0-9]{2}"
        r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)\b"
    ),
)
TIMELINE_EVENT_CLASSIFIERS = (
    ("power", "reboot_or_shutdown", re.compile(r"\b(?:reboot|booted|shutdown|power(?:ed)? off|panic)\b", re.I)),
    ("lock_state", "lock_state", re.compile(r"\b(?:lock(?:ed)?|unlock(?:ed)?|passcode|biometric)\b", re.I)),
    ("vpn", "vpn_state", re.compile(r"\b(?:VPN|utun|tunnel|NetworkExtension)\b", re.I)),
    ("wifi", "wifi_state", re.compile(r"\b(?:Wi-?Fi|SSID|BSSID|AWDL|wifid|airport)\b", re.I)),
    ("location", "location", re.compile(r"\b(?:CoreLocation|locationd|latitude|longitude|GPS|CLLocation|geod)\b", re.I)),
    ("baseband", "baseband", re.compile(r"\b(?:Baseband|bbticket|AppleBaseband|ambtool)\b", re.I)),
    ("sim_carrier", "sim_carrier", re.compile(r"\b(?:SIM|ICCID|IMSI|EID|carrier|roaming|PLMN)\b", re.I)),
    ("cellular", "cellular", re.compile(r"\b(?:CommCenter|CoreTelephony|cell|MCC|MNC|TAC|LAC|RAT|LTE|GSM|NR)\b", re.I)),
    ("network", "network", re.compile(r"\b(?:IPv4|IPv6|IP address|ifconfig|route|DHCP|interface|network)\b", re.I)),
)
BSSID_PATTERN = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
IP_ADDRESS_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

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
        cell_db: Optional[Path] = None,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_tracev3_file_bytes: int = DEFAULT_MAX_TRACEV3_FILE_BYTES,
        max_values: int = MAX_VALUES_PER_SECTION,
        scan_unified_log: bool = True,
    ) -> None:
        self.cell_db = cell_db
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
        self.timeline_events: list[dict[str, Any]] = []
        self.timeline_events_count = 0
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

        report = {
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
        if self.cell_db is not None:
            report["gsm"]["cell_database"] = _enrich_cell_towers_from_database(
                report["gsm"],
                self.cell_db,
                include_sensitive=self.include_sensitive,
                max_values=self.max_values,
            )
        report["gsm"]["journey"] = _analyze_cellular_journey(
            report["gsm"],
            include_sensitive=self.include_sensitive,
            max_values=self.max_values,
        )
        report["timeline"] = _build_unified_timeline(
            report,
            self.timeline_events,
            raw_text_events_count=self.timeline_events_count,
            include_sensitive=self.include_sensitive,
            max_values=self.max_values,
        )
        return report

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
            self._scan_timeline_line(path, line)
            self._scan_cell_tower_line(path, line)

    def _scan_timeline_line(self, path: str, line: str) -> None:
        timestamp = _extract_timeline_timestamp(line)
        if timestamp is None:
            return
        classified = _classify_timeline_event(path, line)
        if classified is None:
            return
        category, event_type, severity = classified
        event = {
            "category": category,
            "event_type": event_type,
            "evidence": _timeline_evidence(line, include_sensitive=self.include_sensitive),
            "severity": severity,
            "source": path,
            "timestamp": timestamp,
        }
        details = _timeline_event_details(line, include_sensitive=self.include_sensitive)
        if details:
            event["details"] = details
        self.timeline_events_count += 1
        if len(self.timeline_events) < self.max_values * 20:
            self.timeline_events.append(event)

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
    cell_db: Optional[Path] = None,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_tracev3_file_bytes: int = DEFAULT_MAX_TRACEV3_FILE_BYTES,
    max_values: int = MAX_VALUES_PER_SECTION,
    scan_unified_log: bool = True,
) -> dict:
    return SysdiagnoseAnalyzer(
        cell_db=cell_db,
        include_sensitive=include_sensitive,
        max_file_bytes=max_file_bytes,
        max_tracev3_file_bytes=max_tracev3_file_bytes,
        max_values=max_values,
        scan_unified_log=scan_unified_log,
    ).analyze(source)


def _build_unified_timeline(
    report: dict,
    text_events: list[dict[str, Any]],
    *,
    raw_text_events_count: int,
    include_sensitive: bool,
    max_values: int,
) -> dict[str, Any]:
    events = [_copy_record(event) for event in text_events]
    gsm_report = report.get("gsm", {})
    for observation in _report_cell_observations(gsm_report, fallback_to_towers=False):
        event = _timeline_event_from_cell_observation(observation)
        if event is not None:
            events.append(event)
    journey = gsm_report.get("journey", {})
    if isinstance(journey, dict):
        for flag in journey.get("flags", []):
            event = _timeline_event_from_journey_flag(flag)
            if event is not None:
                events.append(event)
    events.sort(key=_timeline_sort_key)
    raw_events_count = len(events)
    events = _dedupe_timeline_events(events)
    categories: dict[str, dict[str, Any]] = {}
    event_types: dict[str, dict[str, Any]] = {}
    for event in events:
        _count_timeline_value(categories, event.get("category"))
        _count_timeline_value(event_types, event.get("event_type"))
    return {
        "available": bool(events),
        "categories": _top_records(categories, max_values),
        "event_types": _top_records(event_types, max_values),
        "events": events[:max_values],
        "events_count": len(events),
        "limitations": _timeline_limitations(events),
        "raw_events_count": raw_events_count,
        "raw_text_events_count": raw_text_events_count,
        "schema": "sysdiagnose_unified_timeline_v1",
        "truncated": len(events) > max_values,
    }


def _timeline_event_from_cell_observation(observation: dict[str, Any]) -> Optional[dict[str, Any]]:
    timestamp = observation.get("observed_at")
    if not timestamp:
        return None
    event = {
        "category": "cellular",
        "cell_key": _journey_cell_key(observation),
        "event_type": "cellular_observation",
        "severity": "info",
        "source": observation.get("source", "system_logs.logarchive"),
        "timestamp": timestamp,
    }
    details = _normalize_journey_observation(observation)
    details.pop("source", None)
    if details:
        event["details"] = details
    return event


def _timeline_event_from_journey_flag(flag: dict[str, Any]) -> Optional[dict[str, Any]]:
    timestamp = flag.get("to_observed_at") or flag.get("from_observed_at")
    if not timestamp:
        return None
    return _copy_record({
        "category": "cellular",
        "details": {
            "elapsed_seconds": flag.get("elapsed_seconds"),
            "from_cell_key": flag.get("from_cell_key"),
            "to_cell_key": flag.get("to_cell_key"),
        },
        "event_type": f"journey_{flag.get('type', 'flag')}",
        "evidence": flag.get("reason"),
        "severity": flag.get("severity", "medium"),
        "source": "gsm.journey",
        "timestamp": timestamp,
    })


def _extract_timeline_timestamp(line: str) -> Optional[str]:
    for pattern in TIMELINE_TIMESTAMP_PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        value = match.group("value")
        parsed = _parse_iso_datetime(value)
        if parsed is not None:
            return parsed.isoformat()
        return value
    return None


def _classify_timeline_event(path: str, line: str) -> Optional[tuple[str, str, str]]:
    haystack = f"{path}\n{line}"
    for category, event_type, pattern in TIMELINE_EVENT_CLASSIFIERS:
        if not pattern.search(haystack):
            continue
        return category, event_type, _timeline_event_severity(category, event_type, line)
    return None


def _timeline_event_severity(category: str, event_type: str, line: str) -> str:
    lowered = line.lower()
    if event_type == "reboot_or_shutdown" or "panic" in lowered:
        return "medium"
    if category == "baseband" and any(token in lowered for token in ("disabled", "error", "fail", "panic")):
        return "medium"
    if category in {"vpn", "sim_carrier"} and any(token in lowered for token in ("changed", "roaming", "connected", "disconnected")):
        return "low"
    return "info"


def _timeline_event_details(line: str, *, include_sensitive: bool) -> dict[str, Any]:
    details: dict[str, Any] = {}
    fields = {}
    for field, pattern in CELL_FIELD_PATTERNS.items():
        match = pattern.search(line)
        if match:
            fields[field] = match.group(1) if include_sensitive or field not in {"cell_id", "lac", "tac", "pci"} else "<redacted>"
    rat = RAT_PATTERN.search(line)
    if rat:
        fields["rat"] = rat.group(0).upper()
    if fields:
        details["cellular"] = fields
    for pattern in COORDINATE_PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        if include_sensitive:
            details["coordinate"] = {
                "latitude": _safe_float(match.group("lat")),
                "longitude": _safe_float(match.group("lon")),
            }
        else:
            details["coordinate"] = {"redacted": True}
        break
    if include_sensitive:
        bssids = BSSID_PATTERN.findall(line)
        if bssids:
            details["bssids"] = bssids[:MAX_SOURCES_PER_FINDING]
        ip_addresses = [value for value in IP_ADDRESS_PATTERN.findall(line) if _valid_ipv4(value)]
        if ip_addresses:
            details["ip_addresses"] = ip_addresses[:MAX_SOURCES_PER_FINDING]
    return details


def _timeline_evidence(line: str, *, include_sensitive: bool) -> str:
    evidence = " ".join(line.split())
    if not include_sensitive:
        for pattern in IDENTIFIER_PATTERNS.values():
            evidence = pattern.sub(lambda match: match.group(0).replace(match.group(1), "<redacted>"), evidence)
        evidence = PHONE_NUMBER_PATTERN.sub(lambda match: match.group(0).replace(match.group(1), "<redacted>"), evidence)
        evidence = BSSID_PATTERN.sub("<redacted-bssid>", evidence)
        evidence = IP_ADDRESS_PATTERN.sub(lambda match: "<redacted-ip>" if _valid_ipv4(match.group(0)) else match.group(0), evidence)
        for pattern in COORDINATE_PATTERNS:
            evidence = pattern.sub("coordinate=<redacted>", evidence)
    if len(evidence) > TIMELINE_EVIDENCE_MAX_LENGTH:
        return evidence[: TIMELINE_EVIDENCE_MAX_LENGTH - 1] + "..."
    return evidence


def _valid_ipv4(value: str) -> bool:
    try:
        return all(0 <= int(part) <= 255 for part in value.split("."))
    except ValueError:
        return False


def _timeline_sort_key(event: dict[str, Any]) -> tuple[int, str, str, str]:
    timestamp = event.get("timestamp")
    parsed = _parse_iso_datetime(timestamp)
    if parsed is None:
        return (1, "", str(event.get("category", "")), str(event.get("source", "")))
    return (0, parsed.isoformat(), str(event.get("category", "")), str(event.get("source", "")))


def _dedupe_timeline_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    for event in events:
        if deduped and _timeline_duplicate_key(deduped[-1]) == _timeline_duplicate_key(event):
            deduped[-1]["occurrences"] = deduped[-1].get("occurrences", 1) + 1
            continue
        deduped.append(event)
    return deduped


def _timeline_duplicate_key(event: dict[str, Any]) -> tuple[Any, Any, Any, Any, Any, str]:
    return (
        event.get("timestamp"),
        event.get("category"),
        event.get("event_type"),
        event.get("source"),
        event.get("cell_key"),
        json.dumps(event.get("details", event.get("evidence", "")), sort_keys=True),
    )


def _count_timeline_value(records: dict[str, dict[str, Any]], value: Any) -> None:
    if not value:
        return
    key = str(value)
    record = records.setdefault(key, {"count": 0, "sources": [], "value": key})
    record["count"] += 1


def _timeline_limitations(events: list[dict[str, Any]]) -> list[str]:
    limitations = ["Timeline is best-effort and only includes parsed timestamped events."]
    if not events:
        limitations.append("No timestamped forensic timeline events were parsed.")
    if not any(event.get("category") == "cellular" for event in events):
        limitations.append("No timestamped cellular observations were available in the unified timeline.")
    return limitations


def _enrich_cell_towers_from_database(
    gsm_report: dict,
    cell_db: Path,
    *,
    include_sensitive: bool,
    max_values: int,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "format": "csv",
        "lookups": 0,
        "matched_towers": 0,
        "matches": 0,
        "path": str(cell_db),
        "rows_scanned": 0,
    }
    towers = _report_cell_towers(gsm_report) + _report_cell_observations(gsm_report, fallback_to_towers=False)
    wanted: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for tower in towers:
        key = _cell_db_lookup_key_from_tower(tower)
        if key is None:
            continue
        wanted.setdefault(key, []).append(tower)
    metadata["lookups"] = len(wanted)
    if not wanted:
        return metadata

    errors: list[str] = []
    try:
        with cell_db.open(newline="", encoding="utf-8", errors="replace") as handle:
            reader = csv.reader(handle)
            first_row = next(reader, None)
            if first_row is None:
                metadata["errors"] = ["empty cell database"]
                return metadata
            has_header = _cell_db_has_header(first_row)
            columns = _cell_db_columns(first_row if has_header else OPENCELLID_COLUMNS[: len(first_row)])
            if not has_header:
                metadata["rows_scanned"] += 1
                _match_cell_db_row(first_row, columns, wanted, metadata, include_sensitive=include_sensitive)
            for row in reader:
                metadata["rows_scanned"] += 1
                try:
                    _match_cell_db_row(row, columns, wanted, metadata, include_sensitive=include_sensitive)
                except ValueError as e:
                    if len(errors) < max_values:
                        errors.append(str(e))
    except OSError as e:
        metadata["errors"] = [str(e)]
        return metadata
    if errors:
        metadata["errors"] = errors
    return metadata


def _report_cell_towers(gsm_report: dict) -> list[dict[str, Any]]:
    towers = list(gsm_report.get("cell_towers", []))
    unified_log = gsm_report.get("unified_log", {})
    if isinstance(unified_log, dict):
        towers.extend(unified_log.get("cell_towers", []))
    return towers


def _report_cell_observations(gsm_report: dict, *, fallback_to_towers: bool = True) -> list[dict[str, Any]]:
    unified_log = gsm_report.get("unified_log", {})
    observations = []
    if isinstance(unified_log, dict):
        observations.extend(unified_log.get("cell_tower_observations", []))
    if observations or not fallback_to_towers:
        return observations
    return _report_cell_towers(gsm_report)


def _analyze_cellular_journey(
    gsm_report: dict,
    *,
    include_sensitive: bool,
    max_values: int,
) -> dict[str, Any]:
    observations = [_normalize_journey_observation(item) for item in _report_cell_observations(gsm_report)]
    observations = [item for item in observations if item]
    observations.sort(key=_journey_sort_key)
    raw_observations_count = len(observations)
    observations = _dedupe_journey_observations(observations)
    flags: list[dict[str, Any]] = []
    segments: list[dict[str, Any]] = []
    limitations = [
        "Heuristic analysis only: no single flag proves IMSI-catcher, rogue base-station, or hijack activity.",
        "Coordinates are optional; distance and speed checks require cell database matches with latitude/longitude.",
    ]
    if not observations:
        return {
            "analysis": "cellular_journey_heuristic_v1",
            "available": False,
            "coordinates_optional": True,
            "flags": [],
            "limitations": [*limitations, "No cellular observations were parsed."],
            "located_observations_count": 0,
            "observations": [],
            "observations_count": 0,
            "ordered_observations_count": 0,
            "raw_observations_count": 0,
            "risk_level": "unknown",
            "risk_score": 0,
            "segments": [],
        }

    _add_identity_collision_flags(observations, flags, max_values=max_values)
    _add_short_window_churn_flags(observations, flags, max_values=max_values)
    for previous, current in zip(observations, observations[1:]):
        segment = _journey_segment(previous, current, include_sensitive=include_sensitive)
        if segment is not None and len(segments) < max_values:
            segments.append(segment)
        _add_transition_flags(previous, current, flags, segment=segment, max_values=max_values)

    score = min(sum(_journey_flag_weight(flag) for flag in flags), 100)
    return {
        "analysis": "cellular_journey_heuristic_v1",
        "available": len(observations) >= 1,
        "coordinates_optional": True,
        "flags": flags[:max_values],
        "limitations": limitations + _journey_limitations(observations),
        "located_observations_count": sum(1 for item in observations if _journey_coordinate(item) is not None),
        "observations": observations[:max_values],
        "observations_count": len(observations),
        "ordered_observations_count": sum(1 for item in observations if item.get("observed_at")),
        "raw_observations_count": raw_observations_count,
        "risk_level": _journey_risk_level(score, observations),
        "risk_score": score,
        "segments": segments,
    }


def _normalize_journey_observation(item: dict[str, Any]) -> dict[str, Any]:
    observation: dict[str, Any] = {}
    for field in (
        "band",
        "bandwidth",
        "cell_id",
        "cell_type",
        "country",
        "lac",
        "mcc",
        "mnc",
        "physical_cell_id",
        "rat",
        "source",
        "tac",
        "uarfcn",
    ):
        value = item.get(field)
        if value not in (None, "", "<redacted>"):
            observation[field] = value
    lookup = item.get("lookup")
    if isinstance(lookup, dict):
        observation["lookup"] = lookup
    match = item.get("cell_database_match")
    if isinstance(match, dict):
        observation["cell_database_match"] = match
    observed_at = item.get("observed_at")
    if observed_at:
        observation["observed_at"] = observed_at
    observation["cell_key"] = _journey_cell_key(observation)
    return observation


def _dedupe_journey_observations(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    for observation in observations:
        if deduped and _journey_duplicate_key(deduped[-1]) == _journey_duplicate_key(observation):
            continue
        deduped.append(observation)
    return deduped


def _journey_duplicate_key(item: dict[str, Any]) -> tuple[Any, Any, Any, Any]:
    return (
        item.get("observed_at"),
        item.get("cell_key"),
        item.get("rat"),
        item.get("cell_type"),
    )


def _journey_sort_key(item: dict[str, Any]) -> tuple[int, str, str]:
    observed_at = item.get("observed_at")
    parsed = _parse_iso_datetime(observed_at) if observed_at else None
    if parsed is None:
        return (1, "", str(item.get("source", "")))
    return (0, parsed.isoformat(), str(item.get("source", "")))


def _journey_cell_key(item: dict[str, Any]) -> str:
    lookup = item.get("lookup") if isinstance(item.get("lookup"), dict) else {}
    area = lookup.get("tac") or lookup.get("lac") or item.get("tac") or item.get("lac") or "unknown"
    cell = lookup.get("eci") or lookup.get("nci") or lookup.get("cid") or item.get("cell_id") or "unknown"
    return "-".join([
        str(item.get("mcc", "unknown")),
        str(item.get("mnc", "unknown")),
        str(area),
        str(cell),
    ])


def _journey_segment(
    previous: dict[str, Any],
    current: dict[str, Any],
    *,
    include_sensitive: bool,
) -> Optional[dict[str, Any]]:
    previous_time = _parse_iso_datetime(previous.get("observed_at"))
    current_time = _parse_iso_datetime(current.get("observed_at"))
    if previous_time is None or current_time is None:
        return None
    elapsed_seconds = (current_time - previous_time).total_seconds()
    if elapsed_seconds < 0:
        return None
    segment: dict[str, Any] = {
        "elapsed_seconds": round(elapsed_seconds, 3),
        "from_cell_key": previous.get("cell_key"),
        "from_observed_at": previous.get("observed_at"),
        "to_cell_key": current.get("cell_key"),
        "to_observed_at": current.get("observed_at"),
    }
    previous_coordinate = _journey_coordinate(previous)
    current_coordinate = _journey_coordinate(current)
    if previous_coordinate is None or current_coordinate is None:
        segment["distance_available"] = False
        return segment
    distance_meters = _haversine_meters(previous_coordinate, current_coordinate)
    adjusted_distance = max(
        0.0,
        distance_meters - _journey_coordinate_range(previous) - _journey_coordinate_range(current),
    )
    segment.update({
        "distance_available": True,
        "distance_meters": round(distance_meters, 3),
        "range_adjusted_distance_meters": round(adjusted_distance, 3),
    })
    if elapsed_seconds > 0:
        speed_kmh = adjusted_distance / elapsed_seconds * 3.6
        segment["range_adjusted_speed_kmh"] = round(speed_kmh, 3)
        if speed_kmh >= CELL_JOURNEY_IMPOSSIBLE_SPEED_KMH:
            segment["movement_flag"] = "impossible_speed"
        elif speed_kmh >= CELL_JOURNEY_SUSPICIOUS_SPEED_KMH:
            segment["movement_flag"] = "suspicious_speed"
    if include_sensitive:
        segment["from_coordinate"] = {"latitude": previous_coordinate[0], "longitude": previous_coordinate[1]}
        segment["to_coordinate"] = {"latitude": current_coordinate[0], "longitude": current_coordinate[1]}
    return segment


def _add_transition_flags(
    previous: dict[str, Any],
    current: dict[str, Any],
    flags: list[dict[str, Any]],
    *,
    segment: Optional[dict[str, Any]],
    max_values: int,
) -> None:
    if len(flags) >= max_values:
        return
    elapsed_seconds = segment.get("elapsed_seconds") if segment else None
    if previous.get("mcc") and current.get("mcc") and previous.get("mcc") != current.get("mcc"):
        _append_journey_flag(
            flags,
            "mcc_change",
            "high" if _short_elapsed(elapsed_seconds) else "medium",
            previous,
            current,
            elapsed_seconds=elapsed_seconds,
            reason="Mobile country code changed between consecutive cell observations.",
        )
    elif _plmn(previous) and _plmn(current) and _plmn(previous) != _plmn(current):
        _append_journey_flag(
            flags,
            "plmn_change",
            "medium" if _short_elapsed(elapsed_seconds) else "low",
            previous,
            current,
            elapsed_seconds=elapsed_seconds,
            reason="Mobile network changed between consecutive cell observations.",
        )
    if _rat_downgrade(previous.get("rat"), current.get("rat")):
        _append_journey_flag(
            flags,
            "rat_downgrade",
            "high" if current.get("rat") in {"GSM", "EDGE", "GPRS"} else "medium",
            previous,
            current,
            elapsed_seconds=elapsed_seconds,
            reason="Radio access technology downgraded between consecutive observations.",
        )
    if segment and segment.get("movement_flag"):
        _append_journey_flag(
            flags,
            segment["movement_flag"],
            "high" if segment["movement_flag"] == "impossible_speed" else "medium",
            previous,
            current,
            elapsed_seconds=elapsed_seconds,
            reason="Cell database coordinates imply an implausible movement speed.",
            extra={"range_adjusted_speed_kmh": segment.get("range_adjusted_speed_kmh")},
        )


def _add_identity_collision_flags(observations: list[dict[str, Any]], flags: list[dict[str, Any]], *, max_values: int) -> None:
    seen: dict[str, set[str]] = {}
    for item in observations:
        cell_id = str(item.get("cell_id") or "")
        if not cell_id:
            continue
        seen.setdefault(cell_id, set()).add(_journey_cell_key(item))
    for cell_id, keys in seen.items():
        if len(keys) <= 1:
            continue
        flags.append({
            "cell_id": cell_id,
            "distinct_keys": sorted(keys)[:max_values],
            "reason": "Same cell identifier appeared with multiple MCC/MNC/area combinations.",
            "severity": "medium",
            "type": "cell_identity_collision",
        })
        if len(flags) >= max_values:
            return


def _add_short_window_churn_flags(
    observations: list[dict[str, Any]],
    flags: list[dict[str, Any]],
    *,
    max_values: int,
) -> None:
    timed = [(item, _parse_iso_datetime(item.get("observed_at"))) for item in observations if item.get("observed_at")]
    timed = [(item, observed_at) for item, observed_at in timed if observed_at is not None]
    for index, (start_item, start_time) in enumerate(timed):
        window = [start_item]
        for item, observed_at in timed[index + 1 :]:
            if (observed_at - start_time).total_seconds() > CELL_JOURNEY_CHURN_WINDOW_SECONDS:
                break
            window.append(item)
        unique_cells = {item.get("cell_key") for item in window}
        if len(unique_cells) < CELL_JOURNEY_CHURN_UNIQUE_CELLS:
            continue
        flags.append({
            "cell_keys": sorted(unique_cells)[:max_values],
            "duration_seconds": CELL_JOURNEY_CHURN_WINDOW_SECONDS,
            "from_observed_at": start_item.get("observed_at"),
            "reason": "Many distinct cells were observed in a short window.",
            "severity": "medium",
            "type": "rapid_cell_churn",
            "unique_cell_count": len(unique_cells),
        })
        if len(flags) >= max_values:
            return


def _append_journey_flag(
    flags: list[dict[str, Any]],
    flag_type: str,
    severity: str,
    previous: dict[str, Any],
    current: dict[str, Any],
    *,
    elapsed_seconds: Optional[float],
    reason: str,
    extra: Optional[dict[str, Any]] = None,
) -> None:
    flag = {
        "elapsed_seconds": elapsed_seconds,
        "from_cell_key": previous.get("cell_key"),
        "from_observed_at": previous.get("observed_at"),
        "reason": reason,
        "severity": severity,
        "to_cell_key": current.get("cell_key"),
        "to_observed_at": current.get("observed_at"),
        "type": flag_type,
    }
    if extra:
        flag.update(extra)
    flags.append(_copy_record(flag))


def _journey_coordinate(item: dict[str, Any]) -> Optional[tuple[float, float]]:
    match = item.get("cell_database_match")
    if not isinstance(match, dict):
        return None
    lat = match.get("latitude")
    lon = match.get("longitude")
    if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
        return None
    return float(lat), float(lon)


def _journey_coordinate_range(item: dict[str, Any]) -> float:
    match = item.get("cell_database_match")
    if not isinstance(match, dict):
        return 0.0
    for field in ("range", "accuracy"):
        value = match.get(field)
        if value is None:
            continue
        try:
            return max(float(value), 0.0)
        except (TypeError, ValueError):
            continue
    return 0.0


def _haversine_meters(start: tuple[float, float], end: tuple[float, float]) -> float:
    lat1, lon1 = math.radians(start[0]), math.radians(start[1])
    lat2, lon2 = math.radians(end[0]), math.radians(end[1])
    delta_lat = lat2 - lat1
    delta_lon = lon2 - lon1
    a = math.sin(delta_lat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2) ** 2
    return 6_371_000 * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _parse_iso_datetime(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace("Z", "+00:00")
    if " " in normalized and "T" not in normalized:
        normalized = normalized.replace(" ", "T", 1)
    if re.search(r"[+-][0-9]{4}$", normalized):
        normalized = f"{normalized[:-5]}{normalized[-5:-2]}:{normalized[-2:]}"
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _plmn(item: dict[str, Any]) -> Optional[tuple[str, str]]:
    mcc = item.get("mcc")
    mnc = item.get("mnc")
    if not mcc or not mnc:
        return None
    return str(mcc), str(mnc)


def _rat_downgrade(previous: Any, current: Any) -> bool:
    previous_rank = CELL_JOURNEY_RAT_RANKS.get(_normalize_cell_radio(previous) or "")
    current_rank = CELL_JOURNEY_RAT_RANKS.get(_normalize_cell_radio(current) or "")
    return previous_rank is not None and current_rank is not None and current_rank < previous_rank


def _short_elapsed(elapsed_seconds: Optional[float]) -> bool:
    return elapsed_seconds is not None and elapsed_seconds <= CELL_JOURNEY_SHORT_WINDOW_SECONDS


def _journey_flag_weight(flag: dict[str, Any]) -> int:
    return {"high": 50, "medium": 20, "low": 5}.get(str(flag.get("severity")), 0)


def _journey_risk_level(score: int, observations: list[dict[str, Any]]) -> str:
    if len(observations) < 2:
        return "unknown"
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def _journey_limitations(observations: list[dict[str, Any]]) -> list[str]:
    limitations = []
    if sum(1 for item in observations if item.get("observed_at")) < 2:
        limitations.append("Fewer than two timestamped observations; transition timing is incomplete.")
    if not any(_journey_coordinate(item) is not None for item in observations):
        limitations.append("No cell database coordinates; movement speed and geographic continuity were not checked.")
    return limitations


def _cell_db_lookup_key_from_tower(tower: dict[str, Any]) -> Optional[tuple[str, str, str, str]]:
    mcc = _normalize_cell_number(tower.get("mcc"))
    mnc = _normalize_cell_number(tower.get("mnc"))
    lookup = tower.get("lookup") if isinstance(tower.get("lookup"), dict) else {}
    area = _normalize_cell_number(lookup.get("tac") or lookup.get("lac") or tower.get("tac") or tower.get("lac"))
    cell = _normalize_cell_number(
        lookup.get("eci") or lookup.get("nci") or lookup.get("cid") or tower.get("cell_id") or tower.get("ecgi")
    )
    if not all((mcc, mnc, area, cell)):
        return None
    return mcc, mnc, area, cell


def _cell_db_has_header(row: list[str]) -> bool:
    normalized = {_normalize_cell_db_column_name(column) for column in row}
    return bool(normalized & {"mcc", "mobilecountrycode"}) and bool(normalized & {"cell", "cellid", "cid", "eci"})


def _cell_db_columns(row: tuple[str, ...] | list[str]) -> dict[str, int]:
    columns: dict[str, int] = {}
    for index, column in enumerate(row):
        normalized = _normalize_cell_db_column_name(column)
        for canonical, aliases in CELL_DB_COLUMN_ALIASES.items():
            if normalized in aliases:
                columns[canonical] = index
                break
        for canonical, aliases in CELL_DB_EXTRA_COLUMNS.items():
            if normalized in aliases:
                columns[canonical] = index
                break
    return columns


def _match_cell_db_row(
    row: list[str],
    columns: dict[str, int],
    wanted: dict[tuple[str, str, str, str], list[dict[str, Any]]],
    metadata: dict[str, Any],
    *,
    include_sensitive: bool,
) -> None:
    mcc = _normalize_cell_number(_cell_db_value(row, columns, "mcc"))
    mnc = _normalize_cell_number(_cell_db_value(row, columns, "mnc"))
    area = _normalize_cell_number(_cell_db_value(row, columns, "area"))
    cell = _normalize_cell_number(_cell_db_value(row, columns, "cell"))
    if not all((mcc, mnc, area, cell)):
        return
    key = (mcc, mnc, area, cell)
    candidates = wanted.get(key)
    if not candidates:
        return
    lat = _safe_float(_cell_db_value(row, columns, "lat") or "")
    lon = _safe_float(_cell_db_value(row, columns, "lon") or "")
    if lat is None or lon is None or not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
        raise ValueError(f"invalid coordinate for cell database key {key}")
    radio = _normalize_cell_radio(_cell_db_value(row, columns, "radio"))
    for tower in candidates:
        if tower.get("cell_database_match"):
            continue
        tower_radio = _normalize_cell_radio(tower.get("rat"))
        if radio and tower_radio and radio != tower_radio:
            continue
        tower["cell_database_match"] = _cell_database_match_record(row, columns, lat, lon, include_sensitive)
        metadata["matched_towers"] += 1
    metadata["matches"] += 1


def _cell_database_match_record(
    row: list[str],
    columns: dict[str, int],
    lat: float,
    lon: float,
    include_sensitive: bool,
) -> dict[str, Any]:
    match: dict[str, Any] = {
        "area": _normalize_cell_number(_cell_db_value(row, columns, "area")),
        "cell": _normalize_cell_number(_cell_db_value(row, columns, "cell")),
        "mcc": _normalize_cell_number(_cell_db_value(row, columns, "mcc")),
        "mnc": _normalize_cell_number(_cell_db_value(row, columns, "mnc")),
    }
    radio = _normalize_cell_radio(_cell_db_value(row, columns, "radio"))
    if radio:
        match["radio"] = radio
    if include_sensitive:
        match["latitude"] = lat
        match["longitude"] = lon
    else:
        match["coordinate"] = _sensitive_digest(f"{lat:.6f},{lon:.6f}")
    for field in ("accuracy", "average_signal", "changeable", "created", "range", "samples", "updated"):
        value = _cell_db_value(row, columns, field)
        if value:
            match[field] = value
    return _copy_record(match)


def _cell_db_value(row: list[str], columns: dict[str, int], field: str) -> Optional[str]:
    index = columns.get(field)
    if index is None or index >= len(row):
        return None
    value = row[index].strip()
    return value or None


def _normalize_cell_db_column_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.strip().lower())


def _normalize_cell_number(value: Any) -> Optional[str]:
    if value is None or value == "<redacted>":
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return str(int(text, 0))
    except ValueError:
        return text.lstrip("0") or "0" if text.isdecimal() else text


def _normalize_cell_radio(value: Any) -> Optional[str]:
    if value is None:
        return None
    radio = str(value).strip().upper()
    if not radio:
        return None
    return CELL_DB_RADIO_ALIASES.get(radio, radio)


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
