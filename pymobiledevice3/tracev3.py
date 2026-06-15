import re
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

DEFAULT_MAX_TRACEV3_FILE_BYTES = 16 * 1024 * 1024
MAX_SOURCES_PER_TRACEV3_FINDING = 5
MAX_TRACEV3_STRING_LENGTH = 320
TRACEV3_CHUNK_PREAMBLE_SIZE = 16
TRACEV3_HEADER_TAG = 0x1000
TRACEV3_KNOWN_TAGS = {
    TRACEV3_HEADER_TAG: "header",
    0x600B: "catalog",
    0x600D: "firehose",
}

CELLULAR_TRACEV3_BYTES = re.compile(
    rb"CommCenter|CoreTelephony|MCC|MNC|CellID|Cell ID|ECGI|ServingCell|serving cell|"
    rb"camped|PLMN|timingadvance|locationId|cellular network|baseband",
    re.IGNORECASE,
)
CELLULAR_TRACEV3_TEXT = re.compile(
    r"CommCenter|CoreTelephony|MCC|MNC|CellID|Cell ID|ECGI|ServingCell|serving cell|"
    r"camped|PLMN|timingadvance|locationId|cellular network|baseband",
    re.IGNORECASE,
)
FORMAT_SPECIFIER_PATTERN = re.compile(
    r"%\{[^}]+}|%[0-9.+#\-]*(?:@|d|u|x|llx|llu|hu|s|f)",
)
MNC_MCC_DOMAIN_PATTERN = re.compile(r"\bmnc(?P<mnc>[0-9]{2,3})\.mcc(?P<mcc>[0-9]{3})\b", re.IGNORECASE)
MCC_MNC_PATTERN = re.compile(
    r"\bmcc\b\D{0,12}(?P<mcc>[0-9]{3}).{0,40}\bmnc\b\D{0,12}(?P<mnc>[0-9]{1,3})",
    re.IGNORECASE,
)
MCC_ONLY_PATTERN = re.compile(r"\bmcc\b\D{0,12}(?P<mcc>[0-9]{3})", re.IGNORECASE)
TRACEV3_HEADER_TEXT_PATTERN = re.compile(
    r"^(?:[0-9]{2}[A-Z][0-9]{2,4}[a-z]?|[A-Z][0-9]{2,4}[A-Z]{2}|"
    r"/var/db/timezone/zoneinfo/[A-Za-z0-9_+./-]+|[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12})$"
)
RAW_FIELD_REDACTION_PATTERNS = (
    re.compile(r"\b(cell(?:ular)?[ _-]?(?:id|identity)|cellid|ci|eci|ecgi)\b\s*[:=,]\s*([0-9A-Fa-fx]{3,})", re.I),
    re.compile(r"\b(lac|tac|pci|sid|nid)\b\s*[:=,]\s*([0-9A-Fa-fx]{2,})", re.I),
    re.compile(r"\b(?:lat|latitude|lon|lng|longitude)\b\s*[:=,]\s*[+-]?[0-9]{1,3}\.[0-9]{3,}", re.I),
)

FIELD_PATTERNS = {
    "cell_id": re.compile(r"\b(?:cell\s*id|cellid|cellular[ _-]?identity|ci|eci|ecgi)\b", re.I),
    "lac": re.compile(r"\bLAC\b|\blac\b", re.I),
    "mcc": re.compile(r"\bMCC\b|\bmcc\b|mnc[0-9]{2,3}\.mcc[0-9]{3}", re.I),
    "mnc": re.compile(r"\bMNC\b|\bmnc\b|mnc[0-9]{2,3}\.mcc[0-9]{3}", re.I),
    "pci": re.compile(r"\bPCI\b|\bphysCellId\b|\bpci\b", re.I),
    "tac": re.compile(r"\bTAC\b|\btac\b", re.I),
}
INDICATOR_PATTERNS = {
    "commcenter": re.compile(r"\bCommCenter\b", re.I),
    "coretelephony": re.compile(r"\bCoreTelephony\b", re.I),
    "last_known_location": re.compile(r"\blastKnown latitude\b|\blastKnown longitude\b", re.I),
    "location_id": re.compile(r"\blocationId\b", re.I),
    "plmn": re.compile(r"\bPLMN\b|mnc[0-9]{2,3}\.mcc[0-9]{3}", re.I),
    "serving_cell": re.compile(r"\bserving cell\b|\bServingCell\b", re.I),
    "supl": re.compile(r"\bSUPL\b|\bsupl\b", re.I),
    "timing_advance": re.compile(r"\btimingadvance\b|\bta\b", re.I),
}


@dataclass(frozen=True)
class Tracev3Chunk:
    offset: int
    payload_offset: int
    payload_size: int
    subtag: int
    tag: int

    @property
    def payload_end(self) -> int:
        return self.payload_offset + self.payload_size


class Tracev3CatalogScanner:
    """Best-effort Apple Unified Log catalog scanner.

    This does not fully decode tracev3 event payloads. It extracts printable strings and
    format templates from tracev3/logarchive files so forensic reports can identify
    cellular evidence and private dynamic fields that require a full unified-log decoder.
    """

    def __init__(
        self,
        *,
        include_sensitive: bool = False,
        max_values: int = 50,
        max_sources: int = MAX_SOURCES_PER_TRACEV3_FINDING,
    ) -> None:
        self.include_sensitive = include_sensitive
        self.max_values = max_values
        self.max_sources = max_sources
        self.bytes_scanned = 0
        self.cellular_files: dict[str, dict[str, Any]] = {}
        self.catalog_strings: dict[str, dict[str, Any]] = {}
        self.field_indicators: dict[str, dict[str, Any]] = {}
        self.files_scanned = 0
        self.plmns: dict[str, dict[str, Any]] = {}
        self.private_field_templates = 0
        self.skipped_large_files = 0
        self.structure_bytes_scanned = 0
        self.tracev3_chunk_records: dict[str, dict[str, Any]] = {}
        self.tracev3_files = 0
        self.tracev3_header_strings: dict[str, dict[str, Any]] = {}
        self.tracev3_malformed_files = 0
        self.templates: dict[str, dict[str, Any]] = {}
        self.tower_lookup_ready_templates = 0

    def record_skipped_file(self, path: str) -> None:
        if is_logarchive_member(path):
            self.skipped_large_files += 1

    def scan_payload(self, path: str, data: bytes) -> None:
        if not is_logarchive_member(path) and Path(path).suffix.lower() != ".tracev3":
            return
        if looks_like_tracev3(data):
            self._scan_structure(path, data)
        if not CELLULAR_TRACEV3_BYTES.search(data):
            return

        self.files_scanned += 1
        self.bytes_scanned += len(data)
        self._record_source(self.cellular_files, path, path)
        for text in iter_printable_strings(data):
            if not CELLULAR_TRACEV3_TEXT.search(text):
                continue
            self._scan_string(path, text)

    def build_report(self) -> dict[str, Any]:
        return {
            "bytes_scanned": self.bytes_scanned,
            "cellular_files": _top_records(self.cellular_files, self.max_values),
            "cellular_files_count": len(self.cellular_files),
            "catalog_strings": _top_records(self.catalog_strings, self.max_values),
            "catalog_strings_count": len(self.catalog_strings),
            "decoder": "tracev3-string-catalog",
            "dynamic_arguments_decoded": False,
            "field_indicators": _top_records(self.field_indicators, self.max_values),
            "files_scanned": self.files_scanned,
            "limitations": (
                "Extracts printable tracev3 strings and format templates; encoded event arguments "
                "are not fully decoded yet."
            ),
            "plmns": _top_records(self.plmns, self.max_values),
            "private_field_templates": self.private_field_templates,
            "skipped_large_files": self.skipped_large_files,
            "structure": {
                "bytes_scanned": self.structure_bytes_scanned,
                "chunk_decoder": "tracev3-preamble-IIQ",
                "chunks": _top_records(self.tracev3_chunk_records, self.max_values),
                "firmware_basis": "LoggingSupport tracev3_chunk_preamble_s=IIQ",
                "header_strings": _top_records(self.tracev3_header_strings, self.max_values),
                "limitations": (
                    "Counts tracev3 chunk preambles and header/catalog strings; firehose event "
                    "arguments are not decoded."
                ),
                "malformed_files": self.tracev3_malformed_files,
                "tracev3_files": self.tracev3_files,
            },
            "templates": _top_records(self.templates, self.max_values),
            "tower_lookup_ready_templates": self.tower_lookup_ready_templates,
        }

    def _scan_structure(self, path: str, data: bytes) -> None:
        self.tracev3_files += 1
        self.structure_bytes_scanned += len(data)
        try:
            for chunk in iter_tracev3_chunks(data):
                key = f"{chunk.tag:04x}:{chunk.subtag:02x}"
                record = self.tracev3_chunk_records.setdefault(
                    key,
                    {
                        "bytes": 0,
                        "count": 0,
                        "name": TRACEV3_KNOWN_TAGS.get(chunk.tag, "unknown"),
                        "sources": [],
                        "subtag": f"0x{chunk.subtag:x}",
                        "tag": f"0x{chunk.tag:x}",
                        "value": f"0x{chunk.tag:x}/0x{chunk.subtag:x}",
                    },
                )
                record["bytes"] += chunk.payload_size
                record["count"] += 1
                _append_source(record["sources"], path, self.max_sources)
                if chunk.tag == TRACEV3_HEADER_TAG:
                    for text in iter_printable_strings(data[chunk.payload_offset : chunk.payload_end]):
                        if not _looks_like_tracev3_header_text(text):
                            continue
                        self._record_source(self.tracev3_header_strings, text, path, value=text)
        except ValueError:
            self.tracev3_malformed_files += 1

    def _scan_string(self, path: str, text: str) -> None:
        text = _clean_tracev3_string(text, include_sensitive=self.include_sensitive)
        if not text:
            return
        self._record_source(self.catalog_strings, text, path, value=text)

        for name, pattern in INDICATOR_PATTERNS.items():
            if pattern.search(text):
                self._record_source(self.field_indicators, name, path, value=name)

        for mcc, mnc in _iter_plmns(text):
            key = f"{mcc}-{mnc or 'unknown'}"
            record = self.plmns.setdefault(
                key,
                {
                    "count": 0,
                    "mcc": mcc,
                    "mnc": mnc,
                    "sources": [],
                    "value": key,
                },
            )
            record["count"] += 1
            _append_source(record["sources"], path, self.max_sources)

        if not _looks_like_log_template(text):
            return

        fields = _template_fields(text)
        if not fields:
            return

        key = text
        is_private = "%{private" in text or "%{sensitive" in text
        tower_lookup_ready = _tower_lookup_ready(fields)
        record = self.templates.setdefault(
            key,
            {
                "count": 0,
                "fields": fields,
                "private_fields": is_private,
                "sources": [],
                "tower_lookup_ready": tower_lookup_ready,
                "value": text,
            },
        )
        record["count"] += 1
        _append_source(record["sources"], path, self.max_sources)
        if record["count"] == 1 and is_private:
            self.private_field_templates += 1
        if record["count"] == 1 and tower_lookup_ready:
            self.tower_lookup_ready_templates += 1

    def _record_source(self, records: dict[str, dict[str, Any]], key: str, source: str, **extra: Any) -> None:
        record = records.setdefault(key, {"count": 0, "sources": [], **extra})
        record["count"] += 1
        _append_source(record["sources"], source, self.max_sources)


def is_logarchive_member(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    return "system_logs.logarchive/" in normalized or normalized.endswith(".logarchive")


def looks_like_tracev3(data: bytes) -> bool:
    if len(data) < TRACEV3_CHUNK_PREAMBLE_SIZE:
        return False
    tag, _subtag, payload_size = struct.unpack_from("<IIQ", data)
    return tag == TRACEV3_HEADER_TAG and payload_size <= len(data) - TRACEV3_CHUNK_PREAMBLE_SIZE


def iter_tracev3_chunks(data: bytes) -> Iterator[Tracev3Chunk]:
    offset = 0
    while offset + TRACEV3_CHUNK_PREAMBLE_SIZE <= len(data):
        tag, subtag, payload_size = struct.unpack_from("<IIQ", data, offset)
        payload_offset = offset + TRACEV3_CHUNK_PREAMBLE_SIZE
        payload_end = payload_offset + payload_size
        if tag == 0 or payload_end > len(data):
            raise ValueError("invalid tracev3 chunk preamble")
        yield Tracev3Chunk(
            offset=offset,
            payload_offset=payload_offset,
            payload_size=payload_size,
            subtag=subtag,
            tag=tag,
        )
        offset = _align8(payload_end)
    if offset != len(data):
        raise ValueError("truncated tracev3 chunk preamble")


def iter_printable_strings(data: bytes, *, min_length: int = 4) -> Iterator[str]:
    current = bytearray()
    for byte in data:
        if byte == 9 or 32 <= byte <= 126:
            current.append(32 if byte == 9 else byte)
            continue
        if len(current) >= min_length:
            yield current.decode("latin1", errors="ignore")
        current = bytearray()
    if len(current) >= min_length:
        yield current.decode("latin1", errors="ignore")


def _align8(value: int) -> int:
    return (value + 7) & ~7


def _looks_like_tracev3_header_text(text: str) -> bool:
    return bool(TRACEV3_HEADER_TEXT_PATTERN.match(text))


def _iter_plmns(text: str) -> list[tuple[str, Optional[str]]]:
    plmns: list[tuple[str, Optional[str]]] = []
    for match in MNC_MCC_DOMAIN_PATTERN.finditer(text):
        plmns.append((match.group("mcc"), match.group("mnc")))
    for match in MCC_MNC_PATTERN.finditer(text):
        plmns.append((match.group("mcc"), match.group("mnc")))
    if not plmns:
        for match in MCC_ONLY_PATTERN.finditer(text):
            plmns.append((match.group("mcc"), None))
    return plmns


def _clean_tracev3_string(text: str, *, include_sensitive: bool) -> str:
    text = " ".join(text.replace("\x00", " ").split())
    if not text:
        return ""
    if not include_sensitive:
        for pattern in RAW_FIELD_REDACTION_PATTERNS:
            text = pattern.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    if len(text) > MAX_TRACEV3_STRING_LENGTH:
        text = text[: MAX_TRACEV3_STRING_LENGTH - 1] + "..."
    return text


def _looks_like_log_template(text: str) -> bool:
    return bool(FORMAT_SPECIFIER_PATTERN.search(text))


def _template_fields(text: str) -> list[str]:
    return sorted(field for field, pattern in FIELD_PATTERNS.items() if pattern.search(text))


def _tower_lookup_ready(fields: list[str]) -> bool:
    return "mcc" in fields and "mnc" in fields and "cell_id" in fields and ("lac" in fields or "tac" in fields)


def _append_source(sources: list[str], source: str, limit: int) -> None:
    if source not in sources and len(sources) < limit:
        sources.append(source)


def _top_records(records: dict[str, dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    return [
        _copy_record(record)
        for record in sorted(records.values(), key=lambda item: (-item["count"], str(item.get("value", ""))))[:limit]
    ]


def _copy_record(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if value not in (None, [], {})}
