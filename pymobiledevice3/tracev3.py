import ctypes
import ctypes.util
import hashlib
import platform
import re
import struct
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

DEFAULT_MAX_TRACEV3_FILE_BYTES = 16 * 1024 * 1024
MAX_SOURCES_PER_TRACEV3_FINDING = 5
MAX_TRACEV3_STRING_LENGTH = 320
TRACEV3_CHUNK_PREAMBLE_SIZE = 16
TRACEV3_CATALOG_TAG = 0x600B
TRACEV3_FIREHOSE_TAG = 0x600D
TRACEV3_FIREHOSE_HEADER_SIZE = struct.calcsize("<QIBB2s")
TRACEV3_HEADER_BASE_SIZE = struct.calcsize("<IIQqiiiI")
TRACEV3_HEADER_TAG = 0x1000
TRACEV3_LOG_SIMPLE_HEADER_SIZE = struct.calcsize("<QIB3s")
TRACEV3_KNOWN_TAGS = {
    TRACEV3_HEADER_TAG: "header",
    TRACEV3_CATALOG_TAG: "catalog",
    TRACEV3_FIREHOSE_TAG: "firehose",
}
TRACEV3_HEADER_SUBCHUNKS = {
    0x6100: "continuous",
    0x6101: "systeminfo",
    0x6102: "generation",
    0x6103: "timezone",
}
APPLE_COMPRESSION_ALGORITHMS = {
    b"bv41": {
        "algorithm": "COMPRESSION_LZ4",
        "compression_algorithm": 0x100,
        "format": "Apple Compression",
    },
    b"bvxn": {
        "algorithm": "COMPRESSION_LZVN",
        "compression_algorithm": 0x800,
        "format": "Apple Compression",
    },
    b"bvx1": {
        "algorithm": "LZFSE_COMPRESSEDV1",
        "format": "LZFSE",
    },
    b"bvx2": {
        "algorithm": "LZFSE_COMPRESSEDV2",
        "format": "LZFSE",
    },
    b"bvx-": {
        "algorithm": "LZFSE_UNCOMPRESSED",
        "format": "LZFSE",
    },
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
TRACEV3_FORMAT_ARGUMENT_PATTERN = re.compile(
    r"%(?!%)"
    r"(?:\{(?P<privacy>[^}]+)\})?"
    r"(?P<flags>[-+#0-9 .]*)"
    r"(?P<length>ll|hh|l|h|q|z|t|j)?"
    r"(?P<conversion>@|d|i|u|x|X|o|s|f|F|e|E|g|G|p|c|B)"
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
    """Best-effort Apple Unified Log tracev3 scanner.

    The scanner decodes tracev3 chunk preambles, file headers, catalog metadata,
    compression wrappers, uncompressed firehose headers, printable templates, and
    printf-style argument blobs when the argument bytes are available.
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
        self.tracev3_catalog_chunks: list[dict[str, Any]] = []
        self.tracev3_chunk_records: dict[str, dict[str, Any]] = {}
        self.tracev3_dynamic_arguments_decoded = 0
        self.tracev3_firehose_blocks: list[dict[str, Any]] = []
        self.tracev3_firehose_compressed = 0
        self.tracev3_firehose_decode_errors = 0
        self.tracev3_firehose_decompressed = 0
        self.tracev3_files = 0
        self.tracev3_headers: list[dict[str, Any]] = []
        self.tracev3_header_strings: dict[str, dict[str, Any]] = {}
        self.tracev3_malformed_files = 0
        self.tracev3_value_samples: list[dict[str, Any]] = []
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
            "decoder": "tracev3-structure-catalog-firehose",
            "dynamic_arguments_decoded": self.tracev3_dynamic_arguments_decoded > 0,
            "dynamic_arguments_decoded_count": self.tracev3_dynamic_arguments_decoded,
            "field_indicators": _top_records(self.field_indicators, self.max_values),
            "files_scanned": self.files_scanned,
            "limitations": (
                "Decodes tracev3 headers, catalog strings, compression wrappers, and "
                "uncompressed firehose payloads. Apple Compression firehose bodies require "
                "the platform decompressor before dynamic event arguments can be decoded."
            ),
            "plmns": _top_records(self.plmns, self.max_values),
            "private_field_templates": self.private_field_templates,
            "skipped_large_files": self.skipped_large_files,
            "structure": {
                "bytes_scanned": self.structure_bytes_scanned,
                "chunk_decoder": "tracev3-preamble-IIQ",
                "chunks": _top_records(self.tracev3_chunk_records, self.max_values),
                "catalogs": self.tracev3_catalog_chunks[: self.max_values],
                "compressed_firehose_blocks": self.tracev3_firehose_compressed,
                "decoded_values": self.tracev3_value_samples[: self.max_values],
                "decompressed_firehose_blocks": self.tracev3_firehose_decompressed,
                "firehose_blocks": self.tracev3_firehose_blocks[: self.max_values],
                "firehose_decode_errors": self.tracev3_firehose_decode_errors,
                "firmware_basis": "LoggingSupport tracev3_chunk_preamble_s=IIQ",
                "header_strings": _top_records(self.tracev3_header_strings, self.max_values),
                "headers": self.tracev3_headers[: self.max_values],
                "limitations": (
                    "The tracev3 structure is firmware-backed. Dynamic firehose event records "
                    "are decoded only when their payload is already uncompressed or the host "
                    "can provide Apple Compression decoding for bv41/bvxn bodies."
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
                    payload = data[chunk.payload_offset : chunk.payload_end]
                    if len(self.tracev3_headers) < self.max_values:
                        try:
                            header = decode_tracev3_header(payload, include_sensitive=self.include_sensitive)
                        except ValueError as e:
                            header = {"error": str(e), "payload_size": len(payload)}
                        header["source"] = path
                        self.tracev3_headers.append(header)
                    for text in iter_printable_strings(payload):
                        if not _looks_like_tracev3_header_text(text):
                            continue
                        self._record_source(self.tracev3_header_strings, text, path, value=text)
                elif chunk.tag == TRACEV3_CATALOG_TAG:
                    payload = data[chunk.payload_offset : chunk.payload_end]
                    catalog = decode_tracev3_catalog(payload, include_sensitive=self.include_sensitive)
                    catalog["source"] = path
                    if len(self.tracev3_catalog_chunks) < self.max_values:
                        self.tracev3_catalog_chunks.append(_truncate_tracev3_detail(catalog, self.max_values))
                    for text in catalog["strings"]:
                        if CELLULAR_TRACEV3_TEXT.search(text):
                            self._scan_string(path, text)
                elif chunk.tag == TRACEV3_FIREHOSE_TAG:
                    payload = data[chunk.payload_offset : chunk.payload_end]
                    firehose = decode_tracev3_firehose_payload(
                        payload,
                        include_sensitive=self.include_sensitive,
                        max_values=self.max_values,
                    )
                    firehose["source"] = path
                    if firehose.get("compressed"):
                        self.tracev3_firehose_compressed += 1
                    if firehose.get("decompressed"):
                        self.tracev3_firehose_decompressed += 1
                    if firehose.get("decode_error"):
                        self.tracev3_firehose_decode_errors += 1
                    self.tracev3_dynamic_arguments_decoded += firehose.get("dynamic_arguments_decoded", 0)
                    if len(self.tracev3_firehose_blocks) < self.max_values:
                        self.tracev3_firehose_blocks.append(_truncate_tracev3_detail(firehose, self.max_values))
                    for text in firehose.get("strings", []):
                        if CELLULAR_TRACEV3_TEXT.search(text):
                            self._scan_string(path, text)
                    for value in firehose.get("decoded_values", []):
                        if len(self.tracev3_value_samples) < self.max_values:
                            sample = dict(value)
                            sample["source"] = path
                            self.tracev3_value_samples.append(sample)
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


def decode_tracev3_header(payload: bytes, *, include_sensitive: bool = False) -> dict[str, Any]:
    if len(payload) < TRACEV3_HEADER_BASE_SIZE:
        raise ValueError("truncated tracev3 header")

    (
        timebase_numer,
        timebase_denom,
        mach_continuous_time,
        unix_time_seconds,
        unix_time_microseconds,
        timezone_minutes_west,
        timezone_dst,
        flags,
    ) = struct.unpack_from("<IIQqiiiI", payload)

    result: dict[str, Any] = {
        "flags": flags,
        "mach_continuous_time": mach_continuous_time,
        "subchunks": [],
        "timebase": {
            "denom": timebase_denom,
            "numer": timebase_numer,
        },
        "timezone": {
            "dst": timezone_dst,
            "minutes_west": timezone_minutes_west,
        },
        "wall_time": {
            "unix_microseconds": unix_time_microseconds,
            "unix_seconds": unix_time_seconds,
        },
    }
    utc = _utc_isoformat(unix_time_seconds, unix_time_microseconds)
    if utc is not None:
        result["wall_time"]["utc"] = utc

    offset = TRACEV3_HEADER_BASE_SIZE
    while offset + 8 <= len(payload):
        subtag, subchunk_size = struct.unpack_from("<II", payload, offset)
        subpayload_offset = offset + 8
        subpayload_end = subpayload_offset + subchunk_size
        if subpayload_end > len(payload):
            result["subchunks"].append({
                "error": "truncated",
                "payload_size": subchunk_size,
                "tag": f"0x{subtag:x}",
            })
            break
        subpayload = payload[subpayload_offset:subpayload_end]
        subchunk = {
            "name": TRACEV3_HEADER_SUBCHUNKS.get(subtag, "unknown"),
            "payload_size": subchunk_size,
            "tag": f"0x{subtag:x}",
        }
        result["subchunks"].append(subchunk)
        _decode_tracev3_header_subchunk(result, subtag, subpayload, include_sensitive=include_sensitive)
        offset = _align8(subpayload_end)
    return result


def decode_tracev3_catalog(payload: bytes, *, include_sensitive: bool = False) -> dict[str, Any]:
    strings = [
        _clean_tracev3_string(text, include_sensitive=include_sensitive)
        for text in iter_printable_strings(payload)
    ]
    strings = [text for text in strings if text]
    templates = [decode_tracev3_format_template(text) for text in strings if _looks_like_log_template(text)]
    catalog: dict[str, Any] = {
        "payload_size": len(payload),
        "string_count": len(strings),
        "strings": strings,
        "template_count": len(templates),
        "templates": templates,
    }
    if len(payload) >= 24:
        words = list(struct.unpack_from("<8H", payload))
        catalog.update({
            "format": "tracev3_chunk_catalog_v2_s",
            "header_words": words,
            "unknown_q": struct.unpack_from("<Q", payload, 16)[0],
        })
    elif len(payload) >= 8:
        catalog.update({
            "format": "tracev3_chunk_catalog_s",
            "header_words": list(struct.unpack_from("<4H", payload)),
        })
    else:
        catalog["format"] = "truncated"
    uuids = _iter_uuid_strings(payload, include_sensitive=include_sensitive)
    if uuids:
        catalog["uuids"] = uuids
    return catalog


def decode_tracev3_firehose_payload(
    payload: bytes,
    *,
    include_sensitive: bool = False,
    max_values: int = 50,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "payload_size": len(payload),
    }
    body = payload
    compression = decode_apple_compression_header(payload)
    if compression is not None:
        result["compressed"] = True
        result["compression"] = compression
        decoded = _decompress_tracev3_payload(payload, compression)
        if decoded is None:
            result["decode_status"] = "compressed_body_not_decoded"
            result["requires_decompressor"] = compression["algorithm"]
            return result
        result["decompressed"] = True
        result["decompressed_size"] = len(decoded)
        body = decoded
    else:
        result["compressed"] = False
        result["decompressed"] = False

    if len(body) < TRACEV3_FIREHOSE_HEADER_SIZE:
        result["decode_error"] = "truncated_firehose_header"
        return result

    header = decode_tracev3_firehose_header(body)
    result["header"] = header
    if not _looks_like_tracev3_firehose_header(header):
        result["decode_status"] = "unrecognized_uncompressed_firehose_header"
        result["dynamic_arguments_decoded"] = 0
        result["string_count"] = 0
        result["strings"] = []
        result["template_count"] = 0
        result["templates"] = []
        return result

    tail = body[TRACEV3_FIREHOSE_HEADER_SIZE:]
    strings = [
        _clean_tracev3_string(text, include_sensitive=include_sensitive)
        for text in iter_printable_strings(tail)
    ]
    strings = [text for text in strings if text]
    templates = [decode_tracev3_format_template(text) for text in strings if _looks_like_log_template(text)]
    result.update({
        "dynamic_arguments_decoded": 0,
        "string_count": len(strings),
        "strings": strings[:max_values],
        "template_count": len(templates),
        "templates": templates[:max_values],
    })
    return result


def decode_tracev3_firehose_header(payload: bytes) -> dict[str, Any]:
    if len(payload) < TRACEV3_FIREHOSE_HEADER_SIZE:
        raise ValueError("truncated tracev3 firehose header")
    mach_continuous_time, thread_identifier, log_type, flags, reserved = struct.unpack_from("<QIBB2s", payload)
    return {
        "flags": flags,
        "log_type": log_type,
        "mach_continuous_time": mach_continuous_time,
        "reserved": reserved.hex(),
        "thread_identifier": thread_identifier,
    }


def decode_apple_compression_header(payload: bytes) -> Optional[dict[str, Any]]:
    if len(payload) < 12:
        return None
    magic = payload[:4]
    algorithm = APPLE_COMPRESSION_ALGORITHMS.get(magic)
    if algorithm is None:
        return None
    uncompressed_size, compressed_size = struct.unpack_from("<II", payload, 4)
    available_payload_size = max(len(payload) - 12, 0)
    return {
        **algorithm,
        "available_payload_size": available_payload_size,
        "compressed_size": compressed_size,
        "magic": magic.decode("ascii", errors="replace"),
        "payload_size_delta": available_payload_size - compressed_size,
        "uncompressed_size": uncompressed_size,
    }


def decode_tracev3_format_template(template: str) -> dict[str, Any]:
    arguments = []
    for index, match in enumerate(TRACEV3_FORMAT_ARGUMENT_PATTERN.finditer(template)):
        conversion = match.group("conversion")
        length = match.group("length") or ""
        privacy = match.group("privacy") or "default"
        arguments.append({
            "conversion": conversion,
            "decoder": _format_value_decoder(length, conversion),
            "index": index,
            "length": length,
            "privacy": privacy,
            "specifier": match.group(0),
        })
    return {
        "argument_count": len(arguments),
        "arguments": arguments,
        "template": template,
    }


def decode_tracev3_format_values(
    template: str,
    payload: bytes,
    *,
    include_sensitive: bool = False,
) -> dict[str, Any]:
    template_info = decode_tracev3_format_template(template)
    arguments = []
    errors = []
    offset = 0
    for argument in template_info["arguments"]:
        try:
            value, offset = _decode_tracev3_format_value(argument, payload, offset)
        except ValueError as e:
            errors.append({
                "error": str(e),
                "index": argument["index"],
                "specifier": argument["specifier"],
            })
            break
        arguments.append({
            **argument,
            "value": _format_value_output(value, argument["privacy"], include_sensitive=include_sensitive),
        })
    return {
        "arguments": arguments,
        "consumed_bytes": offset,
        "decoded_count": len(arguments),
        "errors": errors,
        "template": template,
    }


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


def _decode_tracev3_header_subchunk(
    result: dict[str, Any],
    subtag: int,
    payload: bytes,
    *,
    include_sensitive: bool,
) -> None:
    if subtag == 0x6100 and len(payload) >= 8:
        result["continuous_time"] = struct.unpack_from("<Q", payload)[0]
    elif subtag == 0x6101 and len(payload) >= 56:
        unknown0, unknown1 = struct.unpack_from("<ii", payload)
        result["system"] = {
            "build": _read_c_string(payload[8:24]),
            "hardware": _read_c_string(payload[24:56]),
            "unknown0": unknown0,
            "unknown1": unknown1,
        }
    elif subtag == 0x6102 and len(payload) >= 24:
        generation_uuid = str(uuid.UUID(bytes=payload[:16]))
        unknown0, unknown1 = struct.unpack_from("<ii", payload, 16)
        result["generation"] = {
            "unknown0": unknown0,
            "unknown1": unknown1,
            "uuid": _sensitive_string(generation_uuid, include_sensitive=include_sensitive),
        }
    elif subtag == 0x6103 and payload:
        timezone_path = _read_c_string(payload)
        result["timezone"]["path"] = timezone_path
        prefix = "/var/db/timezone/zoneinfo/"
        if timezone_path.startswith(prefix):
            result["timezone"]["name"] = timezone_path[len(prefix):]


def _looks_like_tracev3_firehose_header(header: dict[str, Any]) -> bool:
    return (
        header["log_type"] <= 0x20
        and header["flags"] <= 0x7F
        and header["reserved"] in {"0000", "0100", "0001"}
    )


def _read_c_string(data: bytes) -> str:
    return data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _utc_isoformat(seconds: int, microseconds: int) -> Optional[str]:
    if not 0 <= microseconds < 1_000_000:
        return None
    try:
        return datetime.fromtimestamp(seconds + (microseconds / 1_000_000), tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def _sensitive_string(value: str, *, include_sensitive: bool) -> str:
    if include_sensitive:
        return value
    return "sha256_12:" + hashlib.sha256(value.encode()).hexdigest()[:12]


def _decompress_tracev3_payload(payload: bytes, compression: dict[str, Any]) -> Optional[bytes]:
    if compression.get("compression_algorithm") is not None:
        decoded = _decode_macos_compression(payload, compression)
        if decoded is not None:
            return decoded

    if compression.get("format") == "LZFSE":
        try:
            import lzfse  # type: ignore[import-not-found]
        except ImportError:
            return None
        try:
            return lzfse.decompress(payload)
        except Exception:
            return None
    return None


def _decode_macos_compression(payload: bytes, compression: dict[str, Any]) -> Optional[bytes]:
    if platform.system() != "Darwin":
        return None
    library_path = ctypes.util.find_library("compression") or "/usr/lib/libcompression.dylib"
    try:
        library = ctypes.CDLL(library_path)
    except OSError:
        return None

    dst_size = compression.get("uncompressed_size", 0)
    algorithm = compression.get("compression_algorithm")
    if not isinstance(dst_size, int) or dst_size <= 0 or not isinstance(algorithm, int):
        return None

    dst = ctypes.create_string_buffer(dst_size)
    src = ctypes.create_string_buffer(payload, len(payload))
    decode = library.compression_decode_buffer
    decode.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    decode.restype = ctypes.c_size_t
    decoded_size = decode(dst, dst_size, src, len(payload), None, algorithm)
    if decoded_size == 0:
        return None
    return dst.raw[:decoded_size]


def _iter_uuid_strings(payload: bytes, *, include_sensitive: bool, limit: int = 20) -> list[str]:
    values = []
    seen = set()
    for offset in range(0, max(len(payload) - 15, 0), 8):
        raw = payload[offset : offset + 16]
        if len(set(raw)) <= 1:
            continue
        candidate = uuid.UUID(bytes=raw)
        # UUID variant bits remove many random binary windows without assuming version.
        if candidate.variant != uuid.RFC_4122:
            continue
        text = str(candidate)
        if text in seen:
            continue
        seen.add(text)
        values.append(_sensitive_string(text, include_sensitive=include_sensitive))
        if len(values) >= limit:
            break
    return values


def _format_value_decoder(length: str, conversion: str) -> str:
    if conversion in {"d", "i"}:
        return f"signed{_integer_size(length) * 8}"
    if conversion in {"u", "x", "X", "o"}:
        return f"unsigned{_integer_size(length) * 8}"
    if conversion == "p":
        return "pointer"
    if conversion in {"f", "F", "e", "E", "g", "G"}:
        return "double"
    if conversion in {"s", "@"}:
        return "cstring"
    if conversion == "c":
        return "char"
    if conversion == "B":
        return "bool"
    return "unknown"


def _decode_tracev3_format_value(argument: dict[str, Any], payload: bytes, offset: int) -> tuple[Any, int]:
    conversion = argument["conversion"]
    length = argument["length"]
    if conversion in {"d", "i", "u", "x", "X", "o"}:
        size = _integer_size(length)
        signed = conversion in {"d", "i"}
        value = _read_integer(payload, offset, size=size, signed=signed)
        if conversion in {"x", "X", "o"}:
            value = hex(value) if conversion in {"x", "X"} else oct(value)
        return value, offset + size
    if conversion == "p":
        return hex(_read_integer(payload, offset, size=8, signed=False)), offset + 8
    if conversion in {"f", "F", "e", "E", "g", "G"}:
        if offset + 8 > len(payload):
            raise ValueError("truncated double")
        return struct.unpack_from("<d", payload, offset)[0], offset + 8
    if conversion in {"s", "@"}:
        value, end = _read_payload_c_string(payload, offset)
        return value, end
    if conversion == "c":
        if offset + 1 > len(payload):
            raise ValueError("truncated char")
        return chr(payload[offset]), offset + 1
    if conversion == "B":
        if offset + 1 > len(payload):
            raise ValueError("truncated bool")
        return bool(payload[offset]), offset + 1
    raise ValueError(f"unsupported conversion {conversion}")


def _integer_size(length: str) -> int:
    if length == "hh":
        return 1
    if length == "h":
        return 2
    if length in {"l", "ll", "q", "z", "t", "j"}:
        return 8
    return 4


def _read_integer(payload: bytes, offset: int, *, size: int, signed: bool) -> int:
    if offset + size > len(payload):
        raise ValueError(f"truncated {size}-byte integer")
    return int.from_bytes(payload[offset : offset + size], "little", signed=signed)


def _read_payload_c_string(payload: bytes, offset: int) -> tuple[str, int]:
    if offset >= len(payload):
        raise ValueError("truncated string")
    end = payload.find(b"\x00", offset)
    if end == -1:
        end = len(payload)
        next_offset = end
    else:
        next_offset = end + 1
    return payload[offset:end].decode("utf-8", errors="replace"), next_offset


def _format_value_output(value: Any, privacy: str, *, include_sensitive: bool) -> Any:
    privacy = privacy.lower()
    if include_sensitive or not ("private" in privacy or "sensitive" in privacy):
        return value
    if isinstance(value, str):
        return _sensitive_string(value, include_sensitive=False)
    return "<redacted>"


def _truncate_tracev3_detail(value: Any, limit: int) -> Any:
    if isinstance(value, dict):
        return {key: _truncate_tracev3_detail(item, limit) for key, item in value.items()}
    if isinstance(value, list) and len(value) <= 32 and not any(isinstance(item, (dict, list)) for item in value):
        return value
    if isinstance(value, list) and len(value) > limit:
        return [_truncate_tracev3_detail(item, limit) for item in value[:limit]] + [{"truncated_count": len(value) - limit}]
    return value


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
