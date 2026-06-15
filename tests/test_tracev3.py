import struct
import uuid

from pymobiledevice3.tracev3 import (
    Tracev3CatalogScanner,
    decode_apple_compression_header,
    decode_tracev3_firehose_payload,
    decode_tracev3_format_values,
    decode_tracev3_header,
    iter_printable_strings,
    iter_tracev3_chunks,
)


def test_iter_printable_strings_extracts_binary_catalog_strings() -> None:
    data = b"\x00abc\x00#nilr,#supl,locationId mcc=%d mnc=%d ci=%d tac=%d\x00tail"

    assert list(iter_printable_strings(data)) == ["#nilr,#supl,locationId mcc=%d mnc=%d ci=%d tac=%d", "tail"]


def test_iter_tracev3_chunks_uses_payload_size_and_alignment() -> None:
    data = _tracev3_chunk(0x1000, b"23F77\x00D37AP\x00") + _tracev3_chunk(0x600B, b"catalog")

    chunks = list(iter_tracev3_chunks(data))

    assert [(chunk.tag, chunk.subtag, chunk.payload_size) for chunk in chunks] == [
        (0x1000, 0x11, 12),
        (0x600B, 0x11, 7),
    ]


def test_tracev3_catalog_scanner_reports_cellular_templates_and_plmn() -> None:
    scanner = Tracev3CatalogScanner()
    payload = (
        _tracev3_chunk(0x1000, b"23F77\x00D37AP\x00/var/db/timezone/zoneinfo/Europe/Paris\x00")
        + _tracev3_chunk(
            0x600B,
            b"\x00".join([
                b"mnc020.mcc208.3gppnetwork.org",
                b'{"msg":"#nilr,#supl,locationId","cellType":%{public}s,"mcc":%{public}d,'
                b'"mnc":%{public}d,"ci":%{public}d,"physCellId":%{public}d,"tac":%{public}d}',
            ]),
        )
        + _tracev3_chunk(
            0x600D,
            b"#timingadvance,SimInstance,%{public}d,LTE Cell Info,mcc,%{private}hu,mnc,%{private}d,"
            b"tac,%{public}u,cellid,%{public}d,pci,%{public}d",
        )
    )

    scanner.scan_payload("system_logs.logarchive/Persist/0000000000000001.tracev3", payload)
    report = scanner.build_report()

    assert report["files_scanned"] == 1
    assert report["structure"]["tracev3_files"] == 1
    assert {chunk["tag"] for chunk in report["structure"]["chunks"]} == {"0x1000", "0x600b", "0x600d"}
    assert report["plmns"][0]["mcc"] == "208"
    assert report["plmns"][0]["mnc"] == "020"
    assert report["dynamic_arguments_decoded"] is False
    assert report["private_field_templates"] == 1
    assert report["tower_lookup_ready_templates"] == 2
    assert report["templates"][0]["tower_lookup_ready"] is True


def test_tracev3_catalog_scanner_redacts_raw_cell_values_by_default() -> None:
    scanner = Tracev3CatalogScanner()
    scanner.scan_payload(
        "system_logs.logarchive/logdata.LiveData.tracev3",
        b"CELL_LOC CellID=123456789 MCC=208 MNC=020",
    )

    report = scanner.build_report()

    assert "123456789" not in str(report)
    assert "<redacted>" in str(report)


def test_decode_tracev3_header_values_and_subchunks() -> None:
    generation = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
    payload = (
        struct.pack("<IIQqiiiI", 125, 3, 3453446222865, 1781279086, 554385, -60, 1, 1)
        + _tracev3_subchunk(0x6100, struct.pack("<Q", 15014814783115))
        + _tracev3_subchunk(0x6101, struct.pack("<ii", 16777228, 2) + _fixed_string("23F77", 16) + _fixed_string("D37AP", 32))
        + _tracev3_subchunk(0x6102, generation.bytes + struct.pack("<ii", 33, 0))
        + _tracev3_subchunk(0x6103, _fixed_string("/var/db/timezone/zoneinfo/Europe/Paris", 48))
    )

    header = decode_tracev3_header(payload)

    assert header["timebase"] == {"denom": 3, "numer": 125}
    assert header["wall_time"]["utc"] == "2026-06-12T15:44:46.554385+00:00"
    assert header["timezone"]["name"] == "Europe/Paris"
    assert header["system"]["build"] == "23F77"
    assert header["system"]["hardware"] == "D37AP"
    assert header["generation"]["uuid"].startswith("sha256_12:")
    assert str(generation) not in str(header)


def test_decode_apple_compression_header_reports_bv41_sizes() -> None:
    payload = struct.pack("<4sII", b"bv41", 64432, 16264) + b"\x00" * 16268

    header = decode_apple_compression_header(payload)

    assert header is not None
    assert header["algorithm"] == "COMPRESSION_LZ4"
    assert header["compressed_size"] == 16264
    assert header["payload_size_delta"] == 4
    assert header["uncompressed_size"] == 64432


def test_decode_tracev3_firehose_payload_decodes_uncompressed_header_and_templates() -> None:
    payload = struct.pack("<QIBB2s", 1234, 5678, 2, 3, b"\x00\x00") + b"mcc=%{public}d mnc=%{private}hu\x00"

    decoded = decode_tracev3_firehose_payload(payload)

    assert decoded["compressed"] is False
    assert decoded["header"]["mach_continuous_time"] == 1234
    assert decoded["header"]["thread_identifier"] == 5678
    assert decoded["header"]["log_type"] == 2
    assert decoded["template_count"] == 1
    assert decoded["templates"][0]["arguments"][1]["privacy"] == "private"


def test_decode_tracev3_firehose_payload_decompresses_bv41() -> None:
    decompressed = struct.pack("<QIBB2s", 1234, 5678, 2, 3, b"\x00\x00") + b"mcc=%{public}d\x00"
    compressed = _lz4_literal_only(decompressed)
    payload = struct.pack("<4sII", b"bv41", len(decompressed), len(compressed)) + compressed + b"\x00\x00\x00\x00"

    decoded = decode_tracev3_firehose_payload(payload)

    assert decoded["compressed"] is True
    assert decoded["decompressed"] is True
    assert decoded["decompressed_size"] == len(decompressed)
    assert decoded["header"]["mach_continuous_time"] == 1234
    assert decoded["template_count"] == 1


def test_decode_tracev3_format_values_decodes_scalars_and_redacts_private_values() -> None:
    template = "mcc=%{public}d mnc=%{private}hu carrier=%{public}s ok=%{public}B"
    payload = struct.pack("<iH", 208, 20) + b"ExampleCarrier\x00" + b"\x01"

    redacted = decode_tracev3_format_values(template, payload)
    sensitive = decode_tracev3_format_values(template, payload, include_sensitive=True)

    assert redacted["decoded_count"] == 4
    assert redacted["arguments"][0]["value"] == 208
    assert redacted["arguments"][1]["value"] == "<redacted>"
    assert redacted["arguments"][2]["value"] == "ExampleCarrier"
    assert redacted["arguments"][3]["value"] is True
    assert sensitive["arguments"][1]["value"] == 20


def _tracev3_chunk(tag: int, payload: bytes, *, subtag: int = 0x11) -> bytes:
    chunk = struct.pack("<IIQ", tag, subtag, len(payload)) + payload
    return chunk + (b"\x00" * ((8 - (len(chunk) % 8)) % 8))


def _tracev3_subchunk(tag: int, payload: bytes) -> bytes:
    chunk = struct.pack("<II", tag, len(payload)) + payload
    return chunk + (b"\x00" * ((8 - (len(chunk) % 8)) % 8))


def _fixed_string(value: str, size: int) -> bytes:
    data = value.encode()
    return data + (b"\x00" * (size - len(data)))


def _lz4_literal_only(value: bytes) -> bytes:
    if len(value) < 15:
        return bytes([len(value) << 4]) + value
    remaining = len(value) - 15
    extension = bytearray()
    while remaining >= 255:
        extension.append(255)
        remaining -= 255
    extension.append(remaining)
    return b"\xf0" + bytes(extension) + value
