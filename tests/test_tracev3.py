import struct

from pymobiledevice3.tracev3 import Tracev3CatalogScanner, iter_printable_strings, iter_tracev3_chunks


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


def _tracev3_chunk(tag: int, payload: bytes, *, subtag: int = 0x11) -> bytes:
    chunk = struct.pack("<IIQ", tag, subtag, len(payload)) + payload
    return chunk + (b"\x00" * ((8 - (len(chunk) % 8)) % 8))
