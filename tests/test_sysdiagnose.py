import plistlib
import struct
import tarfile
from pathlib import Path

from pymobiledevice3.sysdiagnose import analyze_sysdiagnose


def _tracev3_chunk(tag: int, payload: bytes, *, subtag: int = 0x11) -> bytes:
    padding = b"\x00" * ((8 - (len(payload) % 8)) % 8)
    return struct.pack("<IIQ", tag, subtag, len(payload)) + payload + padding


def _tracev3_header(*, mach_time: int = 1_000_000_000, unix_seconds: int = 1_700_000_000) -> bytes:
    return struct.pack("<IIQqiiiI", 1, 1, mach_time, unix_seconds, 0, 0, 0, 0)


def _cell_monitor_firehose(mach_time: int, fields: list[bytes]) -> bytes:
    return _tracev3_chunk(
        0x600D,
        struct.pack("<QIBB2s", mach_time, 5678, 2, 3, b"\x00\x00") + b"\x00".join(fields) + b"\x00",
    )


def _write_sample_sysdiagnose(root: Path) -> None:
    commcenter = root / "logs" / "CommCenter"
    commcenter.mkdir(parents=True)
    (commcenter / "cellular.log").write_text(
        "\n".join([
            "carrier name: Orange F",
            "MCC=208 MNC=01 TAC=12345 CellID=67890 PCI=42 RAT=LTE",
            "latitude=48.856600 longitude=2.352200",
            "IMSI: 208011234567890",
            "ICCID: 8933012345678901234",
            "MSISDN: +33 1 23 45 67 89",
        ])
    )
    (root / "SystemVersion.plist").write_bytes(
        plistlib.dumps({
            "BuildVersion": "24A000",
            "ProductType": "iPhone99,9",
            "ProductVersion": "27.0",
        })
    )
    crash_dir = root / "private" / "var" / "mobile" / "Library" / "Logs" / "CrashReporter"
    crash_dir.mkdir(parents=True)
    (crash_dir / "panic-full.ips").write_text("{}")
    trace_dir = root / "system_logs.logarchive" / "C0"
    trace_dir.mkdir(parents=True)
    (trace_dir / "trace-chunk").write_bytes(
        b"\x00".join([
            b"mnc020.mcc208.3gppnetwork.org",
            b'{"msg":"#nilr,#supl,locationId","cellType":%{public}s,"mcc":%{public}d,'
            b'"mnc":%{public}d,"ci":%{public}d,"physCellId":%{public}d,"tac":%{public}d}',
        ])
    )


def test_analyze_sysdiagnose_reports_forensic_gsm_statistics(tmp_path: Path) -> None:
    _write_sample_sysdiagnose(tmp_path)

    report = analyze_sysdiagnose(tmp_path)

    assert report["archive"]["type"] == "directory"
    assert report["device"] == {
        "build_version": "24A000",
        "product_type": "iPhone99,9",
        "product_version": "27.0",
    }
    assert report["artifact_categories"]["cellular"]["count"] == 1
    assert report["artifact_categories"]["crash"]["count"] == 1
    assert report["gsm"]["providers"][0]["value"] == "Orange F"
    assert report["gsm"]["plmns"][0]["mcc"] == "208"
    assert report["gsm"]["plmns"][0]["mnc"] == "01"
    assert report["gsm"]["plmns"][0]["country"] == "France"
    assert report["gsm"]["geo"]["mcc_countries"][0]["value"] == "France"
    assert report["gsm"]["geo"]["coordinates"]["redacted"] is True
    assert report["gsm"]["geo"]["coordinates"]["unique_count"] == 1
    assert report["gsm"]["identifiers"]["imsi"][0]["value"]["redacted"] is True
    assert report["gsm"]["phone_numbers"][0]["value"]["redacted"] is True
    assert report["gsm"]["radio_access_technologies"][0]["value"] == "LTE"
    assert report["gsm"]["cell_towers"][0]["cell_id"] == "67890"
    assert report["gsm"]["unified_log"]["files_scanned"] == 1
    assert report["gsm"]["unified_log"]["plmns"][0]["mcc"] == "208"
    assert report["gsm"]["unified_log"]["plmns"][0]["mnc"] == "020"
    assert report["gsm"]["unified_log"]["tower_lookup_ready_templates"] == 1


def test_analyze_sysdiagnose_can_include_sensitive_values(tmp_path: Path) -> None:
    _write_sample_sysdiagnose(tmp_path)

    report = analyze_sysdiagnose(tmp_path, include_sensitive=True)

    assert report["privacy"]["include_sensitive"] is True
    assert report["gsm"]["identifiers"]["imsi"][0]["value"] == "208011234567890"
    assert report["gsm"]["phone_numbers"][0]["value"] == "+33123456789"
    assert report["gsm"]["geo"]["coordinates"][0]["latitude"] == 48.8566
    assert report["gsm"]["geo"]["coordinates"][0]["longitude"] == 2.3522


def test_analyze_sysdiagnose_enriches_cell_towers_from_csv_database(tmp_path: Path) -> None:
    _write_sample_sysdiagnose(tmp_path)
    cell_db = tmp_path / "cells.csv"
    cell_db.write_text(
        "\n".join([
            "radio,mcc,net,area,cell,unit,lon,lat,range,samples,changeable,created,updated,averageSignal",
            "LTE,208,1,12345,67890,,2.352200,48.856600,125,4,1,1710000000,1710000100,-80",
        ])
    )

    report = analyze_sysdiagnose(tmp_path, cell_db=cell_db, include_sensitive=True)

    assert report["gsm"]["cell_database"] == {
        "format": "csv",
        "lookups": 1,
        "matched_towers": 1,
        "matches": 1,
        "path": str(cell_db),
        "rows_scanned": 1,
    }
    assert report["gsm"]["cell_towers"][0]["cell_database_match"] == {
        "area": "12345",
        "average_signal": "-80",
        "cell": "67890",
        "changeable": "1",
        "created": "1710000000",
        "latitude": 48.8566,
        "longitude": 2.3522,
        "mcc": "208",
        "mnc": "1",
        "radio": "LTE",
        "range": "125",
        "samples": "4",
        "updated": "1710000100",
    }


def test_analyze_sysdiagnose_builds_unified_timeline_from_text_events(tmp_path: Path) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "events.log").write_text(
        "\n".join([
            "2026-06-12 17:46:01.100000 WiFi joined SSID Cafe BSSID aa:bb:cc:dd:ee:ff",
            "2026-06-12 17:46:02.200000 locationd latitude=48.856600 longitude=2.352200",
            "2026-06-12 17:46:03.300000 CommCenter MCC=208 MNC=20 TAC=30301 CellID=137096039 RAT=LTE",
            "2026-06-12 17:46:04.400000 VPN connected utun2 10.0.0.8",
            "2026-06-12 17:46:05.500000 device unlocked",
            "2026-06-12 17:46:06.600000 reboot requested",
        ])
    )

    report = analyze_sysdiagnose(tmp_path, include_sensitive=True)
    timeline = report["timeline"]

    assert timeline["available"] is True
    assert timeline["events_count"] == 6
    assert [event["category"] for event in timeline["events"]] == [
        "wifi",
        "location",
        "cellular",
        "vpn",
        "lock_state",
        "power",
    ]
    assert timeline["events"][1]["details"]["coordinate"] == {"latitude": 48.8566, "longitude": 2.3522}
    assert timeline["events"][2]["details"]["cellular"]["cell_id"] == "137096039"
    assert timeline["events"][3]["details"]["ip_addresses"] == ["10.0.0.8"]


def test_analyze_sysdiagnose_redacts_unified_timeline_evidence_by_default(tmp_path: Path) -> None:
    (tmp_path / "events.log").write_text(
        "2026-06-12 17:46:01.100000 WiFi BSSID aa:bb:cc:dd:ee:ff IP address 10.0.0.8 "
        "latitude=48.856600 longitude=2.352200 IMSI: 208011234567890\n"
    )

    report = analyze_sysdiagnose(tmp_path)
    event = report["timeline"]["events"][0]

    assert "aa:bb:cc:dd:ee:ff" not in event["evidence"]
    assert "10.0.0.8" not in event["evidence"]
    assert "48.856600" not in event["evidence"]
    assert "208011234567890" not in event["evidence"]
    assert event["details"] == {"coordinate": {"redacted": True}}


def test_analyze_sysdiagnose_flags_2g_downgrade_without_coordinates(tmp_path: Path) -> None:
    trace_dir = tmp_path / "system_logs.logarchive"
    trace_dir.mkdir()
    (trace_dir / "logdata.LiveData.tracev3").write_bytes(
        _tracev3_chunk(0x1000, _tracev3_header())
        + _cell_monitor_firehose(
            1_000_000_000,
            [
                b"kCTCellMonitorCellId = 137096039;",
                b"kCTCellMonitorCellRadioAccessTechnology = kCTCellMonitorRadioAccessTechnologyLTE;",
                b"kCTCellMonitorMCC = 208;",
                b"kCTCellMonitorMNC = 20;",
                b"kCTCellMonitorTAC = 30301;",
            ],
        )
        + _cell_monitor_firehose(
            2_000_000_000,
            [
                b"kCTCellMonitorCellId = 456;",
                b"kCTCellMonitorCellRadioAccessTechnology = kCTCellMonitorRadioAccessTechnologyGSM;",
                b"kCTCellMonitorLAC = 123;",
                b"kCTCellMonitorMCC = 208;",
                b"kCTCellMonitorMNC = 20;",
            ],
        )
    )

    report = analyze_sysdiagnose(tmp_path, include_sensitive=True)
    journey = report["gsm"]["journey"]

    assert journey["coordinates_optional"] is True
    assert journey["located_observations_count"] == 0
    assert journey["observations_count"] == 2
    assert journey["risk_level"] == "high"
    assert {
        (flag["type"], flag["severity"])
        for flag in journey["flags"]
    } >= {("rat_downgrade", "high")}
    assert {
        event["event_type"]
        for event in report["timeline"]["events"]
    } >= {"cellular_observation", "journey_rat_downgrade"}


def test_analyze_sysdiagnose_flags_impossible_cell_journey_speed(tmp_path: Path) -> None:
    trace_dir = tmp_path / "system_logs.logarchive"
    trace_dir.mkdir()
    (trace_dir / "logdata.LiveData.tracev3").write_bytes(
        _tracev3_chunk(0x1000, _tracev3_header())
        + _cell_monitor_firehose(
            1_000_000_000,
            [
                b"kCTCellMonitorCellId = 137096039;",
                b"kCTCellMonitorCellRadioAccessTechnology = kCTCellMonitorRadioAccessTechnologyLTE;",
                b"kCTCellMonitorMCC = 208;",
                b"kCTCellMonitorMNC = 20;",
                b"kCTCellMonitorTAC = 30301;",
            ],
        )
        + _cell_monitor_firehose(
            2_000_000_000,
            [
                b"kCTCellMonitorCellId = 137096295;",
                b"kCTCellMonitorCellRadioAccessTechnology = kCTCellMonitorRadioAccessTechnologyLTE;",
                b"kCTCellMonitorMCC = 208;",
                b"kCTCellMonitorMNC = 20;",
                b"kCTCellMonitorTAC = 30302;",
            ],
        )
    )
    cell_db = tmp_path / "cells.csv"
    cell_db.write_text(
        "\n".join([
            "radio,mcc,net,area,cell,unit,lon,lat,range,samples,changeable,created,updated,averageSignal",
            "LTE,208,20,30301,137096039,,2.352200,48.856600,100,4,1,1710000000,1710000100,-80",
            "LTE,208,20,30302,137096295,,-74.006000,40.712800,100,4,1,1710000000,1710000100,-80",
        ])
    )

    report = analyze_sysdiagnose(tmp_path, cell_db=cell_db, include_sensitive=True)
    journey = report["gsm"]["journey"]

    assert journey["located_observations_count"] == 2
    assert journey["segments"][0]["distance_available"] is True
    assert journey["segments"][0]["movement_flag"] == "impossible_speed"
    assert any(flag["type"] == "impossible_speed" for flag in journey["flags"])


def test_analyze_sysdiagnose_reads_tar_archives(tmp_path: Path) -> None:
    sample = tmp_path / "sample"
    sample.mkdir()
    _write_sample_sysdiagnose(sample)
    archive_path = tmp_path / "sysdiagnose.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(sample, arcname="sysdiagnose_test")

    report = analyze_sysdiagnose(archive_path)

    assert report["archive"]["type"] == "tar"
    assert report["gsm"]["providers"][0]["value"] == "Orange F"
    assert report["gsm"]["plmns"][0]["country"] == "France"
