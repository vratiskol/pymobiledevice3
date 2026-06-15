import plistlib
import tarfile
from pathlib import Path

from pymobiledevice3.sysdiagnose import analyze_sysdiagnose


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
