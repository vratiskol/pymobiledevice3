import hashlib
import plistlib

from pymobiledevice3.acquisition import (
    DIRECTORY_DIGEST_ALGORITHM,
    build_acquisition_manifest,
    build_device_context,
    classify_artifact,
)


def test_build_acquisition_manifest_summarizes_files_and_directories(tmp_path) -> None:
    file_path = tmp_path / "note.txt"
    file_path.write_bytes(b"hello")
    directory = tmp_path / "collection"
    directory.mkdir()
    nested = directory / "nested"
    nested.mkdir()
    (nested / "data.bin").write_bytes(b"abc")

    manifest = build_acquisition_manifest([file_path, directory])

    assert manifest["schema_version"] == 1
    assert "generated_at" in manifest
    assert manifest["artifacts"][0] == {
        "kind": "file",
        "modified_at": manifest["artifacts"][0]["modified_at"],
        "name": "note.txt",
        "path": str(file_path),
        "sha256": hashlib.sha256(b"hello").hexdigest(),
        "size": 5,
        "type": "file",
    }
    assert manifest["artifacts"][1] == {
        "digest_algorithm": DIRECTORY_DIGEST_ALGORITHM,
        "directory_count": 1,
        "file_count": 1,
        "kind": "directory",
        "modified_at": manifest["artifacts"][1]["modified_at"],
        "name": "collection",
        "path": str(directory),
        "sha256": manifest["artifacts"][1]["sha256"],
        "total_size": 3,
        "type": "directory",
    }


def test_build_acquisition_manifest_can_skip_hashes(tmp_path) -> None:
    file_path = tmp_path / "note.txt"
    file_path.write_bytes(b"hello")
    directory = tmp_path / "collection"
    directory.mkdir()
    (directory / "data.bin").write_bytes(b"abc")

    manifest = build_acquisition_manifest([file_path, directory], hash_files=False)

    assert "sha256" not in manifest["artifacts"][0]
    assert "sha256" not in manifest["artifacts"][1]
    assert "digest_algorithm" not in manifest["artifacts"][1]


def test_classify_artifact_detects_common_acquisition_artifacts(tmp_path) -> None:
    backup = tmp_path / "backup"
    backup.mkdir()
    for marker in ("Info.plist", "Manifest.plist", "Status.plist"):
        (backup / marker).write_bytes(b"")
    backup_root = tmp_path / "backup-root"
    backup_root.mkdir()
    nested_backup = backup_root / "device-udid"
    nested_backup.mkdir()
    for marker in ("Info.plist", "Manifest.plist", "Status.plist"):
        (nested_backup / marker).write_bytes(b"")
    crash = tmp_path / "panic-full.ips"
    crash.write_text("{}")
    sysdiagnose = tmp_path / "sysdiagnose_2026.tar.gz"
    sysdiagnose.write_bytes(b"archive")
    dotted_sysdiagnose = tmp_path / "sysdiagnose_2026.06.12_17-45-46+0200_iPhone-OS_iPhone_23F77.tar.gz"
    dotted_sysdiagnose.write_bytes(b"archive")
    sysdiagnose_json_report = tmp_path / "sysdiagnose_report.json"
    sysdiagnose_json_report.write_text("{}")

    assert classify_artifact(backup) == "itunes_backup"
    assert classify_artifact(backup_root) == "itunes_backup_root"
    assert classify_artifact(crash) == "crash_report"
    assert classify_artifact(sysdiagnose) == "sysdiagnose_archive"
    assert classify_artifact(dotted_sysdiagnose) == "sysdiagnose_archive"
    assert classify_artifact(sysdiagnose_json_report) == "file"


def test_classify_artifact_detects_forensic_collection_artifacts(tmp_path) -> None:
    packet_capture = tmp_path / "device-traffic.pcapng"
    packet_capture.write_bytes(b"pcap")
    legacy_packet_capture = tmp_path / "device-traffic.pcap"
    legacy_packet_capture.write_bytes(b"pcap")
    logarchive = tmp_path / "system_logs.logarchive"
    logarchive.mkdir()
    (logarchive / "logdata").write_bytes(b"log")
    file_relay_archive = tmp_path / "CrashReporter.cpio.gz"
    file_relay_archive.write_bytes(b"archive")
    diagnostics_archive = tmp_path / "os_trace_2026.tar"
    diagnostics_archive.write_bytes(b"archive")
    dotted_diagnostics_archive = tmp_path / "diagnostics_2026.06.12.tar.gz"
    dotted_diagnostics_archive.write_bytes(b"archive")
    mobilebackup_domains = tmp_path / "Domains.plist"
    with mobilebackup_domains.open("wb") as out:
        plistlib.dump({"SystemDomains": {}, "Version": "24.0"}, out)
    generic_domains = tmp_path / "OtherDomains.plist"
    with generic_domains.open("wb") as out:
        plistlib.dump({"Domains": {}}, out)

    assert classify_artifact(packet_capture) == "packet_capture"
    assert classify_artifact(legacy_packet_capture) == "packet_capture"
    assert classify_artifact(logarchive) == "logarchive"
    assert classify_artifact(file_relay_archive) == "file_relay_archive"
    assert classify_artifact(diagnostics_archive) == "diagnostics_archive"
    assert classify_artifact(dotted_diagnostics_archive) == "diagnostics_archive"
    assert classify_artifact(mobilebackup_domains) == "mobilebackup_domains_plist"
    assert classify_artifact(generic_domains) == "plist"


def test_build_device_context_redacts_identifiers_by_default() -> None:
    values = {
        "BuildVersion": "23A000",
        "DeviceClass": "iPhone",
        "DeviceName": "Example iPhone",
        "ProductType": "iPhone99,9",
        "ProductVersion": "26.0",
        "SerialNumber": "SERIAL",
        "UniqueChipID": 123,
        "UniqueDeviceID": "UDID",
    }

    assert build_device_context(values) == {
        "build_version": "23A000",
        "device_class": "iPhone",
        "product_type": "iPhone99,9",
        "product_version": "26.0",
    }
    assert build_device_context(values, include_identifiers=True) == {
        "build_version": "23A000",
        "device_class": "iPhone",
        "device_name": "Example iPhone",
        "product_type": "iPhone99,9",
        "product_version": "26.0",
        "serial_number": "SERIAL",
        "unique_chip_id": 123,
        "unique_device_id": "UDID",
    }
