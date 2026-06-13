import json
import plistlib

from typer.testing import CliRunner

from pymobiledevice3 import __main__


def _write_lockdown_pair_record(folder, identifier="device-1"):
    (folder / f"{identifier}.plist").write_bytes(
        plistlib.dumps({
            "EscrowBag": b"escrow",
            "HostID": "host-id",
            "HostPrivateKey": b"private-key",
            "SystemBUID": "system-buid",
            "WiFiMACAddress": "00:11:22:33:44:55",
        })
    )


def test_lockdown_pair_records_lists_local_records(tmp_path):
    _write_lockdown_pair_record(tmp_path)

    result = CliRunner().invoke(
        __main__.app,
        [
            "--no-color",
            "lockdown",
            "pair-records",
            "--pairing-records-cache-folder",
            str(tmp_path),
            "--no-include-itunes",
            "--no-include-path",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload[0]["identifier"] == "device-1"
    assert payload[0]["source"] == "local"
    assert payload[0]["has_host_private_key"] is True
    assert "path" not in payload[0]
    assert "record" not in payload[0]


def test_lockdown_pair_record_shows_missing_record(tmp_path):
    result = CliRunner().invoke(
        __main__.app,
        [
            "--no-color",
            "lockdown",
            "pair-record",
            "missing",
            "--pairing-records-cache-folder",
            str(tmp_path),
            "--no-include-itunes",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["identifier"] == "missing"
    assert payload["exists"] is False
    assert payload["records"] == []


def test_lockdown_delete_pair_record_dry_run(tmp_path):
    _write_lockdown_pair_record(tmp_path)

    result = CliRunner().invoke(
        __main__.app,
        [
            "--no-color",
            "lockdown",
            "delete-pair-record",
            "device-1",
            "--pairing-records-cache-folder",
            str(tmp_path),
            "--dry-run",
            "--no-include-path",
        ],
    )

    assert result.exit_code == 0, result.output
    assert (tmp_path / "device-1.plist").exists()
    payload = json.loads(result.output)
    assert payload["identifier"] == "device-1"
    assert payload["deleted"] is False
    assert payload["dry_run"] is True
    assert payload["records"][0]["source"] == "local"
    assert "path" not in payload["records"][0]


def test_lockdown_delete_pair_record_deletes_local_record(tmp_path):
    _write_lockdown_pair_record(tmp_path)

    result = CliRunner().invoke(
        __main__.app,
        [
            "--no-color",
            "lockdown",
            "delete-pair-record",
            "device-1",
            "--pairing-records-cache-folder",
            str(tmp_path),
            "--no-include-path",
        ],
    )

    assert result.exit_code == 0, result.output
    assert not (tmp_path / "device-1.plist").exists()
    payload = json.loads(result.output)
    assert payload["deleted"] is True
    assert payload["records"][0]["deleted"] is True


def test_lockdown_delete_pair_record_missing_ok(tmp_path):
    result = CliRunner().invoke(
        __main__.app,
        [
            "--no-color",
            "lockdown",
            "delete-pair-record",
            "missing",
            "--pairing-records-cache-folder",
            str(tmp_path),
            "--missing-ok",
            "--no-include-path",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["identifier"] == "missing"
    assert payload["deleted"] is False
    assert payload["records"][0]["exists"] is False


def test_lockdown_delete_pair_record_missing_fails(tmp_path):
    result = CliRunner().invoke(
        __main__.app,
        [
            "--no-color",
            "lockdown",
            "delete-pair-record",
            "missing",
            "--pairing-records-cache-folder",
            str(tmp_path),
        ],
    )

    assert result.exit_code != 0
    assert "pair record not found: missing" in result.output
