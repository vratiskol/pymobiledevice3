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
