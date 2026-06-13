import json
import plistlib

from typer.testing import CliRunner

from pymobiledevice3 import __main__


def _write_remote_pair_record(folder, identifier="device-1"):
    (folder / f"remote_{identifier}.plist").write_bytes(
        plistlib.dumps({
            "public_key": b"public",
            "private_key": b"private",
            "remote_unlock_host_key": b"unlock",
        })
    )


def test_remote_pair_records_lists_local_records(tmp_path):
    _write_remote_pair_record(tmp_path)

    result = CliRunner().invoke(
        __main__.app,
        ["--no-color", "remote", "pair-records", "--pairing-records-cache-folder", str(tmp_path)],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload[0]["identifier"] == "device-1"
    assert payload[0]["has_private_key"] is True
    assert "record" not in payload[0]


def test_remote_pair_record_shows_missing_record(tmp_path):
    result = CliRunner().invoke(
        __main__.app,
        ["--no-color", "remote", "pair-record", "missing", "--pairing-records-cache-folder", str(tmp_path)],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["identifier"] == "missing"
    assert payload["exists"] is False
    assert payload["valid"] is False


def test_remote_delete_pair_dry_run(tmp_path):
    _write_remote_pair_record(tmp_path)

    result = CliRunner().invoke(
        __main__.app,
        [
            "--no-color",
            "remote",
            "delete-pair",
            "device-1",
            "--pairing-records-cache-folder",
            str(tmp_path),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["deleted"] is False
    assert payload["exists"] is True
