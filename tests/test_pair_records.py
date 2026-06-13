import base64
import plistlib

from pymobiledevice3.pair_records import (
    delete_remote_pairing_record,
    get_remote_pairing_record_path,
    get_remote_pairing_record_summary,
    iter_remote_paired_identifiers,
    list_remote_pairing_record_summaries,
)


def _write_remote_pair_record(folder, identifier="device-1"):
    path = folder / f"remote_{identifier}.plist"
    path.write_bytes(
        plistlib.dumps({
            "public_key": b"public",
            "private_key": b"private",
            "remote_unlock_host_key": b"unlock",
        })
    )
    return path


def test_remote_pairing_record_summary_redacts_secrets_by_default(tmp_path):
    _write_remote_pair_record(tmp_path)

    summary = get_remote_pairing_record_summary("device-1", pairing_records_cache_folder=tmp_path)

    assert summary["identifier"] == "device-1"
    assert summary["valid"] is True
    assert summary["public_key"]["length"] == 6
    assert summary["has_private_key"] is True
    assert "record" not in summary
    assert "base64" not in summary["private_key"]


def test_remote_pairing_record_summary_can_include_secrets(tmp_path):
    _write_remote_pair_record(tmp_path)

    summary = get_remote_pairing_record_summary(
        "device-1",
        pairing_records_cache_folder=tmp_path,
        include_secrets=True,
    )

    assert summary["record"]["private_key"]["base64"] == base64.b64encode(b"private").decode()


def test_list_remote_pairing_records_and_identifiers(tmp_path):
    _write_remote_pair_record(tmp_path, "device-b")
    _write_remote_pair_record(tmp_path, "device-a")

    summaries = list_remote_pairing_record_summaries(tmp_path, include_path=False)

    assert [summary["identifier"] for summary in summaries] == ["device-a", "device-b"]
    assert list(iter_remote_paired_identifiers(tmp_path)) == ["device-a", "device-b"]
    assert "path" not in summaries[0]


def test_delete_remote_pairing_record(tmp_path):
    _write_remote_pair_record(tmp_path)
    path = get_remote_pairing_record_path("device-1", pairing_records_cache_folder=tmp_path)

    result = delete_remote_pairing_record("device-1", pairing_records_cache_folder=tmp_path)

    assert result["deleted"] is True
    assert not path.exists()


def test_delete_remote_pairing_record_dry_run(tmp_path):
    path = _write_remote_pair_record(tmp_path)

    result = delete_remote_pairing_record("device-1", pairing_records_cache_folder=tmp_path, dry_run=True)

    assert result["deleted"] is False
    assert path.exists()
