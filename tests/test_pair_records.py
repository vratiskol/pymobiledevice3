import base64
import plistlib

import pytest

from pymobiledevice3 import pair_records
from pymobiledevice3.pair_records import (
    delete_lockdown_pairing_record,
    describe_lockdown_pairing_record,
    get_local_pairing_record_path,
    get_lockdown_pairing_record_summary,
    list_lockdown_pairing_record_summaries,
)


def _write_lockdown_pair_record(folder, identifier="device-1"):
    path = folder / f"{identifier}.plist"
    path.write_bytes(
        plistlib.dumps({
            "DeviceCertificate": b"device-cert",
            "EscrowBag": b"escrow",
            "HostID": "host-id",
            "HostPrivateKey": b"private-key",
            "RootPrivateKey": b"root-private-key",
            "SystemBUID": "system-buid",
            "WiFiMACAddress": "00:11:22:33:44:55",
        })
    )
    return path


def test_lockdown_pairing_record_summary_redacts_secret_values_by_default(tmp_path):
    path = _write_lockdown_pair_record(tmp_path)

    summary = describe_lockdown_pairing_record(path, "local")

    assert summary["identifier"] == "device-1"
    assert summary["source"] == "local"
    assert summary["valid"] is True
    assert summary["has_escrow_bag"] is True
    assert summary["has_host_id"] is True
    assert summary["has_host_private_key"] is True
    assert summary["has_root_private_key"] is True
    assert summary["has_system_buid"] is True
    assert summary["has_wifi_mac_address"] is True
    assert summary["values"]["HostPrivateKey"]["length"] == len(b"private-key")
    assert "base64" not in summary["values"]["HostPrivateKey"]
    assert "record" not in summary


def test_lockdown_pairing_record_summary_can_include_secrets(tmp_path):
    path = _write_lockdown_pair_record(tmp_path)

    summary = describe_lockdown_pairing_record(path, "local", include_secrets=True)

    assert summary["record"]["HostPrivateKey"]["base64"] == base64.b64encode(b"private-key").decode()
    assert summary["record"]["HostID"]["value"] == "host-id"


def test_list_lockdown_pairing_records_skips_remote_records_and_sorts(tmp_path):
    _write_lockdown_pair_record(tmp_path, "device-b")
    _write_lockdown_pair_record(tmp_path, "device-a")
    (tmp_path / "remote_device-c.plist").write_bytes(plistlib.dumps({"private_key": b"remote"}))

    summaries = list_lockdown_pairing_record_summaries(tmp_path, include_itunes=False, include_path=False)

    assert [summary["identifier"] for summary in summaries] == ["device-a", "device-b"]
    assert [summary["source"] for summary in summaries] == ["local", "local"]
    assert "path" not in summaries[0]


def test_get_lockdown_pairing_record_summary_reports_missing_record(tmp_path):
    summary = get_lockdown_pairing_record_summary("missing", tmp_path, include_itunes=False)

    assert summary == {
        "identifier": "missing",
        "exists": False,
        "records": [],
    }


def test_get_local_pairing_record_path(tmp_path):
    assert get_local_pairing_record_path("device-1", tmp_path) == tmp_path / "device-1.plist"


def test_lockdown_pairing_record_summary_rejects_non_dictionary_plist(tmp_path):
    path = tmp_path / "device-1.plist"
    path.write_bytes(plistlib.dumps(["not", "a", "dict"]))

    summary = describe_lockdown_pairing_record(path, "local")

    assert summary["valid"] is False
    assert summary["error"] == "pair record is not a plist dictionary"


def test_delete_lockdown_pairing_record_dry_run(tmp_path):
    path = _write_lockdown_pair_record(tmp_path)

    result = delete_lockdown_pairing_record("device-1", tmp_path, dry_run=True, include_path=False)

    assert path.exists()
    assert result == {
        "identifier": "device-1",
        "exists": True,
        "deleted": False,
        "dry_run": True,
        "records": [
            {
                "identifier": "device-1",
                "source": "local",
                "exists": True,
                "deleted": False,
                "dry_run": True,
            }
        ],
    }


def test_delete_lockdown_pairing_record(tmp_path):
    path = _write_lockdown_pair_record(tmp_path)

    result = delete_lockdown_pairing_record("device-1", tmp_path, include_path=False)

    assert not path.exists()
    assert result["deleted"] is True
    assert result["records"][0]["deleted"] is True
    assert result["records"][0]["exists"] is False


def test_delete_lockdown_pairing_record_missing_ok(tmp_path):
    result = delete_lockdown_pairing_record("missing", tmp_path, missing_ok=True, include_path=False)

    assert result == {
        "identifier": "missing",
        "exists": False,
        "deleted": False,
        "dry_run": False,
        "records": [
            {
                "identifier": "missing",
                "source": "local",
                "exists": False,
                "deleted": False,
                "dry_run": False,
            }
        ],
    }


def test_delete_lockdown_pairing_record_missing_fails(tmp_path):
    with pytest.raises(FileNotFoundError):
        delete_lockdown_pairing_record("missing", tmp_path)


def test_delete_lockdown_pairing_record_does_not_include_itunes_by_default(monkeypatch: pytest.MonkeyPatch, tmp_path):
    local_path = _write_lockdown_pair_record(tmp_path)
    itunes_path = tmp_path / "itunes" / "device-1.plist"
    itunes_path.parent.mkdir()
    itunes_path.write_bytes(local_path.read_bytes())
    monkeypatch.setattr(pair_records, "get_itunes_pairing_record_path", lambda identifier: itunes_path)

    result = delete_lockdown_pairing_record("device-1", tmp_path, include_path=False)

    assert result["deleted"] is True
    assert not local_path.exists()
    assert itunes_path.exists()
    assert [record["source"] for record in result["records"]] == ["local"]


def test_delete_lockdown_pairing_record_can_include_itunes(monkeypatch: pytest.MonkeyPatch, tmp_path):
    local_path = _write_lockdown_pair_record(tmp_path)
    itunes_path = tmp_path / "itunes" / "device-1.plist"
    itunes_path.parent.mkdir()
    itunes_path.write_bytes(local_path.read_bytes())
    monkeypatch.setattr(pair_records, "get_itunes_pairing_record_path", lambda identifier: itunes_path)

    result = delete_lockdown_pairing_record("device-1", tmp_path, include_itunes=True, include_path=False)

    assert result["deleted"] is True
    assert not local_path.exists()
    assert not itunes_path.exists()
    assert [record["source"] for record in result["records"]] == ["local", "itunes"]
    assert all(record["deleted"] is True for record in result["records"])
