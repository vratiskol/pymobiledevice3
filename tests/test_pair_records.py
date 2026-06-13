import base64
import plistlib

from pymobiledevice3.pair_records import (
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
