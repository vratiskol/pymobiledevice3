import json

import pytest
from typer.testing import CliRunner

from pymobiledevice3 import __main__
from pymobiledevice3.cli.lockdown import build_cellular_info

pytestmark = [pytest.mark.cli]


class FakeServiceProvider:
    all_values = {
        "TelephonyCapability": True,
        "HasBaseband": True,
        "DataPlanCapability": True,
        "DualSIMActivationPolicyCapable": True,
        "SIMStatus": "kCTSIMSupportSIMStatusReady",
        "SIMStatus2": "kCTSIMSupportSIMStatusNotInserted",
        "SIMTrayStatus": "kCTSIMSupportSIMTrayPresent",
        "EUICCChipID": 5,
        "InternationalMobileEquipmentIdentity": "001122334455667",
        "InternationalMobileSubscriberIdentity": "208001234567890",
        "IntegratedCircuitCardIdentity": "8901000000000000000",
        "MobileEquipmentIdentifier": "A0000000000000",
        "PhoneNumber": "+15550101010",
        "BasebandFirmwareVersion": "1.00.00",
        "BasebandSerialNumber": "BB-SERIAL-TEST",
        "FirmwarePreflightInfo": {
            "ChipID": 123,
            "CertID": 456,
            "ChipSerialNo": "BB-PREFLIGHT-SERIAL",
            "Nonce": b"baseband-nonce",
            "EUICCChipID": 5,
            "EUICCCSN": "EID-TEST-89049032000000000000000000000000",
            "EUICCCertIdentifier": b"euicc-cert-id",
            "EUICCGoldNonce": b"euicc-gold-nonce",
            "EUICCMainNonce": b"euicc-main-nonce",
        },
    }


def test_build_cellular_info_redacts_sensitive_values_by_default():
    result = build_cellular_info(FakeServiceProvider())

    assert result["redacted"] is True
    assert result["summary"] == {
        "telephony_capability": True,
        "has_baseband": True,
        "data_plan_capability": True,
        "dual_sim_activation_policy_capable": True,
        "sim_status": "kCTSIMSupportSIMStatusReady",
        "sim_status2": "kCTSIMSupportSIMStatusNotInserted",
        "euicc_present": True,
    }
    assert result["lockdown"]["SIMStatus"] == "kCTSIMSupportSIMStatusReady"
    assert result["lockdown"]["InternationalMobileEquipmentIdentity"] == "<redacted>"
    assert result["lockdown"]["InternationalMobileSubscriberIdentity"] == "<redacted>"
    assert result["lockdown"]["IntegratedCircuitCardIdentity"] == "<redacted>"
    assert result["lockdown"]["PhoneNumber"] == "<redacted>"
    assert result["lockdown"]["BasebandSerialNumber"] == "<redacted>"
    assert result["firmware_preflight_info"]["EUICCChipID"] == 5
    assert result["firmware_preflight_info"]["EUICCCSN"] == "<redacted>"
    assert result["firmware_preflight_info"]["EUICCGoldNonce"] == "<redacted>"
    assert result["restore_tss_parameters"] == {
        "available": True,
        "source": "FirmwarePreflightInfo",
        "parameters": {
            "@eUICC,Ticket": True,
            "eUICC,ChipID": 5,
            "eUICC,EID": "<redacted>",
            "eUICC,RootKeyIdentifier": "<redacted>",
            "EUICCGoldNonce": "<redacted>",
            "EUICCMainNonce": "<redacted>",
        },
    }

    rendered = json.dumps(result, default=str)
    assert "001122334455667" not in rendered
    assert "208001234567890" not in rendered
    assert "8901000000000000000" not in rendered
    assert "EID-TEST" not in rendered
    assert "BB-PREFLIGHT-SERIAL" not in rendered


def test_build_cellular_info_can_include_sensitive_values():
    result = build_cellular_info(FakeServiceProvider(), include_sensitive=True)

    assert result["redacted"] is False
    assert result["lockdown"]["InternationalMobileEquipmentIdentity"] == "001122334455667"
    assert result["lockdown"]["InternationalMobileSubscriberIdentity"] == "208001234567890"
    assert result["lockdown"]["IntegratedCircuitCardIdentity"] == "8901000000000000000"
    assert result["lockdown"]["PhoneNumber"] == "+15550101010"
    assert result["firmware_preflight_info"]["EUICCCSN"] == "EID-TEST-89049032000000000000000000000000"
    assert result["restore_tss_parameters"]["parameters"]["eUICC,EID"] == (
        "EID-TEST-89049032000000000000000000000000"
    )


def test_lockdown_cellular_info_help():
    result = CliRunner().invoke(__main__.app, ["lockdown", "cellular-info", "--help"], env={"COLUMNS": "180"})

    assert result.exit_code == 0
    assert "--include-sensitive" in result.output
    assert "cellular" in result.output
