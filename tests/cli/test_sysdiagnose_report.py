import json
import plistlib
from pathlib import Path

from typer.testing import CliRunner

from pymobiledevice3 import __main__


def test_crash_sysdiagnose_report_cli_writes_json(tmp_path: Path) -> None:
    sysdiagnose = tmp_path / "sysdiagnose"
    sysdiagnose.mkdir()
    (sysdiagnose / "cellular.log").write_text("carrier name: Test Carrier\nMCC=310 MNC=260 RAT=LTE\n")
    trace_dir = sysdiagnose / "system_logs.logarchive" / "Persist"
    trace_dir.mkdir(parents=True)
    (trace_dir / "0000000000000001.tracev3").write_bytes(
        b'{"msg":"#nilr,#supl,locationId","mcc":%{public}d,"mnc":%{public}d,"ci":%{public}d,"tac":%{public}d}'
    )
    (sysdiagnose / "SystemVersion.plist").write_bytes(
        plistlib.dumps({
            "BuildVersion": "24A000",
            "ProductType": "iPhone99,9",
            "ProductVersion": "27.0",
        })
    )
    output = tmp_path / "report.json"

    result = CliRunner().invoke(__main__.app, ["crash", "sysdiagnose-report", str(sysdiagnose), "--output", str(output)])

    assert result.exit_code == 0, result.output
    report = json.loads(output.read_text())
    assert report["archive"]["type"] == "directory"
    assert report["device"]["product_version"] == "27.0"
    assert report["gsm"]["providers"][0]["value"] == "Test Carrier"
    assert report["gsm"]["plmns"][0]["country"] == "United States"
    assert report["gsm"]["unified_log"]["files_scanned"] == 1
    assert report["gsm"]["unified_log"]["tower_lookup_ready_templates"] == 1
