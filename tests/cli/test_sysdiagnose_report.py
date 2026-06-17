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


def test_crash_sysdiagnose_report_cli_accepts_cell_database(tmp_path: Path) -> None:
    sysdiagnose = tmp_path / "sysdiagnose"
    sysdiagnose.mkdir()
    (sysdiagnose / "cellular.log").write_text("MCC=208 MNC=20 TAC=30301 CellID=137096039 RAT=LTE\n")
    cell_db = tmp_path / "cells.csv"
    cell_db.write_text(
        "\n".join([
            "radio,mcc,net,area,cell,unit,lon,lat,range,samples,changeable,created,updated,averageSignal",
            "LTE,208,20,30301,137096039,,2.352200,48.856600,250,7,1,1710000000,1710000100,-75",
        ])
    )
    output = tmp_path / "report.json"

    result = CliRunner().invoke(
        __main__.app,
        [
            "crash",
            "sysdiagnose-report",
            str(sysdiagnose),
            "--cell-db",
            str(cell_db),
            "--include-sensitive",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    report = json.loads(output.read_text())
    assert report["gsm"]["cell_database"]["matches"] == 1
    assert report["gsm"]["cell_towers"][0]["cell_database_match"]["latitude"] == 48.8566
    assert report["gsm"]["cell_towers"][0]["cell_database_match"]["longitude"] == 2.3522
