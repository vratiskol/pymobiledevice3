from pathlib import Path

import pytest
import typer

from pymobiledevice3.cli import crash as crash_cli
from pymobiledevice3.exceptions import SysdiagnoseTimeoutError
from pymobiledevice3.services.crash_reports import SYSDIAGNOSE_STAGE_DETECTING_ARCHIVE


class FakeCrashReportsManager:
    def __init__(self, service_provider) -> None:
        self.service_provider = service_provider

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        return None

    async def get_new_sysdiagnose(self, out: str, erase: bool = True, *, timeout: float | None = None) -> None:
        exc = SysdiagnoseTimeoutError("Timeout finding in-progress sysdiagnose filename")
        exc.phase = SYSDIAGNOSE_STAGE_DETECTING_ARCHIVE
        raise exc


def test_crash_sysdiagnose_timeout_is_cli_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(crash_cli, "CrashReportsManager", FakeCrashReportsManager)

    with pytest.raises(typer.Exit) as exc_info:
        crash_cli.crash_sysdiagnose(object(), tmp_path / "sysdiagnose.tar.gz", erase=False, timeout=5.0)

    assert exc_info.value.exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == "Press Power+VolUp+VolDown for 0.215 seconds\n"
    assert captured.err == "Error: Timeout finding in-progress sysdiagnose filename\n"
    assert "Traceback" not in captured.err


def test_crash_sysdiagnose_timeout_can_be_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    printed_json = []
    monkeypatch.setattr(crash_cli, "CrashReportsManager", FakeCrashReportsManager)
    monkeypatch.setattr(crash_cli, "print_json", printed_json.append)

    with pytest.raises(typer.Exit) as exc_info:
        crash_cli.crash_sysdiagnose(
            object(), tmp_path / "sysdiagnose.tar.gz", erase=False, timeout=5.0, json_output=True
        )

    assert exc_info.value.exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == "Press Power+VolUp+VolDown for 0.215 seconds\n"
    assert captured.err == ""
    assert len(printed_json) == 1
    output = printed_json[0]
    assert output == {
        "error": "Timeout finding in-progress sysdiagnose filename",
        "status": "timeout",
        "timeout": {
            "phase": SYSDIAGNOSE_STAGE_DETECTING_ARCHIVE,
            "seconds": 5.0,
        },
    }
