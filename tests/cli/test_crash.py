from pathlib import Path

import pytest
import typer

from pymobiledevice3.cli import crash as crash_cli
from pymobiledevice3.exceptions import SysdiagnoseTimeoutError


def test_crash_sysdiagnose_timeout_is_cli_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class FakeCrashReportsManager:
        def __init__(self, service_provider) -> None:
            self.service_provider = service_provider

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
            return None

        async def get_new_sysdiagnose(self, out: str, erase: bool = True, *, timeout: float | None = None) -> None:
            assert out == str(tmp_path / "sysdiagnose.tar.gz")
            assert erase is False
            assert timeout == 5.0
            raise SysdiagnoseTimeoutError("Timeout finding in-progress sysdiagnose filename")

    monkeypatch.setattr(crash_cli, "CrashReportsManager", FakeCrashReportsManager)

    with pytest.raises(typer.Exit) as exc_info:
        crash_cli.crash_sysdiagnose(object(), tmp_path / "sysdiagnose.tar.gz", erase=False, timeout=5.0)

    assert exc_info.value.exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == "Press Power+VolUp+VolDown for 0.215 seconds\n"
    assert captured.err == "Error: Timeout finding in-progress sysdiagnose filename\n"
    assert "Traceback" not in captured.err
