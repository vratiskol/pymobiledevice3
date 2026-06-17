from typer.testing import CliRunner

from pymobiledevice3 import __main__


def test_backup_only_regex_invalid_pattern(tmp_path):
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "backup", "--only-regex", "[", str(tmp_path)])

    assert result.exit_code != 0
    assert "Invalid value for '--only-regex'" in result.output
    assert "Invalid regex pattern '['" in result.output


def test_backup_exclude_regex_invalid_pattern(tmp_path):
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "backup", "--exclude-regex", "[", str(tmp_path)])

    assert result.exit_code != 0
    assert "Invalid value for '--exclude-regex'" in result.output
    assert "Invalid regex pattern '['" in result.output


def test_backup_command_has_password_option():
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "backup", "--help"])

    assert result.exit_code == 0
    assert "--password" in result.output


def test_backup_command_has_unback_option():
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "backup", "--help"])

    assert result.exit_code == 0
    assert "--unback" in result.output


def test_backup_full_help_describes_conditional_default():
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "backup", "--help"])

    assert result.exit_code == 0
    normalized_output = " ".join(result.output.split())
    assert "incremental" in normalized_output
    assert "valid local metadata" in normalized_output
    assert "exists" in normalized_output
    assert "full for an empty" in normalized_output
    assert "incomplete backup" in normalized_output
    assert "directory" in normalized_output


def test_backup_only_choices_include_database_artifacts():
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "backup", "--help"])

    assert result.exit_code == 0
    assert "database_artifacts" in result.output


def test_backup_command_has_exclude_options():
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["backup2", "backup", "--help"])

    assert result.exit_code == 0
    assert "--exclude" in result.output
    assert "--exclude-regex" in result.output
    assert "photos" in result.output
    assert "may still transmit excluded data" in result.output
