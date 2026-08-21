from __future__ import annotations

from typer.testing import CliRunner

from cyberkimi import __version__
from cyberkimi.cli import app


runner = CliRunner()


def test_version_exits_successfully() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_no_arguments_prints_help_successfully() -> None:
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "Evidence-first security analysis harness" in result.stdout
    assert "review" in result.stdout
