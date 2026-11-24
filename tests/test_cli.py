import subprocess
import sys

import pytest

from devops_cli import __version__, disk
from devops_cli.cli import main
from devops_cli.common import CliError


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == f"devops-cli {__version__}"


def test_help_is_in_spanish(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--help"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("uso: devops-cli")
    assert "muestra esta ayuda y termina" in out
    assert "Códigos de salida" in out
    for command in ("disk", "tls-expiry", "logs"):
        assert command in out


@pytest.mark.parametrize("command", ["disk", "tls-expiry", "logs"])
def test_subcommand_help(command: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([command, "--help"]) == 0
    assert "opciones" in capsys.readouterr().out


def test_no_command_is_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 64
    assert "devops-cli: error" in capsys.readouterr().err


def test_unknown_command_is_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["inexistente"]) == 64
    assert "uso: devops-cli" in capsys.readouterr().err


def test_cli_error_becomes_message_and_exit_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(_: object) -> int:
        raise CliError("algo falló", 3)

    monkeypatch.setattr(disk, "run", boom)
    assert main(["disk"]) == 3
    assert capsys.readouterr().err == "devops-cli: error: algo falló\n"


def test_keyboard_interrupt_returns_130(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def interrupted(_: object) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(disk, "run", interrupted)
    assert main(["disk"]) == 130
    assert "interrumpido" in capsys.readouterr().err


def test_python_dash_m_entry_point() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "devops_cli", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert __version__ in result.stdout


def test_exit_code_64_via_subprocess() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "devops_cli", "disk", "-w", "abc"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 64
    assert "Traceback" not in result.stderr
