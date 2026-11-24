import gzip
import io
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from devops_cli.cli import main
from devops_cli.common import CliError
from devops_cli.logs import normalize_message, parse_since, summarize

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)

ACCESS_LINES = [
    '203.0.113.7 - - [24/Nov/2026:08:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" "ua"',
    '203.0.113.7 - - [24/Nov/2026:09:00:00 +0000] "GET /api/x?id=1 HTTP/1.1" 500 10 "-" "ua"',
    '203.0.113.7 - - [24/Nov/2026:10:00:00 +0000] "GET /api/x?id=2 HTTP/1.1" 500 10 "-" "ua"',
    '198.51.100.4 - - [24/Nov/2026:11:00:00 +0000] "GET /missing HTTP/1.1" 404 10 "-" "ua"',
    '198.51.100.4 - - [24/Nov/2026:11:30:00 +0000] "GET /static/a.css HTTP/1.1" 304 0 "-" "ua"',
    "línea que no es de acceso",
]

SYSLOG_LINES = [
    "Nov 24 08:00:00 web01 sshd[1]: Failed password for root from 203.0.113.7 port 1111 ssh2",
    "Nov 24 08:05:00 web01 sshd[1]: Failed password for root from 203.0.113.7 port 2222 ssh2",
    "Nov 24 09:00:00 web01 sshd[2]: Failed password for bob from 198.51.100.4 port 3333 ssh2",
    "Nov 24 10:00:00 web01 CRON[3]: (root) CMD (backup.sh)",
    "Nov 24 11:00:00 web01 smartd[4]: warning: SMART attribute changed",
    "Nov 24 11:30:00 web01 kernel: Out of memory: Killed process 99 (java)",
]


@pytest.fixture
def access_log(tmp_path: Path) -> Path:
    path = tmp_path / "access.log"
    path.write_text("\n".join(ACCESS_LINES) + "\n")
    return path


@pytest.fixture
def syslog_file(tmp_path: Path) -> Path:
    path = tmp_path / "syslog"
    path.write_text("\n".join(SYSLOG_LINES) + "\n")
    return path


# --- parse_since / normalize_message ---


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("30m", datetime(2026, 11, 24, 11, 30, tzinfo=UTC)),
        ("2h", datetime(2026, 11, 24, 10, 0, tzinfo=UTC)),
        ("1d", datetime(2026, 11, 23, 12, 0, tzinfo=UTC)),
        ("1w", datetime(2026, 11, 17, 12, 0, tzinfo=UTC)),
        ("90s", datetime(2026, 11, 24, 11, 58, 30, tzinfo=UTC)),
        ("2026-11-24T10:30:00", datetime(2026, 11, 24, 10, 30, tzinfo=UTC)),
        ("2026-11-24", datetime(2026, 11, 24, tzinfo=UTC)),
        ("2026-11-24T10:30:00+02:00", datetime(2026, 11, 24, 8, 30, tzinfo=UTC)),
    ],
)
def test_parse_since(text: str, expected: datetime) -> None:
    assert parse_since(text, NOW) == expected


@pytest.mark.parametrize("text", ["", "ayer", "10x", "-5m", "2026-99-99"])
def test_parse_since_rejects_invalid(text: str) -> None:
    with pytest.raises(CliError, match="--since") as excinfo:
        parse_since(text, NOW)
    assert excinfo.value.exit_code == 64


def test_normalize_message_groups_variable_parts() -> None:
    assert (
        normalize_message("Failed password from 203.0.113.7 port 22 ssh2")
        == "Failed password from <IP> port <N> ssh2"
    )
    assert len(normalize_message("x" * 500)) == 120


# --- summarize ---


def test_summarize_access_auto_detects_and_counts() -> None:
    summary = summarize(ACCESS_LINES, "auto", None, NOW, top=3)
    assert summary["format"] == "access"
    assert summary["lines"] == {"total": 6, "parsed": 5, "unparsed": 1, "in_range": 5}
    assert summary["status_codes"] == {"200": 1, "304": 1, "404": 1, "500": 2}
    assert summary["status_classes"] == {"2xx": 1, "3xx": 1, "4xx": 1, "5xx": 2}
    assert summary["top_ips"][0] == {"ip": "203.0.113.7", "count": 3}
    assert summary["top_errors"] == [
        {"status": 500, "path": "/api/x", "count": 2},  # la query string se descarta
        {"status": 404, "path": "/missing", "count": 1},
    ]
    assert summary["period"] == {
        "first": "2026-11-24T08:00:00+00:00",
        "last": "2026-11-24T11:30:00+00:00",
    }


def test_summarize_since_filters_entries() -> None:
    since = parse_since("2h", NOW)
    summary = summarize(ACCESS_LINES, "access", since, NOW)
    assert summary["lines"]["parsed"] == 5
    assert summary["lines"]["in_range"] == 3  # 10:00, 11:00 y 11:30
    assert summary["since"] == since.isoformat()
    assert summary["status_codes"] == {"304": 1, "404": 1, "500": 1}


def test_summarize_top_limits_rankings() -> None:
    summary = summarize(ACCESS_LINES, "access", None, NOW, top=1)
    assert len(summary["top_ips"]) == 1
    assert len(summary["top_errors"]) == 1


def test_summarize_syslog() -> None:
    summary = summarize(SYSLOG_LINES, "auto", None, NOW)
    assert summary["format"] == "syslog"
    assert summary["levels"] == {"critical": 1, "error": 3, "warning": 1, "info": 1}
    assert summary["top_programs"][0] == {"program": "sshd", "count": 3}
    assert summary["top_ips"][0] == {"ip": "203.0.113.7", "count": 2}
    assert summary["top_errors"][0] == {
        "message": "Failed password for root from <IP> port <N> ssh2",
        "count": 2,
    }


def test_summarize_ignores_blank_lines() -> None:
    summary = summarize(["", *ACCESS_LINES, "   "], "access", None, NOW)
    assert summary["lines"]["total"] == 6


def test_summarize_empty_and_unrecognized() -> None:
    with pytest.raises(CliError, match="vacío"):
        summarize([], "auto", None, NOW)
    with pytest.raises(CliError, match="no reconocido"):
        summarize(["hola", "mundo"], "auto", None, NOW)
    with pytest.raises(CliError, match="ninguna línea coincide"):
        summarize(ACCESS_LINES, "syslog", None, NOW)


def test_summarize_explicit_format_with_no_lines_is_empty_report() -> None:
    summary = summarize([], "access", None, NOW)
    assert summary["lines"]["total"] == 0
    assert summary["period"] == {"first": None, "last": None}


# --- CLI ---


def test_cli_text_report(access_log: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["logs", str(access_log)]) == 0
    out = capsys.readouterr().out
    assert f"Fichero: {access_log}  (formato: access)" in out
    assert "6 totales, 5 reconocidas, 1 sin reconocer" in out
    assert "Clases: 2xx=1  3xx=1  4xx=1  5xx=2" in out
    assert "Errores más frecuentes (HTTP >= 400)" in out
    assert "/api/x" in out


def test_cli_syslog_text_report(syslog_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["logs", str(syslog_file), "-f", "syslog", "--top", "2"]) == 0
    out = capsys.readouterr().out
    assert "Niveles" in out
    assert "IPs en mensajes de error" in out
    assert "Failed password for root from <IP>" in out


def test_cli_json_output(access_log: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["logs", str(access_log), "--json", "-n", "2"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["file"] == str(access_log)
    assert data["format"] == "access"
    assert data["lines"]["unparsed"] == 1
    assert len(data["top_ips"]) == 2


def test_cli_since_option(access_log: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["logs", str(access_log), "--since", "2020-01-01", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["lines"]["in_range"] == 5
    assert main(["logs", str(access_log), "--since", "2030-01-01", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["lines"]["in_range"] == 0
    assert data["top_ips"] == []


def test_cli_empty_sections_say_no_data(
    access_log: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["logs", str(access_log), "--since", "2030-01-01"]) == 0
    out = capsys.readouterr().out
    assert "(sin datos)" in out
    assert "Clases: -" in out
    assert "Periodo:" not in out
    assert "Desde:" in out


def test_cli_reads_gzip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "access.log.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write("\n".join(ACCESS_LINES))
    assert main(["logs", str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["lines"]["parsed"] == 5


def test_cli_reads_stdin(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("\n".join(ACCESS_LINES)))
    assert main(["logs", "-", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["file"] == "-"


def test_cli_missing_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["logs", str(tmp_path / "no-existe.log")]) == 3
    err = capsys.readouterr().err
    assert err.startswith("devops-cli: error: no existe el fichero")
    assert "Traceback" not in err


def test_cli_directory_and_corrupt_gzip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["logs", str(tmp_path)]) == 3
    bad = tmp_path / "roto.log.gz"
    bad.write_bytes(b"esto no es gzip")
    assert main(["logs", str(bad)]) == 3
    truncated = tmp_path / "corto.log.gz"
    truncated.write_bytes(gzip.compress(("\n".join(ACCESS_LINES) * 200).encode())[:-20])
    assert main(["logs", str(truncated)]) == 3
    err = capsys.readouterr().err
    assert err.count("no se pudo leer") == 3
    assert "Traceback" not in err


def test_cli_unreadable_format_is_unknown(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "raro.log"
    path.write_text("nada\nque\nreconocer\n")
    assert main(["logs", str(path)]) == 3
    assert "formato de log no reconocido" in capsys.readouterr().err


def test_cli_usage_errors(access_log: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["logs"]) == 64
    assert main(["logs", str(access_log), "--since", "ayer"]) == 64
    assert main(["logs", str(access_log), "--top", "0"]) == 64
    assert main(["logs", str(access_log), "--format", "xml"]) == 64
    assert "--since" in capsys.readouterr().err


def test_bundled_examples_parse() -> None:
    """Los ficheros de ejemplo del repositorio deben seguir siendo válidos."""
    root = Path(__file__).resolve().parent.parent / "examples"
    access = summarize((root / "access.log").read_text().splitlines(), "auto", None, NOW)
    syslog = summarize((root / "syslog.log").read_text().splitlines(), "auto", None, NOW)
    assert access["format"] == "access"
    assert access["lines"]["unparsed"] == 1
    assert syslog["format"] == "syslog"
    assert syslog["lines"]["unparsed"] == 0


@pytest.mark.parametrize("text", ["99999999999w", "9999999999d", "0001-01-01T00:00:00+23:59"])
def test_parse_since_overflow_is_usage_error(text: str) -> None:
    with pytest.raises(CliError) as excinfo:
        parse_since(text, NOW)
    assert excinfo.value.exit_code == 64


def test_cli_empty_since_is_usage_error(access_log: Path) -> None:
    assert main(["logs", str(access_log), "--since", ""]) == 64


def test_cli_stdin_with_invalid_utf8(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    raw = ("\n".join(ACCESS_LINES) + "\n").encode() + b"\xff\xfe basura\n"
    stdin = io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8")
    monkeypatch.setattr("sys.stdin", stdin)
    assert main(["logs", "-", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["lines"]["unparsed"] == 2


def test_control_characters_in_log_data_cannot_forge_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    line = '203.0.113.7 - - [24/Nov/2026:08:00:00 +0000] "GET /\x1b[2J\x1b[31m500 HTTP/1.1" 404 1'
    path = tmp_path / "a.log"
    path.write_text(line + "\n")
    assert main(["logs", str(path)]) == 0
    assert "\x1b" not in capsys.readouterr().out
