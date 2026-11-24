import json
import socket
import ssl
import threading
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta

import pytest

from devops_cli import tls
from devops_cli.cli import main
from devops_cli.common import Status
from devops_cli.tls import (
    Target,
    TlsCheckError,
    check_target,
    classify,
    days_until,
    fetch_certificate,
    parse_target,
    validate_thresholds,
)
from devops_cli.x509 import parse_certificate

HOST = "127.0.0.1"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("example.com", Target("example.com", 443)),
        ("example.com:8443", Target("example.com", 8443)),
        ("  example.com  ", Target("example.com", 443)),
        ("[::1]", Target("::1", 443)),
        ("[::1]:993", Target("::1", 993)),
        ("2001:db8::1", Target("2001:db8::1", 443)),
        ("192.0.2.10:465", Target("192.0.2.10", 465)),
    ],
)
def test_parse_target(text: str, expected: Target) -> None:
    assert parse_target(text) == expected


@pytest.mark.parametrize(
    "text", ["", ":443", "host:0", "host:65536", "host:abc", "host:", "[::1", "[::1]x", "[]:443"]
)
def test_parse_target_rejects_invalid(text: str) -> None:
    with pytest.raises(ValueError, match=r"no válido|puerto"):
        parse_target(text)


def test_target_str_brackets_ipv6() -> None:
    assert str(Target("::1", 443)) == "[::1]:443"
    assert str(Target("example.com", 8443)) == "example.com:8443"


@pytest.mark.parametrize(
    ("days", "expected"),
    [(60, Status.OK), (31, Status.OK), (30, Status.WARNING), (15, Status.WARNING),
     (14, Status.CRITICAL), (0, Status.CRITICAL), (-3, Status.CRITICAL)],
)  # fmt: skip
def test_classify(days: int, expected: Status) -> None:
    assert classify(days, 30, 14) is expected


def test_days_until_truncates_toward_zero() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert days_until(now + timedelta(days=5, hours=23), now) == 5
    assert days_until(now - timedelta(days=2, hours=5), now) == -2
    assert days_until(now - timedelta(hours=3), now) == 0


def test_validate_thresholds() -> None:
    validate_thresholds(30, 14)
    with pytest.raises(Exception, match="debe ser menor") as excinfo:
        validate_thresholds(14, 14)
    assert excinfo.value.exit_code == 64  # type: ignore[attr-defined]


# --- check_target con un fetcher simulado (sin red) ---


def _report_at(cert_der: Callable[..., bytes], offset: timedelta):
    der = cert_der(90)
    info = parse_certificate(der)
    now = info.not_after - offset
    return check_target(Target("host.test", 443), 30, 14, 5, lambda *_: der, now=now)


def test_check_target_ok(cert_der: Callable[..., bytes]) -> None:
    report = _report_at(cert_der, timedelta(days=60, hours=1))
    assert report.status is Status.OK
    assert report.days_left == 60
    assert report.subject == "localhost"
    assert "caduca en 60 días" in report.detail


def test_check_target_warning(cert_der: Callable[..., bytes]) -> None:
    assert _report_at(cert_der, timedelta(days=20, hours=1)).status is Status.WARNING


def test_check_target_critical(cert_der: Callable[..., bytes]) -> None:
    assert _report_at(cert_der, timedelta(days=5, hours=1)).status is Status.CRITICAL


def test_check_target_expired(cert_der: Callable[..., bytes]) -> None:
    report = _report_at(cert_der, timedelta(days=-3, hours=-1))
    assert report.status is Status.CRITICAL
    assert report.days_left == -3
    assert "caducó hace 3 días" in report.detail


def test_check_target_expired_today(cert_der: Callable[..., bytes]) -> None:
    report = _report_at(cert_der, timedelta(hours=-2))
    assert report.status is Status.CRITICAL
    assert "menos de un día" in report.detail


def test_check_target_not_yet_valid(cert_der: Callable[..., bytes]) -> None:
    der = cert_der(90)
    now = parse_certificate(der).not_before - timedelta(days=2)
    report = check_target(Target("h", 443), 30, 14, 5, lambda *_: der, now=now)
    assert report.status is Status.CRITICAL
    assert "aún no es válido" in report.detail


def test_check_target_fetch_error_is_unknown() -> None:
    def failing(*_: object) -> bytes:
        raise TlsCheckError("conexión rechazada en el puerto 443")

    report = check_target(Target("h", 443), 30, 14, 5, failing)
    assert report.status is Status.UNKNOWN
    assert report.error == "conexión rechazada en el puerto 443"
    assert report.days_left is None


def test_check_target_unreadable_certificate_is_unknown() -> None:
    report = check_target(Target("h", 443), 30, 14, 5, lambda *_: b"basura")
    assert report.status is Status.UNKNOWN
    assert report.error


# --- fetch_certificate contra un servidor TLS local real ---


def test_fetch_certificate_from_local_server(tls_server: Callable[..., int]) -> None:
    port = tls_server(45, "servidor.test")
    info = parse_certificate(fetch_certificate(HOST, port, 5))
    assert info.subject == "servidor.test"
    assert info.not_after - info.not_before == timedelta(days=45)


def test_fetch_connection_refused(closed_port: int) -> None:
    with pytest.raises(TlsCheckError, match="conexión rechazada"):
        fetch_certificate(HOST, closed_port, 2)


def test_fetch_resolution_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_: object, **__: object) -> None:
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(tls.socket, "create_connection", fail)
    with pytest.raises(TlsCheckError, match="no se pudo resolver"):
        fetch_certificate("no-existe.invalid", 443, 2)


def test_fetch_invalid_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_: object, **__: object) -> None:
        raise UnicodeError("label empty or too long")

    monkeypatch.setattr(tls.socket, "create_connection", fail)
    with pytest.raises(TlsCheckError, match="nombre de host no válido"):
        fetch_certificate("a..b", 443, 2)


def test_fetch_generic_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_: object, **__: object) -> None:
        raise OSError(101, "Network is unreachable")

    monkeypatch.setattr(tls.socket, "create_connection", fail)
    with pytest.raises(TlsCheckError, match="error de red"):
        fetch_certificate("h", 443, 2)


@pytest.fixture
def silent_server() -> Iterator[int]:
    """Acepta conexiones TCP pero nunca habla: el handshake TLS agota el tiempo."""
    sock = socket.socket()
    sock.bind((HOST, 0))
    sock.listen(5)
    yield sock.getsockname()[1]
    sock.close()


def test_fetch_timeout(silent_server: int) -> None:
    with pytest.raises(TlsCheckError, match="tiempo de espera agotado"):
        fetch_certificate(HOST, silent_server, 0.3)


@pytest.fixture
def plain_server() -> Iterator[int]:
    """Responde con basura que no es TLS."""
    sock = socket.socket()
    sock.bind((HOST, 0))
    sock.listen(5)
    sock.settimeout(3)

    def serve() -> None:
        try:
            conn, _ = sock.accept()
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            conn.close()
        except OSError:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield sock.getsockname()[1]
    sock.close()
    thread.join(timeout=2)


def test_fetch_non_tls_server(plain_server: int) -> None:
    with pytest.raises(TlsCheckError, match="handshake TLS"):
        fetch_certificate(HOST, plain_server, 3)


def test_fetch_no_certificate(
    monkeypatch: pytest.MonkeyPatch, tls_server: Callable[..., int]
) -> None:
    port = tls_server()
    monkeypatch.setattr(ssl.SSLSocket, "getpeercert", lambda self, binary_form=False: None)
    with pytest.raises(TlsCheckError, match="no presentó ningún certificado"):
        fetch_certificate(HOST, port, 5)


# --- CLI de extremo a extremo contra el servidor local ---


def test_cli_ok(tls_server: Callable[..., int], capsys: pytest.CaptureFixture[str]) -> None:
    port = tls_server(90)
    assert main(["tls-expiry", f"{HOST}:{port}"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("TLS OK")
    assert f"{HOST}:{port}" in out


def test_cli_warning(tls_server: Callable[..., int], capsys: pytest.CaptureFixture[str]) -> None:
    port = tls_server(20)
    assert main(["tls-expiry", f"{HOST}:{port}"]) == 1
    assert capsys.readouterr().out.startswith("TLS WARNING")


def test_cli_critical_with_custom_thresholds(tls_server: Callable[..., int]) -> None:
    port = tls_server(20)
    assert main(["tls-expiry", f"{HOST}:{port}", "-w", "60", "-c", "30"]) == 2


def test_cli_worst_status_wins(
    tls_server: Callable[..., int], closed_port: int, capsys: pytest.CaptureFixture[str]
) -> None:
    good = tls_server(90)
    code = main(["tls-expiry", f"{HOST}:{good}", f"{HOST}:{closed_port}", "-t", "2"])
    out = capsys.readouterr().out
    assert code == 3
    assert "conexión rechazada" in out


def test_cli_json(tls_server: Callable[..., int], capsys: pytest.CaptureFixture[str]) -> None:
    port = tls_server(90, "json.test")
    assert main(["tls-expiry", f"{HOST}:{port}", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "OK"
    assert data["exit_code"] == 0
    assert data["thresholds"] == {"warning_days": 30, "critical_days": 14}
    cert = data["certificates"][0]
    assert cert["subject"] == "json.test"
    assert cert["days_left"] in (89, 90)


def test_cli_usage_errors(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["tls-expiry"]) == 64
    assert main(["tls-expiry", "host:99999"]) == 64
    assert main(["tls-expiry", "host", "-w", "5", "-c", "10"]) == 64
    assert main(["tls-expiry", "host", "-t", "0"]) == 64
    err = capsys.readouterr().err
    assert "puerto no válido" in err
    assert "debe ser menor" in err


def test_parse_target_rejects_non_ascii_digits_and_control_characters() -> None:
    for text in ("host:²", "host:٤٤٣", "ho\x1b[2Jst", "ho st"):
        with pytest.raises(ValueError, match=r"no válido|puerto"):
            parse_target(text)


def test_cli_rejects_non_finite_timeout_and_negative_days(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["tls-expiry", "host", "-t", "nan"]) == 64
    assert main(["tls-expiry", "host", "-t", "inf"]) == 64
    assert main(["tls-expiry", "host", "-w", "-5"]) == 64
    assert "no puede ser negativo" in capsys.readouterr().err
