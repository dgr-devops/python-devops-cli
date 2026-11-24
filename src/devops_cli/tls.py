"""Subcomando `tls-expiry`: días que le quedan al certificado de un servidor TLS."""

from __future__ import annotations

import argparse
import math
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, NamedTuple

from .common import (
    EXIT_USAGE,
    CliError,
    Status,
    dump_json,
    non_negative_int,
    positive_float,
    printable,
    render_table,
    worst_status,
)
from .x509 import CertificateError, parse_certificate

DEFAULT_PORT = 443
DEFAULT_WARNING_DAYS = 30
DEFAULT_CRITICAL_DAYS = 14
DEFAULT_TIMEOUT = 10.0
SECONDS_PER_DAY = 86400

CertFetcher = Callable[[str, int, float], bytes]


class Target(NamedTuple):
    host: str
    port: int

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


class TlsCheckError(Exception):
    """No se pudo obtener o leer el certificado del servidor."""


@dataclass(frozen=True)
class TlsReport:
    target: str
    status: Status
    detail: str
    days_left: int | None = None
    not_after: datetime | None = None
    subject: str | None = None
    issuer: str | None = None
    error: str | None = None


def parse_target(text: str) -> Target:
    """Interpreta HOST, HOST:PUERTO o [IPv6]:PUERTO. Lanza ValueError si no es válido."""
    value = text.strip()
    port_text: str | None = None
    if value.startswith("["):
        host, closing, rest = value[1:].partition("]")
        if not closing or (rest and not rest.startswith(":")):
            raise ValueError(f"destino no válido: '{text}'")
        port_text = rest[1:] if rest else None
    elif value.count(":") == 1:
        host, _, port_text = value.partition(":")
    else:
        host = value  # nombre sin puerto o IPv6 sin corchetes
    if not host or any(ch.isspace() or not ch.isprintable() for ch in host):
        raise ValueError(f"destino no válido: '{printable(text)}'")
    if port_text is None:
        return Target(host, DEFAULT_PORT)
    if not (port_text.isascii() and port_text.isdecimal()) or not 1 <= int(port_text) <= 65535:
        raise ValueError(f"puerto no válido en '{text}' (debe estar entre 1 y 65535)")
    return Target(host, int(port_text))


def target_arg(text: str) -> Target:
    """Tipo de argparse para HOST[:PORT]."""
    try:
        return parse_target(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def fetch_certificate(host: str, port: int, timeout: float) -> bytes:
    """Abre una conexión TLS y devuelve el certificado del servidor en DER.

    No valida la cadena de confianza: el objetivo es medir la caducidad, también
    de certificados autofirmados o de CAs internas.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
    except socket.gaierror as exc:
        raise TlsCheckError(f"no se pudo resolver el host '{host}'") from exc
    except TimeoutError as exc:
        raise TlsCheckError(f"tiempo de espera agotado ({timeout:g} s)") from exc
    except ConnectionRefusedError as exc:
        raise TlsCheckError(f"conexión rechazada en el puerto {port}") from exc
    except ssl.SSLError as exc:
        raise TlsCheckError(f"fallo en el handshake TLS: {exc.reason or exc}") from exc
    except UnicodeError as exc:
        raise TlsCheckError(f"nombre de host no válido: '{host}'") from exc
    except OSError as exc:
        raise TlsCheckError(f"error de red: {exc.strerror or exc}") from exc
    if not der:
        raise TlsCheckError("el servidor no presentó ningún certificado")
    return der


def days_until(not_after: datetime, now: datetime) -> int:
    """Días completos hasta la caducidad; negativo (días completos desde que caducó) si ya pasó."""
    return math.trunc((not_after - now).total_seconds() / SECONDS_PER_DAY)


def classify(days_left: int, warning: int, critical: int) -> Status:
    if days_left <= critical:
        return Status.CRITICAL
    if days_left <= warning:
        return Status.WARNING
    return Status.OK


def _describe(days_left: int, not_after: datetime, expired: bool) -> str:
    when = not_after.strftime("%Y-%m-%d")
    if not expired:
        return f"caduca en {days_left} días ({when})"
    if days_left == 0:
        return f"caducó hace menos de un día ({when})"
    return f"caducó hace {-days_left} días ({when})"


def check_target(
    target: Target,
    warning: int,
    critical: int,
    timeout: float,
    fetcher: CertFetcher = fetch_certificate,
    now: datetime | None = None,
) -> TlsReport:
    moment = now or datetime.now(UTC)
    try:
        info = parse_certificate(fetcher(target.host, target.port, timeout))
    except (TlsCheckError, CertificateError) as exc:
        return TlsReport(str(target), Status.UNKNOWN, str(exc), error=str(exc))
    days_left = days_until(info.not_after, moment)
    expired = info.not_after <= moment
    if info.not_before > moment:
        status, detail = Status.CRITICAL, f"aún no es válido (desde {info.not_before:%Y-%m-%d})"
    elif expired:
        status, detail = Status.CRITICAL, _describe(days_left, info.not_after, expired)
    else:
        status = classify(days_left, warning, critical)
        detail = _describe(days_left, info.not_after, expired)
    return TlsReport(
        str(target), status, detail, days_left, info.not_after, info.subject, info.issuer
    )


def validate_thresholds(warning: int, critical: int) -> None:
    if critical >= warning:
        raise CliError(
            f"el umbral crítico (-c {critical}) debe ser menor que el de aviso (-w {warning})",
            EXIT_USAGE,
        )


def summary_line(reports: list[TlsReport], status: Status) -> str:
    if status is Status.OK:
        return f"TLS OK - {len(reports)} certificados con vigencia suficiente"
    problems = "; ".join(f"{r.target} {r.detail}" for r in reports if r.status is not Status.OK)
    return f"TLS {status.name} - {problems}"


def render_text(reports: list[TlsReport], status: Status) -> str:
    rows = [
        [
            r.target, r.subject or "-", r.issuer or "-",
            r.not_after.strftime("%Y-%m-%d") if r.not_after else "-",
            "-" if r.days_left is None else str(r.days_left), r.status.name,
        ]
        for r in reports
    ]  # fmt: skip
    table = render_table(
        ["DESTINO", "SUJETO (CN)", "EMISOR (CN)", "CADUCA", "DÍAS", "ESTADO"],
        rows,
        right_aligned=(4,),
    )
    return f"{summary_line(reports, status)}\n\n{table}"


def to_dict(reports: list[TlsReport], status: Status, warning: int, critical: int) -> dict:
    return {
        "check": "tls-expiry",
        "status": status.name,
        "exit_code": int(status),
        "thresholds": {"warning_days": warning, "critical_days": critical},
        "certificates": [
            {
                "target": r.target,
                "status": r.status.name,
                "days_left": r.days_left,
                "not_after": r.not_after.isoformat() if r.not_after else None,
                "subject": r.subject,
                "issuer": r.issuer,
                "detail": r.detail,
                "error": r.error,
            }
            for r in reports
        ],
    }


def run(args: argparse.Namespace) -> int:
    validate_thresholds(args.warning, args.critical)
    reports = [
        check_target(target, args.warning, args.critical, args.timeout) for target in args.targets
    ]
    status = worst_status(r.status for r in reports)
    if args.json:
        print(dump_json(to_dict(reports, status, args.warning, args.critical)))
    else:
        print(render_text(reports, status))
    return int(status)


def add_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "tls-expiry",
        help="días hasta la caducidad de certificados TLS",
        description=(
            "Se conecta a cada HOST[:PUERTO] (por defecto 443) y calcula los días que "
            "le quedan al certificado. No valida la cadena de confianza."
        ),
    )
    parser.add_argument(
        "targets", nargs="+", type=target_arg, metavar="HOST[:PUERTO]",
        help="servidores a comprobar (acepta [IPv6]:PUERTO)",
    )  # fmt: skip
    parser.add_argument(
        "-w", "--warning", type=non_negative_int, default=DEFAULT_WARNING_DAYS, metavar="DIAS",
        help=f"aviso si quedan DIAS o menos (por defecto {DEFAULT_WARNING_DAYS})",
    )  # fmt: skip
    parser.add_argument(
        "-c", "--critical", type=non_negative_int, default=DEFAULT_CRITICAL_DAYS, metavar="DIAS",
        help=f"crítico si quedan DIAS o menos (por defecto {DEFAULT_CRITICAL_DAYS})",
    )  # fmt: skip
    parser.add_argument(
        "-t", "--timeout", type=positive_float, default=DEFAULT_TIMEOUT, metavar="SEG",
        help=f"tiempo máximo por conexión en segundos (por defecto {DEFAULT_TIMEOUT:g})",
    )  # fmt: skip
    parser.add_argument("--json", action="store_true", help="salida en JSON")
    parser.set_defaults(handler=run)
