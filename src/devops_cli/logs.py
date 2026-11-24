"""Subcomando `logs`: resumen de un log de acceso (nginx/apache) o de syslog."""

from __future__ import annotations

import argparse
import gzip
import itertools
import re
import sys
import zlib
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .common import EXIT_USAGE, CliError, Status, dump_json, positive_int, render_table
from .logparse import (
    FORMAT_ACCESS,
    FORMAT_SYSLOG,
    LEVELS,
    AccessEntry,
    SyslogEntry,
    detect_format,
    parse_access_line,
    parse_syslog_line,
)

DEFAULT_TOP = 10
SAMPLE_SIZE = 20
MIN_ERROR_STATUS = 400
MAX_MESSAGE_LEN = 120
FORMAT_CHOICES = ("auto", FORMAT_ACCESS, FORMAT_SYSLOG)

_DURATION_RE = re.compile(r"^(\d{1,9})([smhdw])$")
_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_NUMBER_RE = re.compile(r"\b\d+\b")


def parse_since(text: str, now: datetime) -> datetime:
    """Acepta duraciones (30m, 2h, 7d, 1w) o una fecha ISO (2026-11-24, 2026-11-24T08:00)."""
    value = text.strip()
    match = _DURATION_RE.match(value)
    try:
        if match:
            return now - timedelta(seconds=int(match[1]) * _SECONDS[match[2]])
        return datetime.fromisoformat(value).astimezone()
    except (ValueError, OverflowError, OSError):
        raise CliError(
            f"valor de --since no válido: '{text}' (usa p. ej. 30m, 2h, 7d o 2026-11-24T08:00)",
            EXIT_USAGE,
        ) from None


def normalize_message(message: str) -> str:
    """Agrupa mensajes parecidos: sustituye IPs y números por marcadores."""
    text = _NUMBER_RE.sub("<N>", _IP_RE.sub("<IP>", message)).strip()
    return text if len(text) <= MAX_MESSAGE_LEN else text[: MAX_MESSAGE_LEN - 1] + "…"


def _top(counter: Counter, limit: int) -> list[tuple[Any, int]]:
    """Los `limit` más frecuentes, con desempate estable por clave."""
    return sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit]


class _Stats:
    """Contador de entradas y rango temporal comunes a ambos formatos."""

    def __init__(self) -> None:
        self.count = 0
        self.first: datetime | None = None
        self.last: datetime | None = None

    def _track(self, timestamp: datetime) -> None:
        self.count += 1
        self.first = timestamp if self.first is None else min(self.first, timestamp)
        self.last = timestamp if self.last is None else max(self.last, timestamp)

    def period(self) -> dict[str, str | None]:
        return {
            "first": self.first.isoformat() if self.first else None,
            "last": self.last.isoformat() if self.last else None,
        }


class AccessStats(_Stats):
    def __init__(self) -> None:
        super().__init__()
        self.statuses: Counter[int] = Counter()
        self.ips: Counter[str] = Counter()
        self.errors: Counter[tuple[int, str]] = Counter()

    def add(self, entry: AccessEntry) -> None:
        self._track(entry.timestamp)
        self.statuses[entry.status] += 1
        self.ips[entry.ip] += 1
        if entry.status >= MIN_ERROR_STATUS:
            self.errors[(entry.status, entry.path.split("?", 1)[0])] += 1

    def to_dict(self, top: int) -> dict[str, Any]:
        classes: Counter[str] = Counter()
        for status, count in self.statuses.items():
            classes[f"{status // 100}xx"] += count
        return {
            "status_codes": {str(code): n for code, n in sorted(self.statuses.items())},
            "status_classes": dict(sorted(classes.items())),
            "top_ips": [{"ip": ip, "count": n} for ip, n in _top(self.ips, top)],
            "top_errors": [
                {"status": status, "path": path, "count": n}
                for (status, path), n in _top(self.errors, top)
            ],
        }


class SyslogStats(_Stats):
    def __init__(self) -> None:
        super().__init__()
        self.levels: Counter[str] = Counter()
        self.programs: Counter[str] = Counter()
        self.ips: Counter[str] = Counter()
        self.errors: Counter[str] = Counter()

    def add(self, entry: SyslogEntry) -> None:
        self._track(entry.timestamp)
        self.levels[entry.level] += 1
        self.programs[entry.program] += 1
        if entry.level in ("critical", "error"):
            self.errors[normalize_message(entry.message)] += 1
            self.ips.update(_IP_RE.findall(entry.message))

    def to_dict(self, top: int) -> dict[str, Any]:
        return {
            "levels": {level: self.levels[level] for level in LEVELS},
            "top_programs": [{"program": p, "count": n} for p, n in _top(self.programs, top)],
            "top_ips": [{"ip": ip, "count": n} for ip, n in _top(self.ips, top)],
            "top_errors": [{"message": m, "count": n} for m, n in _top(self.errors, top)],
        }


def summarize(
    lines: Iterable[str],
    fmt: str,
    since: datetime | None,
    now: datetime,
    top: int = DEFAULT_TOP,
) -> dict[str, Any]:
    """Recorre las líneas una sola vez (en streaming) y construye el resumen."""
    iterator = (line for line in lines if line.strip())
    if fmt == "auto":
        sample = list(itertools.islice(iterator, SAMPLE_SIZE))
        if not sample:
            raise CliError("el log está vacío")
        detected = detect_format(sample, now)
        if detected is None:
            raise CliError("formato de log no reconocido (prueba con --format access|syslog)")
        fmt, iterator = detected, itertools.chain(sample, iterator)

    parse: Callable[[str], AccessEntry | SyslogEntry | None]
    stats: AccessStats | SyslogStats
    if fmt == FORMAT_ACCESS:
        parse, stats = parse_access_line, AccessStats()
    else:
        parse, stats = (lambda line: parse_syslog_line(line, now)), SyslogStats()

    total = parsed = 0
    for raw in iterator:
        total += 1
        entry = parse(raw)
        if entry is None:
            continue
        parsed += 1
        if since is None or entry.timestamp >= since:
            stats.add(entry)  # type: ignore[arg-type]
    if total and not parsed:
        raise CliError(f"ninguna línea coincide con el formato '{fmt}'")

    return {
        "format": fmt,
        "since": since.isoformat() if since else None,
        "lines": {
            "total": total,
            "parsed": parsed,
            "unparsed": total - parsed,
            "in_range": stats.count,
        },
        "period": stats.period(),
        **stats.to_dict(top),
    }


def open_lines(source: str) -> Iterator[str]:
    """Líneas del fichero (admite .gz) o de la entrada estándar si `source` es '-'."""
    if source == "-":
        if hasattr(sys.stdin, "reconfigure"):
            sys.stdin.reconfigure(errors="replace")  # bytes inválidos no deben abortar
        for line in sys.stdin:
            yield line.rstrip("\r\n")
        return
    path = Path(source)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            yield line.rstrip("\r\n")


def _section(title: str, headers: list[str], rows: list[list[str]], right: tuple[int, ...]) -> str:
    body = render_table(headers, rows, right) if rows else "(sin datos)"
    return f"{title}\n{body}"


def render_text(summary: dict[str, Any]) -> str:
    counts, period = summary["lines"], summary["period"]
    head = [
        f"Fichero: {summary['file']}  (formato: {summary['format']})",
        f"Líneas: {counts['total']} totales, {counts['parsed']} reconocidas, "
        f"{counts['unparsed']} sin reconocer, {counts['in_range']} en el rango",
    ]
    if summary["since"]:
        head.append(f"Desde: {summary['since']}")
    if period["first"]:
        head.append(f"Periodo: {period['first']} -> {period['last']}")

    is_access = summary["format"] == FORMAT_ACCESS
    ips_title = "IPs más activas" if is_access else "IPs en mensajes de error"
    ips = [[i["ip"], str(i["count"])] for i in summary["top_ips"]]
    if is_access:
        classes = "  ".join(f"{k}={v}" for k, v in summary["status_classes"].items())
        sections = [
            _section(
                "Códigos de estado",
                ["CÓDIGO", "PETICIONES"],
                [[code, str(n)] for code, n in summary["status_codes"].items()],
                (1,),
            ),
            f"Clases: {classes or '-'}",
            _section(ips_title, ["IP", "PETICIONES"], ips, (1,)),
            _section(
                f"Errores más frecuentes (HTTP >= {MIN_ERROR_STATUS})",
                ["ESTADO", "RUTA", "VECES"],
                [[str(e["status"]), e["path"], str(e["count"])] for e in summary["top_errors"]],
                (2,),
            ),
        ]
    else:
        sections = [
            _section(
                "Niveles",
                ["NIVEL", "LÍNEAS"],
                [[level, str(n)] for level, n in summary["levels"].items()],
                (1,),
            ),
            _section(
                "Programas más activos",
                ["PROGRAMA", "LÍNEAS"],
                [[p["program"], str(p["count"])] for p in summary["top_programs"]],
                (1,),
            ),
            _section(ips_title, ["IP", "VECES"], ips, (1,)),
            _section(
                "Errores más frecuentes",
                ["VECES", "MENSAJE"],
                [[str(e["count"]), e["message"]] for e in summary["top_errors"]],
                (0,),
            ),
        ]
    return "\n".join(head) + "\n\n" + "\n\n".join(sections)


def run(args: argparse.Namespace) -> int:
    now = datetime.now(UTC).astimezone()
    since = parse_since(args.since, now) if args.since is not None else None
    try:
        summary = summarize(open_lines(args.file), args.format, since, now, args.top)
    except FileNotFoundError:
        raise CliError(f"no existe el fichero: {args.file}") from None
    except (OSError, EOFError, zlib.error) as exc:
        reason = getattr(exc, "strerror", None) or str(exc)
        raise CliError(f"no se pudo leer {args.file}: {reason}") from exc
    summary = {"file": args.file, **summary}
    print(dump_json(summary) if args.json else render_text(summary))
    return int(Status.OK)


def add_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "logs",
        help="resumen de un log de acceso o de syslog",
        description=(
            "Resume un log de acceso nginx/apache (combined/common) o un syslog: "
            "recuentos por código o nivel, IPs y errores más frecuentes."
        ),
    )
    parser.add_argument(
        "file", metavar="FICHERO", help="ruta del log (.gz admitido) o '-' para la entrada estándar"
    )
    parser.add_argument(
        "-f", "--format", choices=FORMAT_CHOICES, default="auto",
        help="formato del log (por defecto auto: se detecta solo)",
    )  # fmt: skip
    parser.add_argument(
        "-s", "--since", metavar="DESDE",
        help="solo entradas posteriores: 30m, 2h, 7d, 1w o fecha ISO (2026-11-24T08:00)",
    )  # fmt: skip
    parser.add_argument(
        "-n", "--top", type=positive_int, default=DEFAULT_TOP, metavar="N",
        help=f"tamaño de los rankings (por defecto {DEFAULT_TOP})",
    )  # fmt: skip
    parser.add_argument("--json", action="store_true", help="salida en JSON")
    parser.set_defaults(handler=run)
