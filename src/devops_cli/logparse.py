"""Análisis línea a línea de logs de acceso (nginx/apache) y de syslog."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone

from .common import printable

FORMAT_ACCESS = "access"
FORMAT_SYSLOG = "syslog"

MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}

_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<request>(?:[^"\\]|\\.)*)" '
    r"(?P<status>\d{3}) (?:\d+|-)"
)
_ACCESS_TS_RE = re.compile(
    r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$"
)
_SYSLOG_TAIL = r"(?P<host>\S+) (?P<program>[^\s:\[]+)(?:\[\d+\])?: ?(?P<message>.*)$"
_SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2}) "
    + _SYSLOG_TAIL
)
_SYSLOG_ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?) " + _SYSLOG_TAIL
)

# El primer patrón que coincide fija el nivel; sin coincidencias, "info".
_LEVEL_PATTERNS = (
    (
        "critical",
        re.compile(r"\b(crit(ical)?|alert|emerg(ency)?|fatal|panic|out of memory)\b", re.I),
    ),
    ("error", re.compile(r"\b(err(or)?|fail(ed|ure|ures)?|denied|refused|invalid)\b", re.I)),
    ("warning", re.compile(r"\bwarn(ing)?\b", re.I)),
)
LEVELS = ("critical", "error", "warning", "info")

SYSLOG_FUTURE_TOLERANCE = timedelta(days=1)


@dataclass(frozen=True)
class AccessEntry:
    ip: str
    timestamp: datetime
    method: str
    path: str
    status: int


@dataclass(frozen=True)
class SyslogEntry:
    timestamp: datetime
    host: str
    program: str
    level: str
    message: str


def _parse_access_timestamp(text: str) -> datetime | None:
    match = _ACCESS_TS_RE.match(text)
    if not match or match.group(2) not in MONTHS:
        return None
    day, mon, year, hour, minute, second, sign, off_h, off_m = match.groups()
    offset = timedelta(hours=int(off_h), minutes=int(off_m))
    try:
        return datetime(
            int(year), MONTHS[mon], int(day), int(hour), int(minute), int(second),
            tzinfo=timezone(-offset if sign == "-" else offset),
        )  # fmt: skip
    except ValueError:
        return None


def parse_access_line(line: str) -> AccessEntry | None:
    """Formato combined/common de nginx y apache. Devuelve None si no encaja."""
    match = _ACCESS_RE.match(line)
    if not match:
        return None
    timestamp = _parse_access_timestamp(match["ts"])
    if timestamp is None:
        return None
    parts = match["request"].split()
    method, path = (parts[0], parts[1]) if len(parts) >= 2 else ("-", match["request"] or "-")
    return AccessEntry(
        printable(match["ip"]), timestamp, printable(method), printable(path), int(match["status"])
    )


def classify_level(message: str) -> str:
    for level, pattern in _LEVEL_PATTERNS:
        if pattern.search(message):
            return level
    return "info"


def _syslog_timestamp(match: re.Match[str], now: datetime) -> datetime | None:
    """Fecha de la línea; el syslog clásico no trae año, se deduce a partir de `now`."""
    try:
        if "ts" in match.re.groupindex:
            return datetime.fromisoformat(match["ts"]).astimezone()
        if match["month"] not in MONTHS:
            return None
        fields = (MONTHS[match["month"]], int(match["day"]), int(match["h"]), int(match["m"]),
                  int(match["s"]))  # fmt: skip
        candidate = datetime(now.year, *fields).astimezone()
        if candidate > now + SYSLOG_FUTURE_TOLERANCE:
            candidate = datetime(now.year - 1, *fields).astimezone()
        return candidate
    except ValueError:
        return None


def parse_syslog_line(line: str, now: datetime | None = None) -> SyslogEntry | None:
    """Syslog clásico (`Nov 24 09:13:01 host prog[1]: msg`) o con fecha ISO 8601."""
    reference = now or datetime.now(UTC)
    match = _SYSLOG_RE.match(line) or _SYSLOG_ISO_RE.match(line)
    if not match:
        return None
    timestamp = _syslog_timestamp(match, reference)
    if timestamp is None:
        return None
    message = match["message"]
    return SyslogEntry(
        timestamp,
        printable(match["host"]),
        printable(match["program"]),
        classify_level(message),
        printable(message),
    )


def detect_format(sample: Iterable[str], now: datetime | None = None) -> str | None:
    """Decide el formato según cuántas líneas de la muestra reconoce cada parser."""
    access = syslog = 0
    for line in sample:
        access += parse_access_line(line) is not None
        syslog += parse_syslog_line(line, now) is not None
    if access == syslog == 0:
        return None
    return FORMAT_ACCESS if access >= syslog else FORMAT_SYSLOG
