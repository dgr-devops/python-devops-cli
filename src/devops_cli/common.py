"""Tipos y utilidades compartidas por todos los subcomandos."""

from __future__ import annotations

import argparse
import json
import math
import re
from collections.abc import Iterable, Sequence
from enum import IntEnum
from typing import Any

EXIT_USAGE = 64
MAX_TIMEOUT = 3600.0

_UNPRINTABLE_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]|[\ud800-\udfff]")


def printable(text: str) -> str:
    """Sustituye por '?' los caracteres de control: evita falsear la salida con datos ajenos."""
    return _UNPRINTABLE_RE.sub("?", text)


class Status(IntEnum):
    """Estados al estilo Nagios; el valor es el código de salida."""

    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3


# Gravedad al agregar varios resultados: CRITICAL > WARNING > UNKNOWN > OK.
_SEVERITY = {Status.OK: 0, Status.UNKNOWN: 1, Status.WARNING: 2, Status.CRITICAL: 3}


def worst_status(statuses: Iterable[Status]) -> Status:
    """Devuelve el estado más grave; sin elementos, UNKNOWN."""
    return max(statuses, key=_SEVERITY.__getitem__, default=Status.UNKNOWN)


class CliError(Exception):
    """Fallo esperado: se muestra el mensaje sin traza y se sale con `exit_code`."""

    def __init__(self, message: str, exit_code: int = Status.UNKNOWN) -> None:
        super().__init__(message)
        self.exit_code = int(exit_code)


def percent_arg(text: str) -> float:
    """Tipo de argparse: porcentaje entre 0 y 100."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{text}' no es un número") from None
    if not 0 <= value <= 100:
        raise argparse.ArgumentTypeError(f"{text} debe estar entre 0 y 100")
    return value


def positive_int(text: str) -> int:
    """Tipo de argparse: entero mayor que cero."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{text}' no es un entero") from None
    if value < 1:
        raise argparse.ArgumentTypeError(f"{text} debe ser mayor que 0")
    return value


def positive_float(text: str) -> float:
    """Tipo de argparse: número finito mayor que cero y de hasta una hora."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{text}' no es un número") from None
    if not math.isfinite(value) or not 0 < value <= MAX_TIMEOUT:
        raise argparse.ArgumentTypeError(f"{text} debe estar entre 0 y {MAX_TIMEOUT:g}")
    return value


def non_negative_int(text: str) -> int:
    """Tipo de argparse: entero mayor o igual que cero."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{text}' no es un entero") from None
    if value < 0:
        raise argparse.ArgumentTypeError(f"{text} no puede ser negativo")
    return value


def format_bytes(size: int) -> str:
    """Tamaño legible en unidades binarias (KiB, MiB...)."""
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    raise AssertionError("inalcanzable")  # pragma: no cover


def render_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    right_aligned: Sequence[int] = (),
) -> str:
    """Tabla de texto con columnas alineadas; `right_aligned` son índices de columna."""
    widths = [len(h) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def fmt(row: Sequence[str]) -> str:
        cells = [
            cell.rjust(widths[i]) if i in right_aligned else cell.ljust(widths[i])
            for i, cell in enumerate(row)
        ]
        return "  ".join(cells).rstrip()

    lines = [fmt(headers), "  ".join("-" * w for w in widths)]
    lines.extend(fmt(row) for row in rows)
    return "\n".join(lines)


def dump_json(data: Any) -> str:
    """JSON legible y estable (UTF-8, sin escapar acentos)."""
    return json.dumps(data, ensure_ascii=False, indent=2)
