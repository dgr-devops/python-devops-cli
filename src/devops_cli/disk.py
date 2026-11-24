"""Subcomando `disk`: uso de disco por punto de montaje con umbrales."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

from .common import (
    EXIT_USAGE,
    CliError,
    Status,
    dump_json,
    format_bytes,
    percent_arg,
    printable,
    render_table,
    worst_status,
)

PROC_MOUNTS = Path("/proc/mounts")
DEFAULT_WARNING = 80.0
DEFAULT_CRITICAL = 90.0

# Sistemas de ficheros virtuales o de solo lectura que no interesa vigilar.
PSEUDO_FILESYSTEMS = frozenset(
    {
        "autofs", "bpf", "binfmt_misc", "cgroup", "cgroup2", "configfs", "debugfs",
        "devpts", "devtmpfs", "efivarfs", "fusectl", "fuse.gvfsd-fuse", "fuse.portal",
        "hugetlbfs", "mqueue", "nsfs", "proc", "pstore", "ramfs", "rpc_pipefs",
        "securityfs", "squashfs", "sysfs", "tmpfs", "tracefs",
    }
)  # fmt: skip

UsageFn = Callable[[str], Any]
MountsReader = Callable[[], list["Mount"]]


class Mount(NamedTuple):
    device: str
    mountpoint: str
    fstype: str


@dataclass(frozen=True)
class DiskReport:
    mountpoint: str
    device: str
    fstype: str
    total: int
    used: int
    free: int
    percent: float | None
    status: Status
    error: str | None = None


def _unescape(field: str) -> str:
    """Decodifica las secuencias octales de /proc/mounts (p. ej. \\040 = espacio)."""
    raw = re.sub(rb"\\([0-7]{3})", lambda m: bytes([int(m[1], 8) & 0xFF]), os.fsencode(field))
    return printable(os.fsdecode(raw))


def parse_mounts(text: str) -> list[Mount]:
    mounts: list[Mount] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            mounts.append(Mount(_unescape(parts[0]), _unescape(parts[1]), parts[2]))
    return mounts


def read_mounts(path: Path | None = None) -> list[Mount]:
    path = path or PROC_MOUNTS
    try:
        return parse_mounts(path.read_text(encoding="utf-8", errors="surrogateescape"))
    except OSError as exc:
        raise CliError(
            f"no se pudo leer {path}: {exc.strerror or exc}. "
            "En sistemas sin /proc indica los directorios con --path."
        ) from exc


def select_mounts(mounts: list[Mount], include_all: bool = False) -> list[Mount]:
    """Quita los sistemas virtuales y los montajes repetidos del mismo dispositivo."""
    if include_all:
        return list(mounts)
    seen: set[str] = set()
    selected: list[Mount] = []
    for mount in mounts:
        if mount.fstype in PSEUDO_FILESYSTEMS or mount.device in seen:
            continue
        if mount.device.startswith("/"):  # solo los dispositivos reales identifican un montaje
            seen.add(mount.device)
        selected.append(mount)
    return selected


def find_mount(path: str, mounts: list[Mount]) -> Mount:
    """Montaje que contiene `path` (el de prefijo más largo); desconocido si no hay."""
    path = os.path.abspath(path)
    best: Mount | None = None
    for mount in mounts:
        prefix = mount.mountpoint.rstrip("/")
        inside = path == mount.mountpoint or path.startswith(prefix + "/")
        if inside and (best is None or len(mount.mountpoint) > len(best.mountpoint)):
            best = mount
    device, fstype = (best.device, best.fstype) if best else ("-", "-")
    return Mount(device, path, fstype)


def percent_used(used: int, free: int) -> float:
    """Porcentaje de uso como `df`: usado / (usado + disponible)."""
    base = used + free
    return 0.0 if base <= 0 else used / base * 100


def classify(percent: float, warning: float, critical: float) -> Status:
    if percent >= critical:
        return Status.CRITICAL
    if percent >= warning:
        return Status.WARNING
    return Status.OK


def check_mount(
    mount: Mount, warning: float, critical: float, usage_fn: UsageFn = shutil.disk_usage
) -> DiskReport:
    try:
        usage = usage_fn(mount.mountpoint)
    except OSError as exc:
        return DiskReport(
            mount.mountpoint, mount.device, mount.fstype, 0, 0, 0, None, Status.UNKNOWN,
            error=exc.strerror or str(exc),
        )  # fmt: skip
    percent = percent_used(usage.used, usage.free)
    return DiskReport(
        mount.mountpoint, mount.device, mount.fstype, usage.total, usage.used, usage.free,
        percent, classify(percent, warning, critical),
    )  # fmt: skip


def collect_reports(
    paths: list[str] | None,
    include_all: bool,
    warning: float,
    critical: float,
    mounts_reader: MountsReader = read_mounts,
    usage_fn: UsageFn = shutil.disk_usage,
) -> tuple[list[DiskReport], list[DiskReport]]:
    """Devuelve (informes, ignorados).

    Al descubrir montajes automáticamente se ignoran los ilegibles (p. ej. capas de
    contenedores sin permiso) siempre que haya al menos uno legible. Con --path un
    fallo de lectura es UNKNOWN: el usuario pidió esa ruta expresamente.
    """
    if paths:
        try:
            known = mounts_reader()
        except CliError:
            known = []  # sin /proc se puede comprobar igualmente la ruta pedida
        targets = [find_mount(path, known) for path in paths]
    else:
        targets = select_mounts(mounts_reader(), include_all)
    if not targets:
        raise CliError("no hay puntos de montaje que comprobar")
    reports = [check_mount(target, warning, critical, usage_fn) for target in targets]
    readable = [r for r in reports if r.error is None]
    if paths or not readable:
        return reports, []
    return readable, [r for r in reports if r.error is not None]


def validate_thresholds(warning: float, critical: float) -> None:
    if warning >= critical:
        raise CliError(
            f"el umbral de aviso (-w {warning:g}) debe ser menor que el crítico (-c {critical:g})",
            EXIT_USAGE,
        )


def summary_line(reports: list[DiskReport], status: Status, warning: float, critical: float) -> str:
    problems = [r for r in reports if r.status is not Status.OK]
    limits = f"aviso >= {warning:g}%, crítico >= {critical:g}%"
    if not problems:
        return f"DISK OK - {len(reports)} puntos de montaje por debajo del umbral ({limits})"
    detail = ", ".join(
        f"{r.mountpoint} {r.percent:.1f}% usado" if r.percent is not None
        else f"{r.mountpoint} ilegible ({r.error})"
        for r in problems
    )  # fmt: skip
    return f"DISK {status.name} - {detail} ({limits})"


def render_text(reports: list[DiskReport], status: Status, warning: float, critical: float) -> str:
    rows = [
        [
            r.mountpoint, r.device, r.fstype, format_bytes(r.total), format_bytes(r.used),
            format_bytes(r.free), "-" if r.percent is None else f"{r.percent:.1f}%", r.status.name,
        ]
        for r in reports
    ]  # fmt: skip
    table = render_table(
        ["MONTAJE", "DISPOSITIVO", "TIPO", "TOTAL", "USADO", "LIBRE", "USO", "ESTADO"],
        rows,
        right_aligned=(3, 4, 5, 6),
    )
    return f"{summary_line(reports, status, warning, critical)}\n\n{table}"


def to_dict(
    reports: list[DiskReport],
    status: Status,
    warning: float,
    critical: float,
    skipped: list[DiskReport] | None = None,
) -> dict:
    return {
        "check": "disk",
        "status": status.name,
        "exit_code": int(status),
        "thresholds": {"warning": warning, "critical": critical},
        "mounts": [
            {
                "mountpoint": r.mountpoint,
                "device": r.device,
                "fstype": r.fstype,
                "total_bytes": r.total,
                "used_bytes": r.used,
                "free_bytes": r.free,
                "used_percent": None if r.percent is None else round(r.percent, 1),
                "status": r.status.name,
                "error": r.error,
            }
            for r in reports
        ],
        "skipped": [{"mountpoint": r.mountpoint, "error": r.error} for r in skipped or []],
    }


def run(args: argparse.Namespace) -> int:
    validate_thresholds(args.warning, args.critical)
    reports, skipped = collect_reports(
        args.path, args.include_all, args.warning, args.critical,
        mounts_reader=read_mounts, usage_fn=shutil.disk_usage,
    )  # fmt: skip
    status = worst_status(r.status for r in reports)
    if args.json:
        print(dump_json(to_dict(reports, status, args.warning, args.critical, skipped)))
    else:
        print(render_text(reports, status, args.warning, args.critical))
    for report in skipped:
        print(f"aviso: se ignora {report.mountpoint}: {report.error}", file=sys.stderr)
    return int(status)


def add_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "disk",
        help="uso de disco por punto de montaje",
        description="Comprueba el porcentaje de uso de cada punto de montaje.",
    )
    parser.add_argument(
        "-w", "--warning", type=percent_arg, default=DEFAULT_WARNING, metavar="PCT",
        help=f"umbral de aviso en %% de uso (por defecto {DEFAULT_WARNING:g})",
    )  # fmt: skip
    parser.add_argument(
        "-c", "--critical", type=percent_arg, default=DEFAULT_CRITICAL, metavar="PCT",
        help=f"umbral crítico en %% de uso (por defecto {DEFAULT_CRITICAL:g})",
    )  # fmt: skip
    parser.add_argument(
        "-p", "--path", action="append", metavar="RUTA",
        help="comprueba solo esta ruta (se puede repetir); por defecto, todos los montajes reales",
    )  # fmt: skip
    parser.add_argument(
        "-a", "--all", action="store_true", dest="include_all",
        help="incluye también sistemas de ficheros virtuales (tmpfs, proc...)",
    )  # fmt: skip
    parser.add_argument("--json", action="store_true", help="salida en JSON")
    parser.set_defaults(handler=run)
