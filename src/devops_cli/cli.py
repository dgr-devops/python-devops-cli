"""Punto de entrada: define el parser, enruta subcomandos y traduce errores a códigos de salida."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import Any

from . import __version__, disk, logs, tls
from .common import EXIT_USAGE, CliError

PROG = "devops-cli"
EXIT_INTERRUPTED = 130


class _HelpFormatter(argparse.HelpFormatter):
    def add_usage(self, usage: Any, actions: Any, groups: Any, prefix: str | None = None) -> None:
        super().add_usage(usage, actions, groups, "uso: " if prefix is None else prefix)


class _Parser(argparse.ArgumentParser):
    """ArgumentParser en español que sale con 64 (uso incorrecto) en vez de 2."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("formatter_class", _HelpFormatter)
        kwargs["add_help"] = False
        super().__init__(*args, **kwargs)
        self._positionals.title = "argumentos"
        self._optionals.title = "opciones"
        self.add_argument(
            "-h", "--help", action="help", default=argparse.SUPPRESS,
            help="muestra esta ayuda y termina",
        )  # fmt: skip

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog=PROG,
        description="Utilidades de operaciones: disco, caducidad TLS y resumen de logs.",
        epilog=(
            "Códigos de salida: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN (error de ejecución), "
            "64 uso incorrecto."
        ),
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}",
                        help="muestra la versión y termina")  # fmt: skip
    subparsers = parser.add_subparsers(dest="command", metavar="COMANDO", required=True)
    for module in (disk, tls, logs):
        module.add_parser(subparsers)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Ejecuta la CLI y devuelve el código de salida (nunca lanza por fallos esperados)."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return int(args.handler(args))
    except SystemExit as exc:  # --help, --version o error de uso
        return exc.code if isinstance(exc.code, int) else 0
    except CliError as exc:
        print(f"{PROG}: error: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print(f"{PROG}: interrumpido", file=sys.stderr)
        return EXIT_INTERRUPTED
