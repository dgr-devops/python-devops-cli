"""Fixtures compartidas: zona horaria fija y servidor TLS local autofirmado."""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

OPENSSL = shutil.which("openssl")


@pytest.fixture(autouse=True)
def utc_timezone(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Fija TZ=UTC para que los tests de fechas no dependan de la máquina."""
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


@pytest.fixture(scope="session")
def make_cert(tmp_path_factory: pytest.TempPathFactory) -> Callable[..., tuple[Path, Path]]:
    """Genera (y cachea) un certificado autofirmado: devuelve (cert.pem, clave.pem)."""
    if OPENSSL is None:
        pytest.skip("openssl no está disponible")
    cache: dict[tuple[int, str], tuple[Path, Path]] = {}

    def factory(days: int = 90, cn: str = "localhost") -> tuple[Path, Path]:
        key = (days, cn)
        if key not in cache:
            folder = tmp_path_factory.mktemp("cert")
            cert, private = folder / "cert.pem", folder / "key.pem"
            subprocess.run(
                [
                    OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", str(private),
                    "-out", str(cert), "-days", str(days), "-subj", f"/CN={cn}/O=Pruebas",
                ],
                check=True,
                capture_output=True,
            )  # fmt: skip
            cache[key] = (cert, private)
        return cache[key]

    return factory


@pytest.fixture
def cert_der(make_cert: Callable[..., tuple[Path, Path]]) -> Callable[..., bytes]:
    """Devuelve el certificado generado en formato DER."""

    def factory(days: int = 90, cn: str = "localhost") -> bytes:
        cert, _ = make_cert(days, cn)
        return ssl.PEM_cert_to_DER_cert(cert.read_text())

    return factory


class _TlsServer:
    """Servidor TLS en un hilo que solo completa el handshake y cierra."""

    def __init__(self, cert: Path, key: Path) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        self._context = context
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(5)
        self._sock.settimeout(0.1)
        self.port: int = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (TimeoutError, OSError):
                continue
            try:
                with self._context.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                conn.close()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._sock.close()


@pytest.fixture
def tls_server(make_cert: Callable[..., tuple[Path, Path]]) -> Iterator[Callable[..., int]]:
    """Arranca servidores TLS locales; `start(days)` devuelve el puerto."""
    servers: list[_TlsServer] = []

    def start(days: int = 90, cn: str = "localhost") -> int:
        cert, key = make_cert(days, cn)
        server = _TlsServer(cert, key)
        servers.append(server)
        return server.port

    yield start
    for server in servers:
        server.close()


@pytest.fixture
def closed_port() -> int:
    """Un puerto local en el que no escucha nadie."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
