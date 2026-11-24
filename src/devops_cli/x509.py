"""Lector mínimo de certificados X.509 en DER, solo con la biblioteca estándar.

`ssl.getpeercert()` devuelve un diccionario vacío cuando no se valida la cadena
de confianza, así que se extraen a mano las fechas de validez y los nombres.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from .common import printable

_TAG_OID = 0x06
_TAG_UTC_TIME = 0x17
_TAG_GENERALIZED_TIME = 0x18
_TAG_BMP_STRING = 0x1E
_TAG_SEQUENCE = 0x30
_TAG_CONTEXT_0 = 0xA0

_OID_COMMON_NAME = bytes.fromhex("550403")
_OID_ORGANIZATION = bytes.fromhex("55040a")

_TBS_FIELDS_NEEDED = 5  # serie, algoritmo, emisor, validez, sujeto


class CertificateError(ValueError):
    """El certificado no se puede interpretar."""


@dataclass(frozen=True)
class CertificateInfo:
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime


def _read(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Lee un elemento TLV: devuelve (etiqueta, contenido, posición siguiente)."""
    if offset + 2 > len(data):
        raise CertificateError("estructura DER truncada")
    tag = data[offset]
    length = data[offset + 1]
    pos = offset + 2
    if length & 0x80:
        size = length & 0x7F
        if size == 0 or size > 4 or pos + size > len(data):
            raise CertificateError("longitud DER no válida")
        length = int.from_bytes(data[pos : pos + size], "big")
        pos += size
    end = pos + length
    if end > len(data):
        raise CertificateError("estructura DER truncada")
    return tag, data[pos:end], end


def _children(content: bytes) -> list[tuple[int, bytes]]:
    items: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(content):
        tag, value, offset = _read(content, offset)
        items.append((tag, value))
    return items


def _decode_string(tag: int, value: bytes) -> str:
    encoding = "utf-16-be" if tag == _TAG_BMP_STRING else "utf-8"
    return printable(value.decode(encoding, errors="replace"))


def _name(content: bytes) -> str:
    """Extrae el CN (o, en su defecto, la organización) de un Name."""
    common_name = organization = None
    for _, rdn in _children(content):
        for _, attribute in _children(rdn):
            items = _children(attribute)
            if len(items) != 2 or items[0][0] != _TAG_OID:
                continue
            text = _decode_string(*items[1])
            if items[0][1] == _OID_COMMON_NAME:
                common_name = text
            elif items[0][1] == _OID_ORGANIZATION:
                organization = text
    return common_name or organization or "-"


def _parse_time(tag: int, value: bytes) -> datetime:
    text = value.decode("ascii")
    if tag == _TAG_UTC_TIME and len(text) == 13 and text.endswith("Z"):
        year = int(text[:2])
        year += 1900 if year >= 50 else 2000  # RFC 5280, 4.1.2.5.1
        rest = text[2:-1]
    elif tag == _TAG_GENERALIZED_TIME and len(text) == 15 and text.endswith("Z"):
        year = int(text[:4])
        rest = text[4:-1]
    else:
        raise CertificateError("formato de fecha no soportado")
    month, day, hour, minute, second = (int(rest[i : i + 2]) for i in range(0, 10, 2))
    return datetime(year, month, day, hour, minute, second, tzinfo=UTC)


def parse_certificate(der: bytes) -> CertificateInfo:
    """Interpreta un certificado DER y devuelve sujeto, emisor y validez."""
    try:
        tag, certificate, _ = _read(der, 0)
        if tag != _TAG_SEQUENCE:
            raise CertificateError("no es un certificado X.509")
        tag, tbs, _ = _read(certificate, 0)
        if tag != _TAG_SEQUENCE:
            raise CertificateError("no es un certificado X.509")
        fields = _children(tbs)
        if fields and fields[0][0] == _TAG_CONTEXT_0:
            fields = fields[1:]  # versión explícita
        if len(fields) < _TBS_FIELDS_NEEDED:
            raise CertificateError("certificado incompleto")
        times = _children(fields[3][1])
        if len(times) != 2:
            raise CertificateError("periodo de validez no válido")
        return CertificateInfo(
            subject=_name(fields[4][1]),
            issuer=_name(fields[2][1]),
            not_before=_parse_time(*times[0]),
            not_after=_parse_time(*times[1]),
        )
    except CertificateError:
        raise
    except (ValueError, IndexError) as exc:
        raise CertificateError(f"certificado ilegible: {exc}") from exc
