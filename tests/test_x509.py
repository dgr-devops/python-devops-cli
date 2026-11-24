from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest

from devops_cli.x509 import CertificateError, _decode_string, _parse_time, parse_certificate

CN_OID = "550403"
ORG_OID = "55040a"
UTC_TIME = 0x17
UTF8 = 0x0C


def tlv(tag: int, content: bytes) -> bytes:
    size = len(content)
    if size < 0x80:
        length = bytes([size])
    else:
        raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def name(*attrs: tuple[str, int, bytes]) -> bytes:
    rdns = b"".join(
        tlv(0x31, tlv(0x30, tlv(0x06, bytes.fromhex(oid)) + tlv(tag, value)))
        for oid, tag, value in attrs
    )
    return tlv(0x30, rdns)


def build(
    subject: bytes,
    issuer: bytes,
    not_before: bytes = b"260101000000Z",
    not_after: bytes = b"270101000000Z",
    time_tag: int = UTC_TIME,
) -> bytes:
    validity = tlv(0x30, tlv(time_tag, not_before) + tlv(time_tag, not_after))
    fields = (
        tlv(0xA0, tlv(0x02, b"\x02"))
        + tlv(0x02, b"\x01")
        + tlv(0x30, tlv(0x06, b"\x2a"))
        + issuer
        + validity
        + subject
    )
    return tlv(0x30, tlv(0x30, fields))


CN = name((CN_OID, UTF8, b"ejemplo.test"))


def test_parse_real_certificate(cert_der: Callable[..., bytes]) -> None:
    info = parse_certificate(cert_der(90, "ejemplo.test"))
    assert info.subject == "ejemplo.test"
    assert info.issuer == "ejemplo.test"
    assert info.not_after - info.not_before == timedelta(days=90)
    assert info.not_after > datetime.now(UTC)


def test_parse_generalized_time_for_far_future(cert_der: Callable[..., bytes]) -> None:
    info = parse_certificate(cert_der(9000))
    assert info.not_after.year >= 2050


def test_parse_synthetic_certificate() -> None:
    info = parse_certificate(build(CN, name((CN_OID, UTF8, b"CA interna"))))
    assert (info.subject, info.issuer) == ("ejemplo.test", "CA interna")
    assert info.not_before == datetime(2026, 1, 1, tzinfo=UTC)
    assert info.not_after == datetime(2027, 1, 1, tzinfo=UTC)


def test_two_digit_year_from_1950_is_previous_century() -> None:
    info = parse_certificate(build(CN, CN, not_before=b"990101000000Z"))
    assert info.not_before.year == 1999


def test_falls_back_to_organization_then_dash() -> None:
    org_only = name((ORG_OID, UTF8, b"Mi Empresa"))
    empty = name()
    info = parse_certificate(build(org_only, empty))
    assert (info.subject, info.issuer) == ("Mi Empresa", "-")


def test_long_form_length_is_supported() -> None:
    long_name = name((CN_OID, UTF8, b"a" * 300))
    assert parse_certificate(build(long_name, CN)).subject == "a" * 300


def test_decode_bmp_string() -> None:
    assert _decode_string(0x1E, "ñandú".encode("utf-16-be")) == "ñandú"


def test_parse_time_generalized() -> None:
    assert _parse_time(0x18, b"20991231235959Z") == datetime(2099, 12, 31, 23, 59, 59, tzinfo=UTC)


@pytest.mark.parametrize(
    "der",
    [
        b"",
        b"\x30",
        tlv(0x02, b"\x01"),  # no es una SEQUENCE
        tlv(0x30, tlv(0x02, b"\x01")),  # tbs no es una SEQUENCE
        b"\x30\x80\x00",  # longitud indefinida
        b"\x30\x05\x01",  # contenido más corto que la longitud declarada
        tlv(0x30, tlv(0x30, b"")),  # tbs vacío
        build(CN, CN, not_before=b"2601010000Z"),  # fecha con formato incorrecto
        build(CN, CN, not_before=b"26ab01000000Z"),  # fecha no numérica
        build(CN, CN, not_before=b"261301000000Z"),  # mes 13
        build(CN, CN, time_tag=0x0C),  # etiqueta de fecha no soportada
    ],
)
def test_malformed_certificates_raise_certificate_error(der: bytes) -> None:
    with pytest.raises(CertificateError):
        parse_certificate(der)


def test_validity_with_one_date_is_rejected() -> None:
    validity = tlv(0x30, tlv(UTC_TIME, b"260101000000Z"))
    fields = tlv(0x02, b"\x01") + tlv(0x30, b"") + CN + validity + CN
    with pytest.raises(CertificateError):
        parse_certificate(tlv(0x30, tlv(0x30, fields)))
