import argparse
import json

import pytest

from devops_cli.common import (
    CliError,
    Status,
    dump_json,
    format_bytes,
    non_negative_int,
    percent_arg,
    positive_float,
    positive_int,
    printable,
    render_table,
    worst_status,
)


def test_status_values_match_nagios_exit_codes() -> None:
    assert [int(s) for s in (Status.OK, Status.WARNING, Status.CRITICAL, Status.UNKNOWN)] == [
        0,
        1,
        2,
        3,
    ]


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([Status.OK, Status.OK], Status.OK),
        ([Status.OK, Status.WARNING], Status.WARNING),
        ([Status.WARNING, Status.CRITICAL, Status.OK], Status.CRITICAL),
        ([Status.OK, Status.UNKNOWN], Status.UNKNOWN),
        ([Status.UNKNOWN, Status.WARNING], Status.WARNING),
        ([Status.UNKNOWN, Status.CRITICAL], Status.CRITICAL),
        ([], Status.UNKNOWN),
    ],
)
def test_worst_status(statuses: list[Status], expected: Status) -> None:
    assert worst_status(statuses) is expected


def test_cli_error_keeps_exit_code() -> None:
    assert CliError("fallo").exit_code == 3
    assert CliError("uso", 64).exit_code == 64


@pytest.mark.parametrize(
    ("size", "expected"),
    [(0, "0 B"), (512, "512 B"), (1024, "1.0 KiB"), (1536, "1.5 KiB"), (5 * 1024**3, "5.0 GiB")],
)
def test_format_bytes(size: int, expected: str) -> None:
    assert format_bytes(size) == expected


def test_format_bytes_caps_at_tib() -> None:
    assert format_bytes(2048 * 1024**4) == "2048.0 TiB"


def test_render_table_aligns_columns() -> None:
    table = render_table(["A", "NUM"], [["x", "5"], ["largo", "123"]], right_aligned=(1,))
    lines = table.splitlines()
    assert lines[0] == "A      NUM"
    assert lines[2] == "x        5"
    assert lines[3] == "largo  123"


def test_dump_json_keeps_accents() -> None:
    text = dump_json({"msg": "caducó"})
    assert "caducó" in text
    assert json.loads(text) == {"msg": "caducó"}


@pytest.mark.parametrize("text", ["0", "55.5", "100"])
def test_percent_arg_accepts_valid(text: str) -> None:
    assert percent_arg(text) == float(text)


@pytest.mark.parametrize("text", ["-1", "100.1", "abc"])
def test_percent_arg_rejects_invalid(text: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        percent_arg(text)


def test_positive_int() -> None:
    assert positive_int("3") == 3
    for bad in ("0", "-2", "x"):
        with pytest.raises(argparse.ArgumentTypeError):
            positive_int(bad)


def test_positive_float() -> None:
    assert positive_float("0.5") == 0.5
    for bad in ("0", "-1", "x"):
        with pytest.raises(argparse.ArgumentTypeError):
            positive_float(bad)


@pytest.mark.parametrize("text", ["nan", "inf", "-inf", "1e400", "0", "-1", "3601", "x"])
def test_positive_float_rejects_non_finite_and_out_of_range(text: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        positive_float(text)


def test_non_negative_int() -> None:
    assert non_negative_int("0") == 0
    for bad in ("-1", "x"):
        with pytest.raises(argparse.ArgumentTypeError):
            non_negative_int(bad)


def test_printable_replaces_control_characters_and_surrogates() -> None:
    assert printable("ok\x1b[31m\nlinea\x7f\udcff") == "ok?[31m?linea??"
    assert printable("acentuación ñ") == "acentuación ñ"
