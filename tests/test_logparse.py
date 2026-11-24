from datetime import UTC, datetime, timedelta, timezone

import pytest

from devops_cli.logparse import (
    FORMAT_ACCESS,
    FORMAT_SYSLOG,
    classify_level,
    detect_format,
    parse_access_line,
    parse_syslog_line,
)

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)

ACCESS = (
    '203.0.113.7 - - [24/Nov/2026:08:01:26 +0100] "GET /api/products?page=2 HTTP/1.1" 200 9444 '
    '"-" "Mozilla/5.0"'
)


def test_parse_access_combined_line() -> None:
    entry = parse_access_line(ACCESS)
    assert entry is not None
    assert entry.ip == "203.0.113.7"
    assert entry.method == "GET"
    assert entry.path == "/api/products?page=2"
    assert entry.status == 200
    assert entry.timestamp == datetime(2026, 11, 24, 7, 1, 26, tzinfo=UTC)


def test_parse_access_common_format_with_dash_size_and_negative_offset() -> None:
    line = '198.51.100.4 - frank [10/Oct/2026:13:55:36 -0700] "POST /x HTTP/1.0" 304 -'
    entry = parse_access_line(line)
    assert entry is not None
    assert entry.timestamp.utcoffset() == timedelta(hours=-7)
    assert entry.status == 304


def test_parse_access_malformed_request_is_kept() -> None:
    entry = parse_access_line('192.0.2.1 - - [24/Nov/2026:08:00:00 +0000] "-" 400 0')
    assert entry is not None
    assert (entry.method, entry.path, entry.status) == ("-", "-", 400)


@pytest.mark.parametrize(
    "line",
    [
        "",
        "texto cualquiera",
        '1.2.3.4 - - [24/Foo/2026:08:00:00 +0000] "GET / HTTP/1.1" 200 1',  # mes inexistente
        '1.2.3.4 - - [31/Feb/2026:08:00:00 +0000] "GET / HTTP/1.1" 200 1',  # fecha imposible
        '1.2.3.4 - - [fecha rara] "GET / HTTP/1.1" 200 1',
    ],
)
def test_parse_access_rejects_garbage(line: str) -> None:
    assert parse_access_line(line) is None


def test_parse_classic_syslog_line() -> None:
    line = "Nov 24 09:13:01 web01 sshd[812]: Failed password for root from 203.0.113.7 port 22"
    entry = parse_syslog_line(line, NOW)
    assert entry is not None
    assert entry.timestamp == datetime(2026, 11, 24, 9, 13, 1, tzinfo=UTC)
    assert (entry.host, entry.program, entry.level) == ("web01", "sshd", "error")
    assert entry.message.startswith("Failed password")


def test_parse_syslog_single_digit_day_is_space_padded() -> None:
    entry = parse_syslog_line("Nov  3 01:02:03 h cron: tarea ok", NOW)
    assert entry is not None
    assert entry.timestamp.day == 3
    assert entry.level == "info"


def test_syslog_future_date_belongs_to_previous_year() -> None:
    entry = parse_syslog_line("Dec 31 23:59:00 h cron: ok", NOW)
    assert entry is not None
    assert entry.timestamp.year == 2025


def test_parse_iso_syslog_line() -> None:
    line = "2026-11-24T09:13:01.123456+01:00 web01 nginx[9]: upstream timed out (error)"
    entry = parse_syslog_line(line, NOW)
    assert entry is not None
    assert entry.timestamp == datetime(2026, 11, 24, 8, 13, 1, 123456, tzinfo=UTC)
    assert entry.program == "nginx"


def test_parse_iso_syslog_with_zulu_suffix() -> None:
    entry = parse_syslog_line("2026-11-24T09:13:01Z h prog: hola", NOW)
    assert entry is not None
    assert entry.timestamp == datetime(2026, 11, 24, 9, 13, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    "line",
    [
        "",
        "basura",
        "Foo 24 09:13:01 h prog: msg",  # mes inexistente
        "Feb 30 09:13:01 h prog: msg",  # día imposible
        "2026-13-45T09:13:01Z h prog: msg",  # fecha ISO imposible
    ],
)
def test_parse_syslog_rejects_garbage(line: str) -> None:
    assert parse_syslog_line(line, NOW) is None


def test_parse_syslog_without_reference_uses_current_time() -> None:
    year = datetime.now(UTC).year
    entry = parse_syslog_line("Jan  1 00:00:01 h prog: msg")
    assert entry is not None
    assert entry.timestamp.year in (year, year - 1)


@pytest.mark.parametrize(
    ("message", "level"),
    [
        ("Kernel panic - not syncing", "critical"),
        ("Out of memory: Killed process 12", "critical"),
        ("EMERG: disk gone", "critical"),
        ("Failed password for root", "error"),
        ("connect() failed (111)", "error"),
        ("Permission denied", "error"),
        ("Invalid user admin", "error"),
        ("something ERROR happened", "error"),
        ("disk WARNING: smart changed", "warning"),
        ("Started Daily apt activities.", "info"),
        ("Accepted publickey for deploy", "info"),
    ],
)
def test_classify_level(message: str, level: str) -> None:
    assert classify_level(message) == level


def test_detect_format() -> None:
    syslog = "Nov 24 09:13:01 h prog: msg"
    assert detect_format([ACCESS, ACCESS, syslog]) == FORMAT_ACCESS
    assert detect_format([syslog, syslog, ACCESS], NOW) == FORMAT_SYSLOG
    assert detect_format(["nada reconocible"]) is None
    assert detect_format([]) is None


def test_access_timestamp_keeps_fixed_offset() -> None:
    entry = parse_access_line(ACCESS)
    assert entry is not None
    assert entry.timestamp.tzinfo == timezone(timedelta(hours=1))
