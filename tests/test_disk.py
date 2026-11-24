import json
from collections import namedtuple
from pathlib import Path

import pytest

from devops_cli import disk
from devops_cli.cli import main
from devops_cli.common import CliError, Status
from devops_cli.disk import (
    DiskReport,
    Mount,
    check_mount,
    classify,
    collect_reports,
    find_mount,
    parse_mounts,
    percent_used,
    read_mounts,
    select_mounts,
    summary_line,
    validate_thresholds,
)

Usage = namedtuple("Usage", "total used free")
GIB = 1024**3

PROC_MOUNTS_SAMPLE = """\
sysfs /sys sysfs rw,nosuid 0 0
proc /proc proc rw 0 0
/dev/sda1 / ext4 rw,relatime 0 0
tmpfs /run tmpfs rw 0 0
/dev/sda1 /etc/hosts ext4 rw 0 0
/dev/sdb1 /mnt/datos\\040backup xfs rw 0 0
/dev/sdc1 /home ext4 rw 0 0
malformed
"""

MOUNTS = [
    Mount("/dev/sda1", "/", "ext4"),
    Mount("/dev/sdb1", "/var", "xfs"),
    Mount("/dev/sdb1", "/var/log", "xfs"),
]


def fake_usage(table: dict[str, Usage]):
    def usage(path: str) -> Usage:
        if path not in table:
            raise FileNotFoundError(2, "No such file or directory")
        return table[path]

    return usage


def test_parse_mounts_decodes_escapes_and_skips_garbage() -> None:
    mounts = parse_mounts(PROC_MOUNTS_SAMPLE)
    assert Mount("/dev/sdb1", "/mnt/datos backup", "xfs") in mounts
    assert len(mounts) == 7


def test_select_mounts_filters_virtual_and_duplicates() -> None:
    selected = select_mounts(parse_mounts(PROC_MOUNTS_SAMPLE))
    assert [m.mountpoint for m in selected] == ["/", "/mnt/datos backup", "/home"]


def test_select_mounts_all_keeps_everything() -> None:
    mounts = parse_mounts(PROC_MOUNTS_SAMPLE)
    assert select_mounts(mounts, include_all=True) == mounts


def test_find_mount_uses_longest_prefix() -> None:
    assert find_mount("/var/log/nginx", MOUNTS) == Mount("/dev/sdb1", "/var/log/nginx", "xfs")
    assert find_mount("/var", MOUNTS).device == "/dev/sdb1"
    assert find_mount("/variable", MOUNTS).device == "/dev/sda1"  # no es hijo de /var
    assert find_mount("/tmp/x", []) == Mount("-", "/tmp/x", "-")


def test_percent_used_matches_df() -> None:
    assert percent_used(50, 50) == 50.0
    assert percent_used(0, 0) == 0.0
    assert percent_used(90, 10) == 90.0


@pytest.mark.parametrize(
    ("percent", "expected"),
    [(10, Status.OK), (79.9, Status.OK), (80, Status.WARNING), (89.9, Status.WARNING),
     (90, Status.CRITICAL), (100, Status.CRITICAL)],
)  # fmt: skip
def test_classify(percent: float, expected: Status) -> None:
    assert classify(percent, 80, 90) is expected


def test_check_mount_ok_and_error() -> None:
    usage = fake_usage({"/": Usage(100 * GIB, 85 * GIB, 15 * GIB)})
    report = check_mount(Mount("/dev/sda1", "/", "ext4"), 80, 90, usage)
    assert report.status is Status.WARNING
    assert report.percent == pytest.approx(85.0)
    assert report.error is None

    broken = check_mount(Mount("-", "/nada", "-"), 80, 90, usage)
    assert broken.status is Status.UNKNOWN
    assert broken.percent is None
    assert broken.error == "No such file or directory"


def test_collect_reports_auto_discovery_skips_unreadable_mounts() -> None:
    usage = fake_usage({"/": Usage(100, 10, 90), "/var": Usage(100, 95, 5)})
    reports, skipped = collect_reports(
        None, False, 80, 90, mounts_reader=lambda: MOUNTS, usage_fn=usage
    )
    assert [r.mountpoint for r in reports] == ["/", "/var"]
    assert skipped == []

    unreadable = fake_usage({"/": Usage(100, 10, 90)})
    reports, skipped = collect_reports(
        None, False, 80, 90, mounts_reader=lambda: MOUNTS, usage_fn=unreadable
    )
    assert [r.mountpoint for r in reports] == ["/"]
    assert [r.mountpoint for r in skipped] == ["/var"]


def test_collect_reports_all_unreadable_stays_unknown() -> None:
    reports, skipped = collect_reports(
        None, False, 80, 90, mounts_reader=lambda: MOUNTS, usage_fn=fake_usage({})
    )
    assert {r.status for r in reports} == {Status.UNKNOWN}
    assert skipped == []


def test_collect_reports_with_paths_reports_errors() -> None:
    usage = fake_usage({"/var/log": Usage(100, 50, 50)})
    reports, skipped = collect_reports(
        ["/var/log", "/nada"], False, 80, 90, mounts_reader=lambda: MOUNTS, usage_fn=usage
    )
    assert [r.status for r in reports] == [Status.OK, Status.UNKNOWN]
    assert reports[0].device == "/dev/sdb1"
    assert skipped == []


def test_collect_reports_paths_work_without_proc() -> None:
    def no_proc() -> list[Mount]:
        raise CliError("sin /proc")

    reports, _ = collect_reports(
        ["/x"], False, 80, 90, mounts_reader=no_proc, usage_fn=fake_usage({"/x": Usage(10, 1, 9)})
    )
    assert reports[0].device == "-"


def test_collect_reports_without_targets_fails() -> None:
    with pytest.raises(CliError, match="no hay puntos de montaje"):
        collect_reports(None, False, 80, 90, mounts_reader=lambda: [], usage_fn=fake_usage({}))


def test_read_mounts_from_file_and_error(tmp_path: Path) -> None:
    sample = tmp_path / "mounts"
    sample.write_text(PROC_MOUNTS_SAMPLE)
    assert len(read_mounts(sample)) == 7
    with pytest.raises(CliError, match="no se pudo leer"):
        read_mounts(tmp_path / "no-existe")


def test_validate_thresholds() -> None:
    validate_thresholds(80, 90)
    with pytest.raises(CliError) as excinfo:
        validate_thresholds(90, 90)
    assert excinfo.value.exit_code == 64


def test_summary_line_lists_problems() -> None:
    reports = [
        DiskReport("/", "d", "ext4", 100, 95, 5, 95.0, Status.CRITICAL),
        DiskReport("/x", "-", "-", 0, 0, 0, None, Status.UNKNOWN, error="Permission denied"),
        DiskReport("/ok", "d", "ext4", 100, 1, 99, 1.0, Status.OK),
    ]
    line = summary_line(reports, Status.CRITICAL, 80, 90)
    assert line.startswith("DISK CRITICAL - / 95.0% usado, /x ilegible (Permission denied)")
    assert "OK" in summary_line(reports[2:], Status.OK, 80, 90)


# --- CLI con sistema de ficheros simulado ---


@pytest.fixture
def fake_system(monkeypatch: pytest.MonkeyPatch) -> None:
    table = {
        "/": Usage(100 * GIB, 50 * GIB, 50 * GIB),
        "/var": Usage(100 * GIB, 85 * GIB, 15 * GIB),
    }
    monkeypatch.setattr(disk, "read_mounts", lambda: MOUNTS)
    monkeypatch.setattr(disk.shutil, "disk_usage", fake_usage(table))


def test_cli_text_output_and_exit_code(
    fake_system: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["disk"]) == 1
    out = capsys.readouterr().out
    assert out.startswith("DISK WARNING - /var 85.0% usado")
    assert "MONTAJE" in out


def test_cli_thresholds(fake_system: None) -> None:
    assert main(["disk", "-w", "40", "-c", "60"]) == 2
    assert main(["disk", "-w", "90", "-c", "95"]) == 0
    assert main(["disk", "--warning", "50", "--critical", "99"]) == 1


def test_cli_json(fake_system: None, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["disk", "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["check"] == "disk"
    assert data["status"] == "WARNING"
    assert data["thresholds"] == {"warning": 80.0, "critical": 90.0}
    assert [m["mountpoint"] for m in data["mounts"]] == ["/", "/var"]
    assert data["mounts"][1]["used_percent"] == 85.0


def test_cli_path_option(fake_system: None, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["disk", "-p", "/"]) == 0
    assert "DISK OK - 1 puntos" in capsys.readouterr().out
    assert main(["disk", "-p", "/no-existe"]) == 3


def test_cli_warns_about_skipped_mounts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def usage(path: str) -> Usage:
        if path == "/var":
            raise PermissionError(13, "Permission denied")
        return Usage(100, 10, 90)

    monkeypatch.setattr(disk, "read_mounts", lambda: MOUNTS)
    monkeypatch.setattr(disk.shutil, "disk_usage", usage)
    assert main(["disk"]) == 0
    captured = capsys.readouterr()
    assert "aviso: se ignora /var: Permission denied" in captured.err


def test_cli_invalid_thresholds(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["disk", "-w", "90", "-c", "80"]) == 64
    assert main(["disk", "-w", "abc"]) == 64
    assert main(["disk", "-c", "101"]) == 64
    assert "debe ser menor" in capsys.readouterr().err


def test_cli_without_proc_is_unknown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(disk, "PROC_MOUNTS", tmp_path / "no-existe")
    assert main(["disk"]) == 3
    assert "devops-cli: error: no se pudo leer" in capsys.readouterr().err


def test_real_system_smoke() -> None:
    """Sin simular nada: el sistema donde corran los tests siempre tiene un `/`."""
    assert main(["disk", "-p", "/", "-w", "99", "-c", "100"]) in (0, 1, 2)


def test_parse_mounts_decodes_utf8_escapes_and_strips_control_characters() -> None:
    mounts = parse_mounts(
        "/dev/sdb1 /mnt/caf\\303\\251 ext4 rw 0 0\n/dev/sdc1 /mnt/a\\033[31mb ext4 rw 0 0\n"
    )
    assert mounts[0].mountpoint == "/mnt/café"
    assert mounts[1].mountpoint == "/mnt/a?[31mb"


def test_read_mounts_tolerates_invalid_utf8(tmp_path: Path) -> None:
    sample = tmp_path / "mounts"
    sample.write_bytes(b"/dev/sdb1 /mnt/\xff\xfe ext4 rw 0 0\n/dev/sda1 / ext4 rw 0 0\n")
    assert [m.device for m in read_mounts(sample)] == ["/dev/sdb1", "/dev/sda1"]


def test_select_mounts_keeps_pseudo_devices_that_share_a_name() -> None:
    mounts = [Mount("overlay", "/a", "overlay"), Mount("overlay", "/b", "overlay")]
    assert len(select_mounts(mounts)) == 2


def test_find_mount_normalizes_the_path() -> None:
    assert find_mount("/var/../var/log/./x", MOUNTS).mountpoint == "/var/log/x"
    assert find_mount("/var/../etc", MOUNTS).device == "/dev/sda1"
