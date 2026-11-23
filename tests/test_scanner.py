"""Tests for multi-threaded recursive folder, file, and nested archive scanning."""

from __future__ import annotations

import errno
import io
import os
import struct
import tarfile
import threading
import time
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

import py7zr

from deeplister import scanner as scanner_module
from deeplister.models import (
    SOURCE_7Z,
    SOURCE_FILESYSTEM,
    SOURCE_ZIP,
    EntryKind,
    ScanOptions,
)
from deeplister.scanner import ScanEngine, detect_archive_type

DATA_DIR = Path(__file__).parent / "data"


def _to_local_naive(utc_dt: datetime) -> datetime:
    """Mirror the scanner's convention: timestamps are reported as naive local time."""
    return utc_dt.astimezone().replace(tzinfo=None)


def _build_zip_with_ut_field(
    name: str, data: bytes, mtime: int, atime: int, ctime: int
) -> bytes:
    """Hand-build a ZIP whose "UT" extra field follows the Info-ZIP layout exactly.

    The local header carries modification, access and creation time; the central directory
    copy keeps the same flag byte but only the modification time.
    """
    raw_name = name.encode("ascii")
    crc = zlib.crc32(data)
    local_extra = struct.pack("<HHBiii", 0x5455, 13, 0x07, mtime, atime, ctime)
    central_extra = struct.pack("<HHBi", 0x5455, 5, 0x07, mtime)
    dos_time, dos_date = 0, (2020 - 1980) << 9 | 1 << 5 | 1

    local = (
        struct.pack(
            "<4s5H3L2H",
            b"PK\x03\x04",
            20,
            0,
            0,
            dos_time,
            dos_date,
            crc,
            len(data),
            len(data),
            len(raw_name),
            len(local_extra),
        )
        + raw_name
        + local_extra
        + data
    )
    central = (
        struct.pack(
            "<4s6H3L5H2L",
            b"PK\x01\x02",
            20,
            20,
            0,
            0,
            dos_time,
            dos_date,
            crc,
            len(data),
            len(data),
            len(raw_name),
            len(central_extra),
            0,
            0,
            0,
            0,
            0,
        )
        + raw_name
        + central_extra
    )
    end = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


def _make_ntfs_extra(mtime_dt: datetime, ctime_dt: datetime) -> bytes:
    """Build a valid ZIP 0x000A NTFS extra field with Windows FILETIME timestamps."""
    epoch_diff = 11644473600
    m_ft = int((mtime_dt.timestamp() + epoch_diff) * 10_000_000)
    c_ft = int((ctime_dt.timestamp() + epoch_diff) * 10_000_000)
    sub_data = struct.pack("<QQQ", m_ft, m_ft, c_ft)
    payload = struct.pack("<IHH", 0, 0x0001, len(sub_data)) + sub_data
    return struct.pack("<HH", 0x000A, len(payload)) + payload


def test_detect_archive_type() -> None:
    assert detect_archive_type("sample.zip") == "zip"
    assert detect_archive_type("DATA.7Z") == "7z"
    assert detect_archive_type("backup.tar.gz") == "tar"
    assert detect_archive_type("backup.tgz") == "tar"
    assert detect_archive_type("backup.tar.xz") == "tar"
    assert detect_archive_type("legacy.rar") == "unsupported_rar"
    assert detect_archive_type("notes.txt") is None


def test_recursive_folder_and_deeply_nested_archives(tmp_path: Path) -> None:
    """Verify folder -> zip -> 7z -> tar.gz -> zip recursive scanning."""
    root = tmp_path / "workspace"
    sub = root / "sub_folder"
    sub.mkdir(parents=True)
    (root / "plain.txt").write_bytes(b"hello")
    (sub / "nested_plain.bin").write_bytes(b"0123456789")

    # Level 4 (innermost): inner.zip
    inner_zip_buf = io.BytesIO()
    with zipfile.ZipFile(inner_zip_buf, "w", compression=zipfile.ZIP_DEFLATED) as z4:
        z4.writestr("deep/leaf.txt", b"leaf-content-12345")
    inner_zip_bytes = inner_zip_buf.getvalue()

    # Level 3: mid.tar.gz containing inner.zip and a regular file
    mid_tar_buf = io.BytesIO()
    with tarfile.open(fileobj=mid_tar_buf, mode="w:gz") as t3:
        ti = tarfile.TarInfo("tar_dir/inner.zip")
        ti.size = len(inner_zip_bytes)
        t3.addfile(ti, io.BytesIO(inner_zip_bytes))

        ti2 = tarfile.TarInfo("tar_readme.md")
        raw2 = b"# tar doc"
        ti2.size = len(raw2)
        t3.addfile(ti2, io.BytesIO(raw2))
    mid_tar_bytes = mid_tar_buf.getvalue()

    # Level 2: box.7z containing mid.tar.gz and a regular file
    box_7z_buf = io.BytesIO()
    with py7zr.SevenZipFile(box_7z_buf, "w") as s2:
        s2.writestr(mid_tar_bytes, "archives/mid.tar.gz")
        s2.writestr(b"seven-z-body", "docs/7z_note.txt")
    box_7z_bytes = box_7z_buf.getvalue()

    # Level 1: outer.zip inside workspace/sub_folder
    outer_zip_path = sub / "outer.zip"
    with zipfile.ZipFile(outer_zip_path, "w") as z1:
        z1.writestr("layer1/box.7z", box_7z_bytes)
        z1.writestr("layer1/top.txt", b"top")

    engine = ScanEngine(ScanOptions(max_workers=4, max_archive_depth=10))
    result = engine.scan([root])

    assert not result.warnings
    by_name = {e.name: e for e in result.entries}

    assert "plain.txt" in by_name
    assert by_name["plain.txt"].size == 5
    assert by_name["plain.txt"].archive_depth == 0

    assert "nested_plain.bin" in by_name
    assert by_name["nested_plain.bin"].size == 10

    assert "outer.zip" in by_name
    assert by_name["outer.zip"].kind == EntryKind.ARCHIVE
    assert by_name["outer.zip"].archive_depth == 0

    assert "top.txt" in by_name
    assert by_name["top.txt"].archive_depth == 1

    assert "box.7z" in by_name
    assert by_name["box.7z"].archive_depth == 1

    assert "7z_note.txt" in by_name
    assert by_name["7z_note.txt"].archive_depth == 2
    assert by_name["7z_note.txt"].size == len(b"seven-z-body")

    assert "mid.tar.gz" in by_name
    assert by_name["mid.tar.gz"].archive_depth == 2

    assert "tar_readme.md" in by_name
    assert by_name["tar_readme.md"].archive_depth == 3

    assert "inner.zip" in by_name
    assert by_name["inner.zip"].archive_depth == 3

    assert "leaf.txt" in by_name
    leaf = by_name["leaf.txt"]
    assert leaf.archive_depth == 4
    assert leaf.size == len(b"leaf-content-12345")
    assert "outer.zip" in leaf.directory
    assert "box.7z" in leaf.directory
    assert "mid.tar.gz" in leaf.directory
    assert "inner.zip" in leaf.directory
    assert leaf.directory.endswith(f"inner.zip{os.sep}deep")

    assert result.stats.max_depth_seen == 4


def test_zip_cp949_korean_filename_and_ntfs_timestamps(tmp_path: Path) -> None:
    """Ensure legacy CP949 ZIP filenames and NTFS extra timestamps are decoded properly."""
    zip_path = tmp_path / "korean_legacy.zip"
    cre_dt = datetime(2024, 5, 10, 9, 30, 0, tzinfo=timezone.utc)
    mod_dt = datetime(2025, 8, 20, 14, 15, 0, tzinfo=timezone.utc)

    # Create a genuine legacy CP949 ZIP (no UTF-8 flag 0x800, raw CP949 filename bytes)
    korean_name = "한글폴더/보고서_최종.xlsx"
    cp949_bytes = korean_name.encode("cp949")
    placeholder = "a" * len(cp949_bytes)

    info = zipfile.ZipInfo(placeholder)
    info.extra = _make_ntfs_extra(mod_dt, cre_dt)
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(info, b"korean-data")

    # Replace ASCII placeholder bytes in both local & central headers with raw CP949 bytes
    raw = zip_path.read_bytes().replace(placeholder.encode("ascii"), cp949_bytes)
    zip_path.write_bytes(raw)

    result = ScanEngine(ScanOptions(max_workers=2)).scan([zip_path])
    members = [e for e in result.entries if e.archive_depth == 1]
    assert len(members) == 1
    entry = members[0]
    assert entry.name == "보고서_최종.xlsx"
    assert entry.directory.endswith(f"korean_legacy.zip{os.sep}한글폴더")
    assert entry.created_at is not None
    assert entry.modified_at is not None
    assert entry.created_at.year == 2024
    assert entry.modified_at.year == 2025


def test_max_depth_limit_and_corrupt_archive_warnings(tmp_path: Path) -> None:
    """Verify max archive depth enforcement and graceful handling of corrupt/RAR files."""
    (tmp_path / "broken.zip").write_bytes(b"not a real zip")
    (tmp_path / "legacy.rar").write_bytes(b"Rar!fake")

    # Depth 2 archive (zip inside zip) with max_archive_depth=1
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w") as zi:
        zi.writestr("secret.txt", b"hidden")

    outer_zip = tmp_path / "two_level.zip"
    with zipfile.ZipFile(outer_zip, "w") as zo:
        zo.writestr("inner.zip", inner_buf.getvalue())

    result = ScanEngine(ScanOptions(max_workers=2, max_archive_depth=1)).scan([tmp_path])
    names = {e.name for e in result.entries}
    assert "inner.zip" in names
    assert "secret.txt" not in names  # blocked by max_archive_depth=1

    warning_reasons = " ".join(w.reason for w in result.warnings)
    assert "ZIP" in warning_reasons
    assert "RAR" in warning_reasons
    assert "최대 압축 중첩 깊이" in warning_reasons


def test_empty_dirs_and_exclude_archive_self(tmp_path: Path) -> None:
    empty = tmp_path / "empty_dir"
    empty.mkdir()
    zpath = tmp_path / "pack.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("inside.txt", b"abc")

    opts = ScanOptions(
        scan_archives=True,
        include_archive_files=False,
        include_empty_dirs=True,
        max_workers=2,
    )
    result = ScanEngine(opts).scan([tmp_path])
    names = {e.name for e in result.entries}
    assert "empty_dir" in names
    assert "inside.txt" in names
    assert "pack.zip" not in names


def test_multithreaded_large_fanout_and_cancel(tmp_path: Path) -> None:
    """Verify parallel scanning across many folders and clean cancellation."""
    for d in range(10):
        folder = tmp_path / f"dir_{d:02d}"
        folder.mkdir()
        for f in range(25):
            (folder / f"file_{f:03d}.txt").write_bytes(b"x" * (f + 1))

    result = ScanEngine(ScanOptions(max_workers=8)).scan([tmp_path])
    assert result.stats.total_entries == 250
    assert result.stats.worker_count == 8
    assert not result.stats.cancelled

    # Pre-cancelled event finishes immediately
    cancel = threading.Event()
    cancel.set()
    cancelled_result = ScanEngine(ScanOptions(max_workers=4), cancel_event=cancel).scan([tmp_path])
    assert cancelled_result.stats.cancelled is True
    assert cancelled_result.stats.total_entries == 0


def test_7z_creation_time_is_extracted_when_the_archive_stores_it() -> None:
    """7-Zip only writes creation time with -mtc=on; the scanner must surface it when present."""
    result = ScanEngine(ScanOptions(max_workers=2)).scan([DATA_DIR / "7zip_mtc_on.7z"])
    members = {e.name: e for e in result.entries if e.archive_depth == 1}

    assert set(members) == {"report.txt", "note.txt"}
    stored_created = datetime(2026, 11, 23, 0, 30, 37, tzinfo=timezone.utc)
    stored_modified = datetime(2024, 7, 30, 9, 26, 21, tzinfo=timezone.utc)
    for entry in members.values():
        assert entry.source == SOURCE_7Z
        assert entry.created_at is not None
        assert entry.created_at.replace(microsecond=0) == _to_local_naive(stored_created)
        assert entry.modified_at == _to_local_naive(stored_modified)

    assert result.stats.created_by_source[SOURCE_7Z] == (2, 2)
    assert result.stats.archives_without_created == 0


def test_7z_made_with_default_settings_has_no_creation_time() -> None:
    """A default 7-Zip archive stores no creation time: report it as missing, never guess."""
    result = ScanEngine(ScanOptions(max_workers=2)).scan(
        [DATA_DIR / "7zip_default_no_ctime.7z"]
    )
    members = [e for e in result.entries if e.archive_depth == 1]

    assert len(members) == 2
    assert all(e.created_at is None for e in members)
    assert all(e.modified_at is not None for e in members)
    assert not result.warnings

    stats = result.stats
    assert stats.created_by_source[SOURCE_7Z] == (0, 2)
    assert stats.archives_without_created == 1
    assert stats.created_missing >= 2  # + the .7z file itself where the OS has no birth time
    assert stats.created_present + stats.created_missing == stats.total_entries


def test_zip_ut_creation_time_is_read_from_local_header(tmp_path: Path) -> None:
    """Info-ZIP keeps the creation time only in the local header's UT field."""
    mtime = int(datetime(2021, 3, 4, 5, 6, 7, tzinfo=timezone.utc).timestamp())
    atime = int(datetime(2022, 1, 1, 0, 0, 0, tzinfo=timezone.utc).timestamp())
    ctime = int(datetime(2019, 2, 22, 16, 20, 42, tzinfo=timezone.utc).timestamp())
    zip_path = tmp_path / "infozip_style.zip"
    zip_path.write_bytes(_build_zip_with_ut_field("doc.txt", b"payload", mtime, atime, ctime))

    with zipfile.ZipFile(zip_path) as zf:  # sanity: a valid archive for the standard library
        assert zf.testzip() is None
        assert len(zf.infolist()[0].extra) == 9  # central copy: flags + modification time only

    result = ScanEngine(ScanOptions(max_workers=2)).scan([zip_path])
    members = [e for e in result.entries if e.archive_depth == 1]
    assert len(members) == 1
    entry = members[0]
    assert entry.source == SOURCE_ZIP
    assert entry.created_at == _to_local_naive(datetime.fromtimestamp(ctime, tz=timezone.utc))
    assert entry.modified_at == _to_local_naive(datetime.fromtimestamp(mtime, tz=timezone.utc))


def test_created_date_statistics_per_source(tmp_path: Path) -> None:
    (tmp_path / "plain.txt").write_bytes(b"x")
    with zipfile.ZipFile(tmp_path / "plain.zip", "w") as zf:
        zf.writestr("inside.txt", b"abc")  # zipfile writes no timestamp extra fields

    result = ScanEngine(ScanOptions(max_workers=2)).scan([tmp_path])
    stats = result.stats

    assert stats.created_by_source[SOURCE_ZIP] == (0, 1)
    assert stats.created_by_source[SOURCE_FILESYSTEM][1] == 2  # plain.txt + plain.zip
    assert stats.archives_without_created == 1
    assert stats.created_present + stats.created_missing == stats.total_entries
    assert sum(total for _present, total in stats.created_by_source.values()) == stats.total_entries


def _make_7z_with_nested_zip(path: Path) -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("deep.txt", b"deep")
    with py7zr.SevenZipFile(path, "w") as sz:
        sz.writestr(inner.getvalue(), "nested/inner.zip")
        sz.writestr(b"top", "top.txt")


def test_nested_7z_extraction_is_skipped_when_temp_space_is_insufficient(
    tmp_path: Path, monkeypatch
) -> None:
    archive = tmp_path / "outer.7z"
    _make_7z_with_nested_zip(archive)
    monkeypatch.setattr(scanner_module, "_free_bytes", lambda _path: 0)

    result = ScanEngine(ScanOptions(max_workers=2)).scan([archive])
    names = {e.name for e in result.entries}

    assert {"outer.7z", "inner.zip", "top.txt"} <= names
    assert "deep.txt" not in names
    assert len(result.warnings) == 1
    assert "임시 폴더 여유 공간이 부족" in result.warnings[0].reason
    assert "중첩 압축파일 1개" in result.warnings[0].reason


def test_disk_full_during_nested_extraction_reports_temp_folder(
    tmp_path: Path, monkeypatch
) -> None:
    archive = tmp_path / "outer.7z"
    _make_7z_with_nested_zip(archive)

    def _disk_full(self, filename):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(scanner_module._Isolated7zWriterFactory, "create", _disk_full)

    result = ScanEngine(ScanOptions(max_workers=2)).scan([archive])

    assert "deep.txt" not in {e.name for e in result.entries}
    assert len(result.warnings) == 1
    reason = result.warnings[0].reason
    assert "7z 중첩 압축파일 추출 오류" in reason
    assert "No space left on device" in reason
    assert "임시 폴더(" in reason and "여유 공간" in reason


def _nested_names(result) -> set[str]:
    return {e.name for e in result.entries}


def test_custom_temp_dir_is_used_and_cleaned_up(tmp_path: Path, monkeypatch) -> None:
    """Nested archives are unpacked in ScanOptions.temp_dir, which is left empty afterwards."""
    data = tmp_path / "data"
    data.mkdir()
    _make_7z_with_nested_zip(data / "outer.7z")  # nested zip is extracted by py7zr
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("spooled.txt", b"spooled")
    with zipfile.ZipFile(data / "outer.zip", "w") as zf:  # nested zip is spooled from a stream
        zf.writestr("inner2.zip", inner.getvalue())
    work = tmp_path / "work"
    work.mkdir()

    temp_files: list[Path] = []
    real_cleanup = ScanEngine._safe_cleanup

    def _record_cleanup(self, path: Path) -> None:
        if path.is_file():
            temp_files.append(path)
        real_cleanup(self, path)

    monkeypatch.setattr(ScanEngine, "_safe_cleanup", _record_cleanup)

    # max_memory_archive_bytes=0: nothing is kept in memory, every nested archive goes to disk
    options = ScanOptions(max_workers=2, max_memory_archive_bytes=0, temp_dir=str(work))
    result = ScanEngine(options).scan([data])

    assert not result.warnings
    assert {"deep.txt", "spooled.txt"} <= _nested_names(result)
    assert len(temp_files) == 2
    for path in temp_files:
        assert path.parent.parent == work  # <temp_dir>/deeplister_xxxx/nested….bin
        assert path.parent.name.startswith("deeplister_")
    assert list(work.iterdir()) == []


def test_unusable_temp_dir_falls_back_to_system_temp_with_warning(
    tmp_path: Path, monkeypatch
) -> None:
    archive = tmp_path / "outer.7z"
    _make_7z_with_nested_zip(archive)

    # 1) The folder does not exist (drive unplugged, typo in --temp-dir, ...)
    missing = tmp_path / "no_such_folder"
    result = ScanEngine(ScanOptions(max_workers=2, temp_dir=str(missing))).scan([archive])
    assert "deep.txt" in _nested_names(result)  # scanned anyway, in the system temp folder
    assert [w.path for w in result.warnings] == [str(missing)]
    assert "시스템 기본 임시 폴더" in result.warnings[0].reason
    assert "폴더를 찾을 수 없습니다" in result.warnings[0].reason
    assert not missing.exists()
    assert scanner_module.temp_dir_problem(missing) == "폴더를 찾을 수 없습니다"

    # 2) The folder exists but nothing can be created in it
    locked = tmp_path / "locked"
    locked.mkdir()
    real_mkdir = os.mkdir

    def _deny_inside_locked(path, *args, **kwargs):
        if Path(path).parent == locked:
            raise PermissionError(errno.EACCES, "Permission denied", str(path))
        return real_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(os, "mkdir", _deny_inside_locked)
    result = ScanEngine(ScanOptions(max_workers=2, temp_dir=str(locked))).scan([archive])
    assert "deep.txt" in _nested_names(result)
    assert [w.path for w in result.warnings] == [str(locked)]
    assert "시스템 기본 임시 폴더" in result.warnings[0].reason
    assert "폴더에 쓸 수 없습니다" in result.warnings[0].reason
    assert list(locked.iterdir()) == []

    # A usable folder reports no problem and the probe leaves nothing behind
    monkeypatch.undo()
    assert scanner_module.temp_dir_problem(locked) is None
    assert list(locked.iterdir()) == []


def test_temp_dir_inside_a_scan_target_is_not_listed(tmp_path: Path) -> None:
    """The scan's own work folder must not show up when the temp folder is being scanned too."""
    _make_7z_with_nested_zip(tmp_path / "outer.7z")
    work = tmp_path / "work"
    work.mkdir()

    options = ScanOptions(max_workers=2, include_empty_dirs=True, temp_dir=str(work))
    result = ScanEngine(options).scan([tmp_path])

    assert not result.warnings
    assert _nested_names(result) == {"outer.7z", "inner.zip", "top.txt", "deep.txt", "work"}
    assert not any("deeplister_" in e.directory for e in result.entries)


# --- Temp-folder space budget -------------------------------------------------------------


def _stored_zip(member: str, payload_size: int = 20_000) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr(member, b"x" * payload_size)
    return buf.getvalue()


def _limit_temp_space(monkeypatch, capacity: int) -> None:
    """Make the scanner see a temp drive that holds only `capacity` bytes."""

    def _free(path: Path) -> int:
        used = 0
        with os.scandir(path) as it:
            for de in it:
                try:
                    used += de.stat().st_size
                except OSError:  # removed meanwhile
                    pass
        return capacity - used

    monkeypatch.setattr(scanner_module, "_free_bytes", _free)


def _scan_or_fail_on_hang(engine: ScanEngine, paths: list[Path]):
    """Run a scan that exercises the wait logic; a deadlock fails the test instead of hanging."""
    results = []
    thread = threading.Thread(target=lambda: results.append(engine.scan(paths)), daemon=True)
    thread.start()
    thread.join(30)
    if thread.is_alive():
        engine.cancel_event.set()
        raise AssertionError("scan did not finish: workers are stuck waiting for temp space")
    # Every reservation was given back
    assert engine._temp_reserved == engine._temp_unwritten == 0
    assert engine._temp_pinned == engine._temp_waiters == 0
    return results[0]


def test_nested_archives_are_scanned_first_so_temp_space_is_reused(
    tmp_path: Path, monkeypatch
) -> None:
    """Unpacked nested archives jump the queue: one after another fits where all at once don't."""
    nested_size = 0
    for i in range(4):
        nested = _stored_zip(f"deep_{i}.txt")
        nested_size = len(nested)
        with py7zr.SevenZipFile(tmp_path / f"outer_{i}.7z", "w") as sz:
            sz.writestr(nested, "inner.zip")
    _limit_temp_space(monkeypatch, int(nested_size * 1.5))  # room for one nested archive

    engine = ScanEngine(ScanOptions(max_workers=1))
    result = _scan_or_fail_on_hang(engine, [tmp_path])

    assert not result.warnings
    assert {f"deep_{i}.txt" for i in range(4)} <= _nested_names(result)


def _make_zip_with_two_large_nested_zips(path: Path) -> int:
    first, second = _stored_zip("deep_1.txt"), _stored_zip("deep_2.txt")
    assert len(first) == len(second)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("n1.zip", first)
        zf.writestr("n2.zip", second)
    return len(first)


def test_worker_waits_for_temp_space_instead_of_failing(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    archive = tmp_path / "outer.zip"
    nested_size = _make_zip_with_two_large_nested_zips(archive)
    _limit_temp_space(monkeypatch, int(nested_size * 1.5))  # n1.zip and n2.zip don't fit together

    # n2.zip can only be spooled after the second worker has scanned and removed n1.zip.
    # Hold n1.zip back until the first worker is really waiting, so the wait is not left to timing.
    waiters_seen: list[int] = []
    real_scan_zip = ScanEngine._scan_zip

    def _scan_zip_after_parent_waits(self, task) -> None:
        if task.virtual_path.endswith("n1.zip"):
            deadline = time.monotonic() + 20
            while self._temp_waiters == 0 and time.monotonic() < deadline:
                time.sleep(0.005)
            waiters_seen.append(self._temp_waiters)
        real_scan_zip(self, task)

    monkeypatch.setattr(ScanEngine, "_scan_zip", _scan_zip_after_parent_waits)

    engine = ScanEngine(ScanOptions(max_workers=2, max_memory_archive_bytes=0))
    with caplog.at_level("INFO", logger="deeplister.scanner"):
        result = _scan_or_fail_on_hang(engine, [archive])

    assert waiters_seen == [1]
    assert not result.warnings
    assert {"deep_1.txt", "deep_2.txt"} <= _nested_names(result)
    assert "임시 폴더 공간 대기 후 확보" in caplog.text


def test_single_worker_does_not_wait_for_space_only_it_could_free(
    tmp_path: Path, monkeypatch
) -> None:
    archive = tmp_path / "outer.zip"
    nested_size = _make_zip_with_two_large_nested_zips(archive)
    _limit_temp_space(monkeypatch, int(nested_size * 1.5))

    # With one worker nobody else can scan n1.zip in the meantime: report n2.zip, don't hang
    engine = ScanEngine(ScanOptions(max_workers=1, max_memory_archive_bytes=0))
    result = _scan_or_fail_on_hang(engine, [archive])

    names = _nested_names(result)
    assert "deep_1.txt" in names and "deep_2.txt" not in names
    assert {"n1.zip", "n2.zip"} <= names  # the archive itself is still listed
    assert len(result.warnings) == 1
    assert result.warnings[0].path.endswith("n2.zip")
    assert "임시 폴더 여유 공간이 부족" in result.warnings[0].reason


def test_waiting_gives_up_when_only_the_archive_being_scanned_occupies_the_space(
    tmp_path: Path, monkeypatch
) -> None:
    """mid.7z sits in the temp folder while it is scanned, so waiting cannot make room for inner.zip."""
    inner = _stored_zip("deep.txt")
    mid = io.BytesIO()
    with py7zr.SevenZipFile(mid, "w") as sz:
        sz.writestr(inner, "inner.zip")
    with py7zr.SevenZipFile(tmp_path / "top.7z", "w") as sz:
        sz.writestr(mid.getvalue(), "mid.7z")
    _limit_temp_space(monkeypatch, len(inner))  # mid.7z fits, inner.zip fits, both do not

    engine = ScanEngine(ScanOptions(max_workers=2))
    result = _scan_or_fail_on_hang(engine, [tmp_path / "top.7z"])

    names = _nested_names(result)
    assert {"top.7z", "mid.7z", "inner.zip"} <= names and "deep.txt" not in names
    assert len(result.warnings) == 1
    assert result.warnings[0].path.endswith("mid.7z")
    assert "임시 폴더 여유 공간이 부족" in result.warnings[0].reason
