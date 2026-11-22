"""Tests for multi-threaded recursive folder, file, and nested archive scanning."""

from __future__ import annotations

import io
import os
import struct
import tarfile
import threading
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import py7zr
import pytest

from deeplister.models import EntryKind, ScanOptions
from deeplister.scanner import ScanEngine, detect_archive_type


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
