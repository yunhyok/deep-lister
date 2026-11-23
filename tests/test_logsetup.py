"""Tests for the diagnostic log file."""

from __future__ import annotations

import logging
import os
import zipfile
from pathlib import Path

import pytest

from deeplister import logsetup
from deeplister.models import ScanOptions
from deeplister.scanner import ScanEngine

DATA_DIR = Path(__file__).parent / "data"


@pytest.fixture
def session_log(tmp_path: Path):
    path = logsetup.start_file_logging(tmp_path / "logs")
    assert path is not None
    try:
        yield path
    finally:
        logsetup.stop_file_logging()


def _read(path: Path) -> str:
    logsetup.current_log_size()  # flush
    return path.read_text(encoding="utf-8-sig")


def test_session_header_and_per_archive_timestamp_diagnostics(session_log: Path) -> None:
    ScanEngine(ScanOptions(max_workers=2)).scan(
        [DATA_DIR / "7zip_default_no_ctime.7z", DATA_DIR / "7zip_mtc_on.7z"]
    )
    text = _read(session_log)

    assert "세션 시작" in text
    assert "py7zr" in text and "임시 폴더" in text
    assert "스캔 시작: 대상 2개" in text

    by_archive = {
        line.split("스캔 완료: ")[1].split(" | ")[0]: line
        for line in text.splitlines()
        if "7z 스캔 완료: " in line
    }
    default_line = by_archive[str(DATA_DIR / "7zip_default_no_ctime.7z")]
    stored_line = by_archive[str(DATA_DIR / "7zip_mtc_on.7z")]
    assert "생성 시각 0/2" in default_line and "수정 시각 2/2" in default_line
    assert "kCTime" in default_line  # states why: the header has no creation-time property
    assert "생성 시각 2/2" in stored_line
    assert "kCTime" not in stored_line

    assert "생성 시각이 저장되지 않은 압축파일 1개" in text
    assert "7z 내부: 생성 날짜 2 / 4" in text


def test_warnings_are_logged_with_traceback(session_log: Path, tmp_path: Path) -> None:
    broken = tmp_path / "broken.7z"
    broken.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 64)  # valid signature, garbage header

    result = ScanEngine(ScanOptions(max_workers=2)).scan([broken])
    assert len(result.warnings) == 1

    text = _read(session_log)
    assert "WARNING" in text
    assert str(broken) in text
    assert result.warnings[0].reason in text


def test_export_log_slice_contains_only_records_after_offset(
    session_log: Path, tmp_path: Path
) -> None:
    with zipfile.ZipFile(tmp_path / "first.zip", "w") as zf:
        zf.writestr("a.txt", b"a")
    with zipfile.ZipFile(tmp_path / "second.zip", "w") as zf:
        zf.writestr("b.txt", b"b")

    ScanEngine(ScanOptions(max_workers=1)).scan([tmp_path / "first.zip"])
    offset = logsetup.current_log_size()
    assert offset > 0
    ScanEngine(ScanOptions(max_workers=1)).scan([tmp_path / "second.zip"])

    copy_path = logsetup.export_log_slice(tmp_path / "out" / "scan.log", offset)
    assert copy_path == tmp_path / "out" / "scan.log"
    sliced = copy_path.read_text(encoding="utf-8-sig")
    assert "second.zip" in sliced
    assert "first.zip" not in sliced
    assert "세션 시작" not in sliced

    full = logsetup.export_log_slice(tmp_path / "out" / "full.log")
    assert full is not None
    assert "first.zip" in full.read_text(encoding="utf-8-sig")


def test_logging_is_optional_and_restartable(tmp_path: Path) -> None:
    assert logsetup.current_log_path() is None
    assert logsetup.current_log_size() == 0
    assert logsetup.export_log_slice(tmp_path / "none.log") is None

    # A scan without file logging must not raise or leave handlers behind
    ScanEngine(ScanOptions(max_workers=1)).scan([DATA_DIR / "7zip_mtc_on.7z"])

    first = logsetup.start_file_logging(tmp_path / "logs")
    assert first is not None and first.is_file()
    assert logsetup.start_file_logging(tmp_path / "other") == first  # already active
    logsetup.stop_file_logging()
    logsetup.stop_file_logging()  # idempotent
    assert logsetup.current_log_path() is None
    assert not [
        h for h in logging.getLogger("deeplister").handlers if isinstance(h, logging.FileHandler)
    ]


def test_unwritable_log_folder_disables_logging(tmp_path: Path) -> None:
    blocker = tmp_path / "not_a_dir"
    blocker.write_bytes(b"file in the way")
    assert logsetup.start_file_logging(blocker / "logs") is None
    assert logsetup.current_log_path() is None


def test_old_logs_are_pruned(tmp_path: Path) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    stale = []
    for i in range(logsetup.MAX_LOG_FILES + 5):
        old_log = log_dir / f"{logsetup.LOG_FILE_PREFIX}20200101_0000{i:02d}_1.log"
        old_log.write_text("x")
        os.utime(old_log, (1_600_000_000 + i, 1_600_000_000 + i))  # higher i = more recent
        stale.append(old_log)
    (log_dir / "unrelated.txt").write_text("keep me")

    path = logsetup.start_file_logging(log_dir)
    try:
        assert path is not None
        remaining = set(log_dir.glob(f"{logsetup.LOG_FILE_PREFIX}*.log"))
        assert len(remaining) == logsetup.MAX_LOG_FILES
        assert path in remaining
        assert not any(old_log in remaining for old_log in stale[:6])  # oldest ones go first
        assert all(old_log in remaining for old_log in stale[6:])
        assert (log_dir / "unrelated.txt").is_file()
    finally:
        logsetup.stop_file_logging()
