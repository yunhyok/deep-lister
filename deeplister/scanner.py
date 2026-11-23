"""Multi-threaded recursive filesystem and nested archive scanner."""

from __future__ import annotations

import errno
import io
import logging
import os
import queue
import shutil
import struct
import tarfile
import tempfile
import threading
import time
import uuid
import zipfile
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable

import py7zr
import py7zr.io

from .models import (
    SOURCE_7Z,
    SOURCE_FILESYSTEM,
    SOURCE_LABELS,
    SOURCE_TAR,
    SOURCE_ZIP,
    EntryKind,
    FileEntry,
    ScanOptions,
    ScanResult,
    ScanStats,
    ScanWarning,
    format_size,
)

log = logging.getLogger("deeplister.scanner")

# Archive extensions (multi-part suffixes checked first)
TAR_MULTI_SUFFIXES = (".tar.gz", ".tar.bz2", ".tar.xz")
TAR_SINGLE_SUFFIXES = (".tar", ".tgz", ".tbz2", ".txz")
ZIP_SUFFIXES = (".zip",)
SEVENZ_SUFFIXES = (".7z",)
UNSUPPORTED_ARCHIVE_SUFFIXES = (".rar",)

SUPPORTED_ARCHIVE_EXTENSIONS = (
    TAR_MULTI_SUFFIXES + TAR_SINGLE_SUFFIXES + ZIP_SUFFIXES + SEVENZ_SUFFIXES
)

# Windows FILETIME epoch: 1601-01-01 00:00:00 UTC
_FILETIME_EPOCH_DIFF_US = 11644473600 * 1_000_000


def detect_archive_type(filename: str) -> str | None:
    """Return archive type key ('zip', '7z', 'tar', 'unsupported_rar') or None."""
    lower = filename.lower()
    for ext in TAR_MULTI_SUFFIXES:
        if lower.endswith(ext):
            return "tar"
    for ext in TAR_SINGLE_SUFFIXES:
        if lower.endswith(ext):
            return "tar"
    for ext in ZIP_SUFFIXES:
        if lower.endswith(ext):
            return "zip"
    for ext in SEVENZ_SUFFIXES:
        if lower.endswith(ext):
            return "7z"
    for ext in UNSUPPORTED_ARCHIVE_SUFFIXES:
        if lower.endswith(ext):
            return "unsupported_rar"
    return None


def is_supported_archive(filename: str) -> bool:
    kind = detect_archive_type(filename)
    return kind in ("zip", "7z", "tar")


def _utc_ts_to_local(ts: float | int | None) -> datetime | None:
    if ts is None or ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(float(ts))
    except (OSError, OverflowError, ValueError):
        return None


def _filetime_to_local(filetime: int) -> datetime | None:
    """Convert 64-bit Windows FILETIME (100-ns ticks since 1601-01-01 UTC) to local datetime."""
    if not filetime or filetime <= 0:
        return None
    try:
        unix_us = (filetime // 10) - _FILETIME_EPOCH_DIFF_US
        if unix_us < 0:
            return None
        utc_dt = datetime.fromtimestamp(unix_us / 1_000_000, tz=timezone.utc)
        return utc_dt.astimezone().replace(tzinfo=None)
    except (OSError, OverflowError, ValueError):
        return None


def _any_7z_time_to_local(val: object) -> datetime | None:
    """Convert py7zr ArchiveTimestamp / datetime / int to naive local datetime."""
    if val is None:
        return None
    try:
        if hasattr(val, "as_datetime"):
            dt = val.as_datetime()
        elif isinstance(val, datetime):
            dt = val
        elif isinstance(val, int):
            return _filetime_to_local(val)
        else:
            return None
        if dt is None:
            return None
        if dt.tzinfo is not None:
            return dt.astimezone().replace(tzinfo=None)
        return dt
    except Exception:
        return None


def _decode_zip_filename(info: zipfile.ZipInfo) -> str:
    """Decode ZIP member filename, handling legacy Windows CP949 encodings."""
    if info.flag_bits & 0x800:
        return info.filename
    try:
        raw = info.filename.encode("cp437")
    except UnicodeEncodeError:
        return info.filename
    for enc in ("utf-8", "cp949"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return info.filename


# Which timestamp extra fields a ZIP member carries (bit flags from _parse_zip_extra)
_ZIP_HAS_NTFS = 0x1
_ZIP_HAS_UT = 0x2
_ZIP_UT_CTIME_IN_LOCAL = 0x4


def _parse_zip_extra(extra: bytes) -> tuple[datetime | None, datetime | None, int]:
    """Parse ZIP extra-field bytes into (created_at, modified_at, field_flags)."""
    ntfs_cre: datetime | None = None
    ntfs_mod: datetime | None = None
    ut_cre: datetime | None = None
    ut_mod: datetime | None = None
    seen = 0

    pos = 0
    end = len(extra)
    while pos + 4 <= end:
        header_id, data_size = struct.unpack_from("<HH", extra, pos)
        pos += 4
        if pos + data_size > end:
            break
        chunk = extra[pos : pos + data_size]
        pos += data_size

        # 0x000A: NTFS Extra Field (100-ns Windows FILETIME mtime, atime, ctime)
        if header_id == 0x000A and data_size >= 8:
            seen |= _ZIP_HAS_NTFS
            sub_pos = 4  # skip 4 reserved bytes
            while sub_pos + 4 <= data_size:
                tag, tag_size = struct.unpack_from("<HH", chunk, sub_pos)
                sub_pos += 4
                if sub_pos + tag_size > data_size:
                    break
                if tag == 0x0001 and tag_size == 24:
                    mtime_ft, _atime_ft, ctime_ft = struct.unpack_from("<QQQ", chunk, sub_pos)
                    ntfs_mod = _filetime_to_local(mtime_ft) or ntfs_mod
                    ntfs_cre = _filetime_to_local(ctime_ft) or ntfs_cre
                sub_pos += tag_size

        # 0x5455: Extended Timestamp (UT, signed 32-bit Unix seconds). The flag bits always
        # describe the LOCAL header; the central-directory copy holds the modification time only.
        elif header_id == 0x5455 and data_size >= 1:
            seen |= _ZIP_HAS_UT
            flags = chunk[0]
            offset = 1
            if (flags & 0x01) and offset + 4 <= data_size:
                ut_mod = _utc_ts_to_local(struct.unpack_from("<i", chunk, offset)[0])
                offset += 4
            if (flags & 0x02) and offset + 4 <= data_size:
                offset += 4  # atime
            if flags & 0x04:
                if offset + 4 <= data_size:
                    ut_cre = _utc_ts_to_local(struct.unpack_from("<i", chunk, offset)[0])
                else:
                    seen |= _ZIP_UT_CTIME_IN_LOCAL

    return ntfs_cre or ut_cre, ntfs_mod or ut_mod, seen


def _zip_dos_datetime(info: zipfile.ZipInfo) -> datetime | None:
    """Modification time from the mandatory DOS date/time header (creator's local time)."""
    try:
        y, mo, d, h, mi, sec = info.date_time
        if y >= 1980:
            return datetime(y, mo, d, h, mi, min(sec, 59))
    except ValueError:
        pass
    return None


def _read_zip_local_extra(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    """Read a member's local-header extra field (zipfile only exposes the central copy)."""
    fp = zf.fp
    if fp is None:
        return b""
    try:
        fp.seek(info.header_offset)
        header = fp.read(30)
        if len(header) != 30 or header[:4] != b"PK\x03\x04":
            return b""
        name_len, extra_len = struct.unpack_from("<HH", header, 26)
        fp.seek(name_len, os.SEEK_CUR)
        return fp.read(extra_len)
    except (OSError, ValueError):
        return b""


def _zip_member_timestamps(
    zf: zipfile.ZipFile, info: zipfile.ZipInfo
) -> tuple[datetime | None, datetime | None, int]:
    """Return (created_at, modified_at, field_flags) for a ZIP member."""
    created, modified, seen = _parse_zip_extra(info.extra or b"")
    if created is None and seen & _ZIP_UT_CTIME_IN_LOCAL:
        created = _parse_zip_extra(_read_zip_local_extra(zf, info))[0]
    return created, modified or _zip_dos_datetime(info), seen


def _free_bytes(path: Path) -> int | None:
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return None


def temp_dir_problem(path: str | Path) -> str | None:
    """Return why a folder cannot serve as the temp work folder, or None when it can."""
    folder = Path(path)
    try:
        if not folder.is_dir():
            return "폴더가 없습니다."
        with tempfile.TemporaryFile(dir=folder):
            pass
    except OSError as exc:
        return f"폴더에 쓸 수 없습니다: {exc}"
    return None


# Appended to disk-space warnings: the fix is in the user's hands
_TEMP_DIR_HINT = (
    "옵션의 '임시 폴더'를 여유 공간이 큰 드라이브로 바꾸거나 '최대 사용' 한도를 늘린 뒤 "
    "다시 스캔하세요."
)

# Automatic temp budget: leave about 10% of the free space (at least 256 MiB) untouched
_TEMP_MARGIN_MIN = 256 * 1024 * 1024

# How many archives one worker may scan on top of another while it waits for temp space
_MAX_HELP_DEPTH = 8


def auto_temp_limit(free_bytes: int | None) -> int | None:
    """Temp budget used when the user sets none: most of the free space, None if unknown."""
    if free_bytes is None:
        return None
    margin = min(max(free_bytes // 10, _TEMP_MARGIN_MIN), free_bytes // 2)
    return max(0, free_bytes - margin)


def _normalize_member_relpath(member_name: str) -> str:
    return member_name.replace("\\", "/").strip("/")


def _split_virtual_member_path(archive_virtual_path: str, member_name: str) -> tuple[str, str]:
    """Split an archive member's internal path into (directory_display, file_name)."""
    normalized = _normalize_member_relpath(member_name)
    if not normalized:
        return archive_virtual_path, ""
    pure = PurePosixPath(normalized)
    name = pure.name
    parent = str(pure.parent)
    if parent in ("", "."):
        return archive_virtual_path, name
    rel_win = parent.replace("/", os.sep)
    return f"{archive_virtual_path}{os.sep}{rel_win}", name


def _mark_ancestor_dirs(relpath: str, non_empty_dirs: set[str]) -> None:
    """Mark all ancestor folders of relpath as non-empty."""
    parts = relpath.split("/")
    for i in range(1, len(parts)):
        non_empty_dirs.add("/".join(parts[:i]))


def _stat_timestamps(st: os.stat_result) -> tuple[datetime | None, datetime | None]:
    """Extract (created_at, modified_at) from os.stat_result."""
    birth = getattr(st, "st_birthtime", None)
    if birth is None:
        birth = st.st_ctime if os.name == "nt" else None
    created = _utc_ts_to_local(birth)
    modified = _utc_ts_to_local(st.st_mtime)
    return created, modified


class _TempFile7zIO(py7zr.io.Py7zIO):
    """Stream 7z extracted payload directly to an isolated UUID temp file."""

    def __init__(self, target_path: Path) -> None:
        self.path = target_path
        self._fp = open(target_path, "w+b")
        self._size = 0

    def write(self, s: bytes | bytearray) -> int:
        n = self._fp.write(s)
        self._size += n
        return n

    def read(self, size: int | None = None) -> bytes:
        return self._fp.read() if size is None else self._fp.read(size)

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._fp.seek(offset, whence)

    def flush(self) -> None:
        self._fp.flush()

    def size(self) -> int:
        return self._size

    def close(self) -> None:
        if not self._fp.closed:
            self._fp.close()


class _Isolated7zWriterFactory(py7zr.io.WriterFactory):
    """Map arbitrary 7z member paths to safe UUID temp files (prevents path traversal/MAX_PATH)."""

    def __init__(self, temp_root: Path) -> None:
        self._temp_root = temp_root
        self.outputs: dict[str, Path] = {}
        self._writers: list[_TempFile7zIO] = []

    def create(self, filename: str) -> py7zr.io.Py7zIO:
        safe_path = self._temp_root / f"nested7z_{uuid.uuid4().hex}.bin"
        writer = _TempFile7zIO(safe_path)
        self.outputs[filename] = safe_path
        self._writers.append(writer)
        return writer

    def close_all(self) -> None:
        for w in self._writers:
            try:
                w.close()
            except Exception:
                pass


@dataclass(slots=True)
class ProgressSnapshot:
    """Periodic progress snapshot sent to UI."""

    entries_found: int
    archives_scanned: int
    warnings_count: int
    total_size: int
    elapsed_seconds: float
    current_path: str


@dataclass(slots=True)
class _DirTask:
    path: Path


@dataclass(slots=True)
class _ArchiveTask:
    archive_type: str
    virtual_path: str
    depth: int
    source_path: Path | None = None
    source_bytes: bytes | None = None
    memory_charge: int = 0
    cleanup_path: Path | None = None
    temp_charge: int = 0  # bytes of the temp budget held until this archive has been scanned
    started: float = 0.0


class ScanEngine:
    """Multi-threaded deadlock-free scanner for folders, files, and nested archives.

    Temp disk budget
    ----------------
    A nested archive that is unpacked to the temp folder holds part of a global budget until
    it has been scanned and deleted. A worker that needs space while the budget is exhausted
    waits for it, and meanwhile scans queued nested archives itself: finishing those is the
    only thing that frees space, so a pool in which every worker merely waited would hang.
    It gives up (with a warning) only when no one can free the space any more.
    """

    def __init__(
        self,
        options: ScanOptions | None = None,
        progress_callback: Callable[[ProgressSnapshot], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> None:
        self.options = options or ScanOptions()
        self.progress_callback = progress_callback
        self.cancel_event = cancel_event or threading.Event()

        self._task_queue: queue.Queue[_DirTask | _ArchiveTask] = queue.Queue()
        self._pending_lock = threading.Lock()
        self._pending_count = 0
        self._queued_bytes = 0
        self._done_event = threading.Event()

        self._result_lock = threading.Lock()
        self._entries: list[FileEntry] = []
        self._warnings: list[ScanWarning] = []
        self._archives_scanned = 0
        self._archives_without_created = 0
        self._total_size = 0
        self._max_depth_seen = 0
        self._current_path = ""
        self._last_progress_time = 0.0
        self._start_time = 0.0
        self._temp_root: Path | None = None

        # Temp disk budget (see class docstring); everything below is guarded by _temp_lock
        self._temp_lock = threading.Lock()
        self._temp_cond = threading.Condition(self._temp_lock)
        self._temp_tasks: deque[_ArchiveTask] = deque()  # queued archives holding temp files
        self._temp_limit: int | None = None  # None = unlimited
        self._temp_used = 0
        self._temp_peak = 0
        self._temp_wait_count = 0
        # Bumped whenever space is freed or an archive that would free space is queued.
        # A waiter is "settled" once it has looked at the current epoch and still cannot go on.
        self._temp_epoch = 0
        self._temp_settled_waiters = 0
        self._busy_workers = 0  # workers that have a task in progress
        self._tls = threading.local()  # per thread: budget held by its task stack, help depth

    def scan(self, input_paths: list[str | Path]) -> ScanResult:
        """Scan all provided files, folders, and archives recursively using worker threads."""
        self._start_time = time.perf_counter()
        self._last_progress_time = 0.0
        self._entries.clear()
        self._warnings.clear()
        self._archives_scanned = 0
        self._archives_without_created = 0
        self._total_size = 0
        self._max_depth_seen = 0
        self._current_path = ""
        self._done_event.clear()

        with self._temp_lock:
            self._temp_tasks.clear()
            self._temp_limit = None
            self._temp_used = 0
            self._temp_peak = 0
            self._temp_wait_count = 0
            self._temp_epoch = 0
            self._temp_settled_waiters = 0
            self._busy_workers = 0

        # Reset queue/accounting state so ScanEngine instances are safely reusable
        with self._pending_lock:
            self._pending_count = 0
            self._queued_bytes = 0
            while True:
                try:
                    self._task_queue.get_nowait()
                except queue.Empty:
                    break

        unique_paths: list[Path] = []
        seen_norm: set[str] = set()
        for raw in input_paths:
            try:
                p = Path(raw).resolve()
            except OSError as exc:
                self._add_warning(str(raw), f"경로를 해석할 수 없습니다: {exc}")
                continue
            key = os.path.normcase(str(p))
            if key not in seen_norm:
                seen_norm.add(key)
                unique_paths.append(p)

        worker_count = max(1, min(32, int(self.options.max_workers)))

        log.info("----- 스캔 시작: 대상 %d개 | %s", len(unique_paths), self.options)
        for p in unique_paths:
            log.info("대상: %s", p)

        temp_parent: str | None = None
        if self.options.temp_dir:
            problem = temp_dir_problem(self.options.temp_dir)
            if problem is None:
                temp_parent = str(self.options.temp_dir)
            else:
                self._add_warning(
                    str(self.options.temp_dir),
                    f"지정한 임시 폴더를 사용할 수 없어 시스템 임시 폴더({tempfile.gettempdir()})를 "
                    f"대신 사용했습니다: {problem}",
                )

        with tempfile.TemporaryDirectory(prefix="deeplister_", dir=temp_parent) as temp_dir:
            self._temp_root = Path(temp_dir)
            free = _free_bytes(self._temp_root)
            self._temp_limit = self._effective_temp_limit(free)
            log.info(
                "임시 작업 폴더: %s (여유 공간 %s, 사용 한도 %s)",
                temp_dir,
                format_size(free) if free is not None else "알 수 없음",
                format_size(self._temp_limit) if self._temp_limit is not None else "제한 없음",
            )

            for p in unique_paths:
                if self.cancel_event.is_set():
                    break
                if not p.exists():
                    self._add_warning(str(p), "경로를 찾을 수 없습니다.")
                    continue
                if p.is_dir():
                    self._enqueue(_DirTask(path=p))
                elif p.is_file():
                    self._process_filesystem_file(p)
                else:
                    self._add_warning(str(p), "지원하지 않는 파일 시스템 항목입니다.")

            if self._pending_count == 0:
                self._done_event.set()
            else:
                threads = [
                    threading.Thread(
                        target=self._worker_loop,
                        name=f"Worker-{i + 1}",
                        daemon=True,
                    )
                    for i in range(worker_count)
                ]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()

            self._temp_root = None

        elapsed = time.perf_counter() - self._start_time
        self._entries.sort(
            key=lambda e: (e.directory.casefold(), e.name.casefold(), e.archive_depth)
        )
        self._warnings.sort(key=lambda w: w.path.casefold())

        stats = self._build_stats(
            input_paths=[str(p) for p in unique_paths],
            elapsed=elapsed,
            worker_count=worker_count,
        )
        self._emit_progress(force=True)
        self._log_summary(stats)
        return ScanResult(entries=list(self._entries), warnings=list(self._warnings), stats=stats)

    def _try_reserve_memory(self, nbytes: int) -> bool:
        """Reserve from the global in-memory nested-archive budget."""
        if nbytes <= 0:
            return True
        if nbytes > self.options.max_memory_archive_bytes:
            return False
        with self._pending_lock:
            if self._queued_bytes + nbytes <= self.options.max_total_memory_bytes:
                self._queued_bytes += nbytes
                return True
            return False

    def _release_memory(self, nbytes: int) -> None:
        if nbytes <= 0:
            return
        with self._pending_lock:
            self._queued_bytes = max(0, self._queued_bytes - nbytes)

    def _effective_temp_limit(self, free_bytes: int | None) -> int | None:
        """Budget for this scan: the user's limit, never more than the disk can hold."""
        auto = auto_temp_limit(free_bytes)
        user = self.options.max_temp_bytes
        if user is not None and user > 0:
            return user if auto is None else min(user, auto)
        return auto

    def _enqueue(self, task: _DirTask | _ArchiveTask) -> None:
        if self.cancel_event.is_set():
            if isinstance(task, _ArchiveTask):
                self._release_memory(task.memory_charge)
                if task.cleanup_path is not None:
                    self._safe_cleanup(task.cleanup_path)
                self._release_temp(task.temp_charge)
            return
        with self._pending_lock:
            self._pending_count += 1
        if isinstance(task, _ArchiveTask) and task.temp_charge > 0:
            # Scanned before anything else: finishing it gives temp space back
            with self._temp_cond:
                self._temp_tasks.append(task)
                self._temp_changed()
        else:
            self._task_queue.put(task)

    def _finish_task(self) -> None:
        with self._pending_lock:
            self._pending_count -= 1
            if self._pending_count <= 0:
                self._done_event.set()

    def _next_task(self) -> _DirTask | _ArchiveTask | None:
        """Take the next task and mark this worker busy; archives holding temp files first."""
        with self._temp_lock:
            if self._temp_tasks:
                self._busy_workers += 1
                return self._temp_tasks.popleft()
        try:
            task = self._task_queue.get(timeout=0.05)
        except queue.Empty:
            return None
        with self._temp_lock:
            self._busy_workers += 1
        return task

    def _worker_loop(self) -> None:
        while not self._done_event.is_set() and not self.cancel_event.is_set():
            task = self._next_task()
            if task is None:
                continue
            try:
                self._run_task(task)
            finally:
                with self._temp_cond:
                    self._busy_workers -= 1
                    self._temp_cond.notify_all()  # waiters re-check whether anyone can still help

    def _run_task(self, task: _DirTask | _ArchiveTask) -> None:
        """Scan one task and release everything it held (also used while waiting for space)."""
        held_before = getattr(self._tls, "held", 0)
        if isinstance(task, _ArchiveTask):
            self._tls.held = held_before + task.temp_charge
        try:
            if not self.cancel_event.is_set():
                if isinstance(task, _DirTask):
                    self._scan_directory(task.path)
                else:
                    self._scan_archive(task)
        except Exception as exc:
            target = str(task.path) if isinstance(task, _DirTask) else task.virtual_path
            self._add_warning(target, self._describe_error("처리 중 오류", exc), exc=exc)
        finally:
            self._tls.held = held_before
            if isinstance(task, _ArchiveTask):
                self._release_memory(task.memory_charge)
                task.source_bytes = None
                if task.cleanup_path is not None:
                    self._safe_cleanup(task.cleanup_path)
                self._release_temp(task.temp_charge)  # after the file is really gone
            self._finish_task()

    def _temp_changed(self) -> None:
        """Start a new epoch: every waiter must look again. Caller holds _temp_lock."""
        self._temp_epoch += 1
        self._temp_settled_waiters = 0
        self._temp_cond.notify_all()

    def _reserve_temp(self, nbytes: int) -> bool:
        """Reserve temp disk space, waiting for other archives to be finished if necessary.

        While it waits, the worker scans queued archives that hold temp files, because
        finishing them is what frees space. Returns False when the scan was cancelled or the
        space can never become available: the request exceeds what this worker could ever
        get, or every busy worker has seen the current state and is waiting too.
        """
        if nbytes <= 0:
            return True
        limit = self._temp_limit
        if limit is not None and getattr(self._tls, "held", 0) + nbytes > limit:
            return False  # even with all other archives finished it would not fit

        help_depth = getattr(self._tls, "help_depth", 0)
        wait_started: float | None = None
        settled_epoch = -1  # epoch in which this thread is counted as a settled waiter

        def unsettle() -> None:
            nonlocal settled_epoch
            if settled_epoch == self._temp_epoch:
                self._temp_settled_waiters -= 1
            settled_epoch = -1

        with self._temp_cond:
            while True:
                if self.cancel_event.is_set():
                    unsettle()
                    return False
                if limit is None or self._temp_used + nbytes <= limit:
                    unsettle()
                    self._temp_used += nbytes
                    if self._temp_used > self._temp_peak:
                        self._temp_peak = self._temp_used
                    break

                if wait_started is None:
                    wait_started = time.perf_counter()
                    self._temp_wait_count += 1
                    log.info(
                        "임시 공간 대기: 필요 %s | 사용 중 %s / 한도 %s",
                        format_size(nbytes),
                        format_size(self._temp_used),
                        format_size(limit),
                    )

                if help_depth < _MAX_HELP_DEPTH and self._temp_tasks:
                    helped = self._temp_tasks.popleft()
                    unsettle()
                    self._temp_cond.release()
                    try:
                        self._tls.help_depth = help_depth + 1
                        try:
                            self._run_task(helped)
                        finally:
                            self._tls.help_depth = help_depth
                    finally:
                        self._temp_cond.acquire()
                    continue

                if settled_epoch != self._temp_epoch:
                    settled_epoch = self._temp_epoch
                    self._temp_settled_waiters += 1
                if self._temp_settled_waiters >= self._busy_workers:
                    # Every busy worker has seen this state and waits: nobody is left to
                    # free space, so waiting any longer would hang the scan
                    unsettle()
                    log.info(
                        "임시 공간 확보 포기: 필요 %s | 사용 중 %s / 한도 %s (공간을 비울 작업이 없음)",
                        format_size(nbytes),
                        format_size(self._temp_used),
                        format_size(limit),
                    )
                    return False

                self._temp_cond.wait(timeout=0.2)

        if wait_started is not None:
            log.info(
                "임시 공간 확보: %s | 대기 %.1f초",
                format_size(nbytes),
                time.perf_counter() - wait_started,
            )
        return True

    def _charge_temp(self, nbytes: int) -> None:
        """Account for temp space that is already on disk, without waiting."""
        if nbytes <= 0:
            return
        with self._temp_lock:
            self._temp_used += nbytes
            if self._temp_used > self._temp_peak:
                self._temp_peak = self._temp_used

    def _release_temp(self, nbytes: int) -> None:
        if nbytes <= 0:
            return
        with self._temp_cond:
            self._temp_used = max(0, self._temp_used - nbytes)
            self._temp_changed()

    def _temp_shortage_text(self, count: int, needed: int) -> str:
        """Warning text for nested archives skipped because the temp budget cannot hold them."""
        limit = self._temp_limit
        folder = self._temp_root.parent if self._temp_root is not None else tempfile.gettempdir()
        return (
            f"임시 폴더 여유 공간이 부족하여 중첩 압축파일 {count}개의 내부를 탐색하지 못했습니다 "
            f"(필요 {format_size(needed)}, 사용 한도 "
            f"{format_size(limit) if limit is not None else '제한 없음'}, 임시 폴더: {folder}). "
            f"{_TEMP_DIR_HINT}"
        )

    def _safe_cleanup(self, path: Path) -> None:
        try:
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            elif path.exists():
                path.unlink(missing_ok=True)
        except OSError:
            pass

    def _add_entries(self, new_entries: list[FileEntry], current_path: str = "") -> None:
        if not new_entries:
            return
        added_size = sum(e.size for e in new_entries if e.kind != EntryKind.DIRECTORY)
        max_d = max((e.archive_depth for e in new_entries), default=0)
        with self._result_lock:
            self._entries.extend(new_entries)
            self._total_size += added_size
            if max_d > self._max_depth_seen:
                self._max_depth_seen = max_d
            if current_path:
                self._current_path = current_path
        self._emit_progress()

    def _add_warning(self, path: str, reason: str, exc: BaseException | None = None) -> None:
        with self._result_lock:
            self._warnings.append(ScanWarning(path=path, reason=reason))
            self._current_path = path
        if exc is not None:
            log.warning("%s | %s", path, reason, exc_info=(type(exc), exc, exc.__traceback__))
        else:
            log.warning("%s | %s", path, reason)
        self._emit_progress()

    def _describe_error(self, prefix: str, exc: BaseException) -> str:
        """Warning text for an exception; adds temp-folder context when the disk is full."""
        text = f"{prefix}: {exc}"
        if isinstance(exc, OSError) and exc.errno == errno.ENOSPC and self._temp_root is not None:
            free = _free_bytes(self._temp_root)
            free_text = format_size(free) if free is not None else "알 수 없음"
            text += f" — 임시 폴더({self._temp_root.parent}) 여유 공간 {free_text}. {_TEMP_DIR_HINT}"
        return text

    def _finish_archive(
        self,
        task: _ArchiveTask,
        source: str,
        entries: list[FileEntry],
        note: str = "",
    ) -> None:
        """Tag an archive's entries with their source, log its timestamp coverage, publish them."""
        files = created = modified = 0
        for e in entries:
            e.source = source
            if e.kind == EntryKind.DIRECTORY:
                continue
            files += 1
            if e.created_at is not None:
                created += 1
            if e.modified_at is not None:
                modified += 1

        if files and not created:
            with self._result_lock:
                self._archives_without_created += 1

        if log.isEnabledFor(logging.INFO):
            if task.cleanup_path is not None:
                origin = "임시 파일"
            elif task.source_bytes is not None:
                origin = "메모리"
            else:
                origin = "디스크"
            log.info(
                "%s 스캔 완료: %s | 깊이 %d | 원본 %s | 파일 %d개 | 생성 시각 %d/%d | "
                "수정 시각 %d/%d | %.2f초%s",
                "7z" if source == SOURCE_7Z else source.upper(),
                task.virtual_path,
                task.depth,
                origin,
                files,
                created,
                files,
                modified,
                files,
                time.perf_counter() - task.started,
                f" | {note}" if note else "",
            )

        self._add_entries(entries, current_path=task.virtual_path)

    def _log_summary(self, stats: ScanStats) -> None:
        if not log.isEnabledFor(logging.INFO):
            return
        log.info(
            "----- 스캔 %s: 항목 %d개 | 탐색 압축파일 %d개 | 총 용량 %s | 경고 %d건 | %.2f초",
            "중지됨" if stats.cancelled else "완료",
            stats.total_entries,
            stats.archives_scanned,
            format_size(stats.total_size),
            stats.warnings_count,
            stats.elapsed_seconds,
        )
        log.info(
            "생성 날짜: 기록됨 %d개 / 없음 %d개 | 생성 시각이 저장되지 않은 압축파일 %d개",
            stats.created_present,
            stats.created_missing,
            stats.archives_without_created,
        )
        for source, (present, total) in stats.created_by_source.items():
            log.info("  %s: 생성 날짜 %d / %d", SOURCE_LABELS.get(source, source), present, total)
        log.info(
            "임시 공간: 한도 %s | 최대 사용 %s | 대기 %d회",
            format_size(stats.temp_limit_bytes)
            if stats.temp_limit_bytes is not None
            else "제한 없음",
            format_size(stats.temp_peak_bytes),
            stats.temp_wait_count,
        )
        if self._temp_used and not stats.cancelled:
            log.warning("임시 공간 정산 불일치: 스캔 종료 후에도 %d바이트가 사용 중으로 남음", self._temp_used)

    def _emit_progress(self, force: bool = False) -> None:
        if self.progress_callback is None:
            return
        now = time.perf_counter()
        if not force and (now - self._last_progress_time) < 0.08:
            return
        with self._result_lock:
            if not force and (now - self._last_progress_time) < 0.08:
                return
            self._last_progress_time = now
            snap = ProgressSnapshot(
                entries_found=len(self._entries),
                archives_scanned=self._archives_scanned,
                warnings_count=len(self._warnings),
                total_size=self._total_size,
                elapsed_seconds=now - self._start_time,
                current_path=self._current_path,
            )
        try:
            self.progress_callback(snap)
        except Exception:
            pass

    def _process_filesystem_file(self, path: Path) -> None:
        try:
            st = path.stat()
        except OSError as exc:
            self._add_warning(str(path), f"파일 정보를 읽을 수 없습니다: {exc}", exc=exc)
            return

        created, modified = _stat_timestamps(st)
        archive_type = detect_archive_type(path.name)
        is_arc = archive_type in ("zip", "7z", "tar")

        if is_arc:
            if self.options.include_archive_files or not self.options.scan_archives:
                self._add_entries(
                    [
                        FileEntry(
                            directory=str(path.parent),
                            name=path.name,
                            created_at=created,
                            modified_at=modified,
                            size=st.st_size,
                            kind=EntryKind.ARCHIVE,
                            archive_depth=0,
                        )
                    ],
                    current_path=str(path),
                )
            if self.options.scan_archives:
                self._enqueue(
                    _ArchiveTask(
                        archive_type=archive_type,
                        virtual_path=str(path),
                        depth=1,
                        source_path=path,
                    )
                )
        else:
            self._add_entries(
                [
                    FileEntry(
                        directory=str(path.parent),
                        name=path.name,
                        created_at=created,
                        modified_at=modified,
                        size=st.st_size,
                        kind=EntryKind.FILE,
                        archive_depth=0,
                    )
                ],
                current_path=str(path),
            )
            if archive_type == "unsupported_rar" and self.options.scan_archives:
                self._add_warning(
                    str(path),
                    "RAR 형식은 내장 엔진에서 지원되지 않아 압축 파일 자체만 기록했습니다.",
                )

    def _scan_directory(self, dir_path: Path) -> None:
        local_entries: list[FileEntry] = []
        has_children = False

        try:
            with os.scandir(dir_path) as it:
                for de in it:
                    if self.cancel_event.is_set():
                        return
                    has_children = True
                    try:
                        if de.is_dir(follow_symlinks=False):
                            self._enqueue(_DirTask(path=Path(de.path)))
                        elif de.is_file(follow_symlinks=False):
                            st = de.stat(follow_symlinks=False)
                            created, modified = _stat_timestamps(st)
                            archive_type = detect_archive_type(de.name)
                            is_arc = archive_type in ("zip", "7z", "tar")

                            if is_arc:
                                if (
                                    self.options.include_archive_files
                                    or not self.options.scan_archives
                                ):
                                    local_entries.append(
                                        FileEntry(
                                            directory=str(dir_path),
                                            name=de.name,
                                            created_at=created,
                                            modified_at=modified,
                                            size=st.st_size,
                                            kind=EntryKind.ARCHIVE,
                                            archive_depth=0,
                                        )
                                    )
                                if self.options.scan_archives:
                                    self._enqueue(
                                        _ArchiveTask(
                                            archive_type=archive_type,
                                            virtual_path=de.path,
                                            depth=1,
                                            source_path=Path(de.path),
                                        )
                                    )
                            else:
                                local_entries.append(
                                    FileEntry(
                                        directory=str(dir_path),
                                        name=de.name,
                                        created_at=created,
                                        modified_at=modified,
                                        size=st.st_size,
                                        kind=EntryKind.FILE,
                                        archive_depth=0,
                                    )
                                )
                                if (
                                    archive_type == "unsupported_rar"
                                    and self.options.scan_archives
                                ):
                                    self._add_warning(
                                        de.path,
                                        "RAR 형식은 내장 엔진에서 지원되지 않아 압축 파일 자체만 기록했습니다.",
                                    )
                    except OSError as exc:
                        self._add_warning(de.path, f"항목 접근 실패: {exc}", exc=exc)
        except OSError as exc:
            self._add_warning(str(dir_path), f"폴더 열기 실패: {exc}", exc=exc)
            return

        if not has_children and self.options.include_empty_dirs:
            try:
                st = dir_path.stat()
                created, modified = _stat_timestamps(st)
            except OSError:
                created, modified = None, None
            local_entries.append(
                FileEntry(
                    directory=str(dir_path.parent),
                    name=dir_path.name,
                    created_at=created,
                    modified_at=modified,
                    size=0,
                    kind=EntryKind.DIRECTORY,
                    archive_depth=0,
                )
            )

        self._add_entries(local_entries, current_path=str(dir_path))

    def _scan_archive(self, task: _ArchiveTask) -> None:
        if task.depth > self.options.max_archive_depth:
            self._add_warning(
                task.virtual_path,
                f"최대 압축 중첩 깊이({self.options.max_archive_depth})를 초과하여 탐색을 중단했습니다.",
            )
            return

        with self._result_lock:
            self._archives_scanned += 1
            self._current_path = task.virtual_path
        task.started = time.perf_counter()

        if task.archive_type == "zip":
            self._scan_zip(task)
        elif task.archive_type == "7z":
            self._scan_7z(task)
        elif task.archive_type == "tar":
            self._scan_tar(task)

    def _enqueue_nested_stream(
        self,
        nested_type: str,
        nested_virtual_path: str,
        next_depth: int,
        stream,
        declared_size: int,
    ) -> None:
        """Read a nested archive stream within global memory budget or spool to temp disk."""
        if self.cancel_event.is_set():
            return
        if next_depth > self.options.max_archive_depth:
            self._add_warning(
                nested_virtual_path,
                f"최대 압축 중첩 깊이({self.options.max_archive_depth})를 초과하여 탐색을 중단했습니다.",
            )
            return

        threshold = self.options.max_memory_archive_bytes
        can_try_memory = (
            declared_size >= 0
            and declared_size <= threshold
            and self._try_reserve_memory(max(declared_size, 1))
        )
        reserved = max(declared_size, 1) if can_try_memory else 0

        if can_try_memory:
            chunks: list[bytes] = []
            actual_size = 0
            spilled_path: Path | None = None
            spilled_fp = None
            spilled_bytes = 0  # temp budget charged for the spilled file
            try:
                while True:
                    if self.cancel_event.is_set():
                        if spilled_fp is not None:
                            spilled_fp.close()
                        if spilled_path is not None:
                            self._safe_cleanup(spilled_path)
                        self._release_memory(reserved)
                        self._release_temp(spilled_bytes)
                        return
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    actual_size += len(chunk)
                    if spilled_fp is None:
                        if actual_size > threshold and self._temp_root is not None:
                            spilled_path = self._temp_root / f"nested_{uuid.uuid4().hex}.bin"
                            spilled_fp = open(spilled_path, "wb")
                            for prev in chunks:
                                spilled_fp.write(prev)
                            chunks.clear()
                            spilled_fp.write(chunk)
                            self._release_memory(reserved)
                            reserved = 0
                            # Larger than declared: already on disk, so account for it as it grows
                            self._charge_temp(actual_size)
                            spilled_bytes = actual_size
                        else:
                            chunks.append(chunk)
                    else:
                        spilled_fp.write(chunk)
                        self._charge_temp(len(chunk))
                        spilled_bytes += len(chunk)
            except Exception:
                if spilled_fp is not None:
                    spilled_fp.close()
                if spilled_path is not None:
                    self._safe_cleanup(spilled_path)
                self._release_memory(reserved)
                self._release_temp(spilled_bytes)
                raise
            finally:
                if spilled_fp is not None and not spilled_fp.closed:
                    spilled_fp.close()

            if spilled_path is not None:
                self._enqueue(
                    _ArchiveTask(
                        archive_type=nested_type,
                        virtual_path=nested_virtual_path,
                        depth=next_depth,
                        source_path=spilled_path,
                        cleanup_path=spilled_path,
                        temp_charge=spilled_bytes,
                    )
                )
            else:
                payload = chunks[0] if len(chunks) == 1 else b"".join(chunks)
                chunks.clear()
                # Adjust reservation to exact payload length
                diff = len(payload) - reserved
                if diff > 0:
                    with self._pending_lock:
                        self._queued_bytes += diff
                elif diff < 0:
                    self._release_memory(-diff)
                self._enqueue(
                    _ArchiveTask(
                        archive_type=nested_type,
                        virtual_path=nested_virtual_path,
                        depth=next_depth,
                        source_bytes=payload,
                        memory_charge=len(payload),
                    )
                )
        else:
            if self._temp_root is None:
                return
            # The declared size is an upper bound: zipfile and tarfile never yield more
            charged = max(declared_size, 0)
            if not self._reserve_temp(charged):
                if not self.cancel_event.is_set():
                    self._add_warning(nested_virtual_path, self._temp_shortage_text(1, charged))
                return
            spilled_path = self._temp_root / f"nested_{uuid.uuid4().hex}.bin"
            written = 0
            try:
                with open(spilled_path, "wb") as out_fp:
                    while True:
                        if self.cancel_event.is_set():
                            out_fp.close()
                            self._safe_cleanup(spilled_path)
                            self._release_temp(charged)
                            return
                        chunk = stream.read(1024 * 1024)
                        if not chunk:
                            break
                        out_fp.write(chunk)
                        written += len(chunk)
            except Exception:
                self._safe_cleanup(spilled_path)
                self._release_temp(charged)
                raise

            if written < charged:
                self._release_temp(charged - written)
            elif written > charged:
                self._charge_temp(written - charged)

            self._enqueue(
                _ArchiveTask(
                    archive_type=nested_type,
                    virtual_path=nested_virtual_path,
                    depth=next_depth,
                    source_path=spilled_path,
                    cleanup_path=spilled_path,
                    temp_charge=written,
                )
            )

    def _scan_zip(self, task: _ArchiveTask) -> None:
        source = (
            io.BytesIO(task.source_bytes)
            if task.source_bytes is not None
            else task.source_path
        )
        if source is None:
            return

        local_entries: list[FileEntry] = []
        candidate_dirs: dict[str, FileEntry] = {}
        non_empty_dirs: set[str] = set()
        ntfs_fields = ut_fields = no_time_fields = 0

        try:
            with zipfile.ZipFile(source, "r") as zf:
                for info in zf.infolist():
                    if self.cancel_event.is_set():
                        return
                    decoded_name = _decode_zip_filename(info)
                    is_dir_entry = info.is_dir() or decoded_name.endswith(("/", "\\"))
                    relpath = _normalize_member_relpath(decoded_name)
                    if not relpath:
                        continue

                    _mark_ancestor_dirs(relpath, non_empty_dirs)

                    if is_dir_entry:
                        if self.options.include_empty_dirs:
                            directory, name = _split_virtual_member_path(
                                task.virtual_path, decoded_name
                            )
                            if name:
                                created, modified, _seen = _zip_member_timestamps(zf, info)
                                candidate_dirs[relpath] = FileEntry(
                                    directory=directory,
                                    name=name,
                                    created_at=created,
                                    modified_at=modified,
                                    size=0,
                                    kind=EntryKind.DIRECTORY,
                                    archive_depth=task.depth,
                                )
                        continue

                    directory, name = _split_virtual_member_path(
                        task.virtual_path, decoded_name
                    )
                    if not name:
                        continue
                    created, modified, seen = _zip_member_timestamps(zf, info)
                    if seen & _ZIP_HAS_NTFS:
                        ntfs_fields += 1
                    if seen & _ZIP_HAS_UT:
                        ut_fields += 1
                    if not seen & (_ZIP_HAS_NTFS | _ZIP_HAS_UT):
                        no_time_fields += 1
                    nested_type = detect_archive_type(name)
                    is_nested_supported = nested_type in ("zip", "7z", "tar")
                    member_vpath = f"{directory}{os.sep}{name}"

                    if is_nested_supported:
                        if self.options.include_archive_files:
                            local_entries.append(
                                FileEntry(
                                    directory=directory,
                                    name=name,
                                    created_at=created,
                                    modified_at=modified,
                                    size=info.file_size,
                                    kind=EntryKind.ARCHIVE,
                                    archive_depth=task.depth,
                                )
                            )
                        if info.flag_bits & 0x1:
                            self._add_warning(
                                member_vpath,
                                "암호화된 중첩 ZIP 항목이어서 내부를 탐색할 수 없습니다.",
                            )
                        else:
                            try:
                                with zf.open(info, "r") as member_stream:
                                    self._enqueue_nested_stream(
                                        nested_type=nested_type,
                                        nested_virtual_path=member_vpath,
                                        next_depth=task.depth + 1,
                                        stream=member_stream,
                                        declared_size=info.file_size,
                                    )
                            except RuntimeError as exc:
                                self._add_warning(
                                    member_vpath,
                                    f"중첩 압축파일 추출 실패(암호화 등): {exc}",
                                    exc=exc,
                                )
                            except Exception as exc:
                                self._add_warning(
                                    member_vpath,
                                    self._describe_error("중첩 압축파일 읽기 실패", exc),
                                    exc=exc,
                                )
                    else:
                        local_entries.append(
                            FileEntry(
                                directory=directory,
                                name=name,
                                created_at=created,
                                modified_at=modified,
                                size=info.file_size,
                                kind=EntryKind.ARCHIVE_MEMBER,
                                archive_depth=task.depth,
                            )
                        )
                        if nested_type == "unsupported_rar":
                            self._add_warning(
                                member_vpath,
                                "중첩 RAR 형식은 내장 엔진에서 지원되지 않아 파일 자체만 기록했습니다.",
                            )
        except zipfile.BadZipFile:
            self._add_warning(task.virtual_path, "손상되었거나 유효하지 않은 ZIP 파일입니다.")
            return
        except Exception as exc:
            self._add_warning(task.virtual_path, f"ZIP 열기 오류: {exc}", exc=exc)
            return

        if candidate_dirs:
            for rel, entry in candidate_dirs.items():
                if rel not in non_empty_dirs:
                    local_entries.append(entry)

        note = (
            f"시각 확장 필드: NTFS(0x000A) {ntfs_fields}개, UT(0x5455) {ut_fields}개, "
            f"없음 {no_time_fields}개"
        )
        self._finish_archive(task, SOURCE_ZIP, local_entries, note)

    def _scan_tar(self, task: _ArchiveTask) -> None:
        local_entries: list[FileEntry] = []
        candidate_dirs: dict[str, FileEntry] = {}
        non_empty_dirs: set[str] = set()

        try:
            if task.source_bytes is not None:
                tf_ctx = tarfile.open(fileobj=io.BytesIO(task.source_bytes), mode="r:*")
            elif task.source_path is not None:
                tf_ctx = tarfile.open(name=task.source_path, mode="r:*")
            else:
                return

            # Stream members sequentially in a single forward pass (fast + immediately cancellable)
            with tf_ctx as tf:
                for member in tf:
                    if self.cancel_event.is_set():
                        return
                    relpath = _normalize_member_relpath(member.name)
                    if not relpath:
                        continue
                    _mark_ancestor_dirs(relpath, non_empty_dirs)

                    if member.isdir():
                        if self.options.include_empty_dirs:
                            directory, name = _split_virtual_member_path(
                                task.virtual_path, member.name
                            )
                            if name:
                                modified = _utc_ts_to_local(member.mtime)
                                candidate_dirs[relpath] = FileEntry(
                                    directory=directory,
                                    name=name,
                                    created_at=None,
                                    modified_at=modified,
                                    size=0,
                                    kind=EntryKind.DIRECTORY,
                                    archive_depth=task.depth,
                                )
                        continue
                    if not member.isfile():
                        continue

                    directory, name = _split_virtual_member_path(
                        task.virtual_path, member.name
                    )
                    if not name:
                        continue

                    modified = _utc_ts_to_local(member.mtime)
                    created = None
                    pax = member.pax_headers or {}
                    for pax_key in ("LIBARCHIVE.creationtime", "ctime"):
                        if pax_key in pax:
                            try:
                                created = _utc_ts_to_local(float(pax[pax_key]))
                                break
                            except ValueError:
                                pass

                    nested_type = detect_archive_type(name)
                    is_nested_supported = nested_type in ("zip", "7z", "tar")
                    member_vpath = f"{directory}{os.sep}{name}"

                    if is_nested_supported:
                        if self.options.include_archive_files:
                            local_entries.append(
                                FileEntry(
                                    directory=directory,
                                    name=name,
                                    created_at=created,
                                    modified_at=modified,
                                    size=member.size,
                                    kind=EntryKind.ARCHIVE,
                                    archive_depth=task.depth,
                                )
                            )
                        try:
                            extracted = tf.extractfile(member)
                            if extracted is not None:
                                with extracted:
                                    self._enqueue_nested_stream(
                                        nested_type=nested_type,
                                        nested_virtual_path=member_vpath,
                                        next_depth=task.depth + 1,
                                        stream=extracted,
                                        declared_size=member.size,
                                    )
                        except Exception as exc:
                            self._add_warning(
                                member_vpath,
                                self._describe_error("TAR 내부 중첩 압축파일 읽기 실패", exc),
                                exc=exc,
                            )
                    else:
                        local_entries.append(
                            FileEntry(
                                directory=directory,
                                name=name,
                                created_at=created,
                                modified_at=modified,
                                size=member.size,
                                kind=EntryKind.ARCHIVE_MEMBER,
                                archive_depth=task.depth,
                            )
                        )
                        if nested_type == "unsupported_rar":
                            self._add_warning(
                                member_vpath,
                                "중첩 RAR 형식은 내장 엔진에서 지원되지 않아 파일 자체만 기록했습니다.",
                            )
        except (tarfile.TarError, EOFError, OSError) as exc:
            self._add_warning(task.virtual_path, f"TAR 압축파일 읽기 오류: {exc}", exc=exc)
            return

        if candidate_dirs:
            for rel, entry in candidate_dirs.items():
                if rel not in non_empty_dirs:
                    local_entries.append(entry)

        note = "TAR은 생성 시각을 저장하지 않음(pax 확장 헤더가 있을 때만 기록)"
        self._finish_archive(task, SOURCE_TAR, local_entries, note)

    def _scan_7z(self, task: _ArchiveTask) -> None:
        source = (
            io.BytesIO(task.source_bytes)
            if task.source_bytes is not None
            else task.source_path
        )
        if source is None:
            return

        local_entries: list[FileEntry] = []
        candidate_dirs: dict[str, FileEntry] = {}
        non_empty_dirs: set[str] = set()
        # (raw_member_name, nested_type, member_vpath, uncompressed_size)
        nested_targets: list[tuple[str, str, str, int]] = []
        has_ctime_property = False  # 7z header carries the optional creation-time property
        note = ""

        try:
            with py7zr.SevenZipFile(source, mode="r") as sz:
                if sz.needs_password():
                    self._add_warning(
                        task.virtual_path,
                        "암호화된 7z 파일이어서 내부를 탐색할 수 없습니다.",
                    )
                    return

                files_list = getattr(sz, "files", None)
                if files_list is not None:
                    for af in files_list:
                        if self.cancel_event.is_set():
                            return
                        if bool(getattr(af, "is_symlink", False)) or bool(
                            getattr(af, "is_junction", False)
                        ):
                            continue

                        raw_name = af.filename
                        relpath = _normalize_member_relpath(raw_name)
                        if not relpath:
                            continue
                        _mark_ancestor_dirs(relpath, non_empty_dirs)

                        is_dir = bool(getattr(af, "is_directory", False))
                        size = int(getattr(af, "uncompressed", 0) or 0)

                        # py7zr 1.1+ exposes creationtime via file_properties()
                        props = {}
                        if hasattr(af, "file_properties"):
                            try:
                                props = af.file_properties() or {}
                            except Exception:
                                props = {}
                        if "creationtime" in props:
                            has_ctime_property = True
                        raw_cre = props.get("creationtime", getattr(af, "creationtime", None))
                        raw_mod = props.get("lastwritetime", getattr(af, "lastwritetime", None))
                        created = _any_7z_time_to_local(raw_cre)
                        modified = _any_7z_time_to_local(raw_mod)

                        if is_dir:
                            if self.options.include_empty_dirs:
                                directory, name = _split_virtual_member_path(
                                    task.virtual_path, raw_name
                                )
                                if name:
                                    candidate_dirs[relpath] = FileEntry(
                                        directory=directory,
                                        name=name,
                                        created_at=created,
                                        modified_at=modified,
                                        size=0,
                                        kind=EntryKind.DIRECTORY,
                                        archive_depth=task.depth,
                                    )
                            continue

                        directory, name = _split_virtual_member_path(
                            task.virtual_path, raw_name
                        )
                        if not name:
                            continue

                        nested_type = detect_archive_type(name)
                        is_nested_supported = nested_type in ("zip", "7z", "tar")
                        member_vpath = f"{directory}{os.sep}{name}"

                        if is_nested_supported:
                            if self.options.include_archive_files:
                                local_entries.append(
                                    FileEntry(
                                        directory=directory,
                                        name=name,
                                        created_at=created,
                                        modified_at=modified,
                                        size=size,
                                        kind=EntryKind.ARCHIVE,
                                        archive_depth=task.depth,
                                    )
                                )
                            nested_targets.append((raw_name, nested_type, member_vpath, size))
                        else:
                            local_entries.append(
                                FileEntry(
                                    directory=directory,
                                    name=name,
                                    created_at=created,
                                    modified_at=modified,
                                    size=size,
                                    kind=EntryKind.ARCHIVE_MEMBER,
                                    archive_depth=task.depth,
                                )
                            )
                            if nested_type == "unsupported_rar":
                                self._add_warning(
                                    member_vpath,
                                    "중첩 RAR 형식은 내장 엔진에서 지원되지 않아 파일 자체만 기록했습니다.",
                                )
                    if not has_ctime_property:
                        note = (
                            "7z 헤더에 생성 시각(kCTime) 속성 없음 — "
                            "압축 시 생성 시각 저장 옵션(-mtc=on)을 쓰지 않은 압축파일"
                        )
                else:
                    note = "py7zr list() 호환 경로: 생성 시각을 읽을 수 없음"
                    for fi in sz.list():
                        if self.cancel_event.is_set():
                            return
                        if fi.is_symlink or fi.is_directory:
                            continue
                        directory, name = _split_virtual_member_path(
                            task.virtual_path, fi.filename
                        )
                        if not name:
                            continue
                        dt = _any_7z_time_to_local(fi.creationtime)
                        nested_type = detect_archive_type(name)
                        member_vpath = f"{directory}{os.sep}{name}"
                        if nested_type in ("zip", "7z", "tar"):
                            if self.options.include_archive_files:
                                local_entries.append(
                                    FileEntry(
                                        directory=directory,
                                        name=name,
                                        created_at=None,
                                        modified_at=dt,
                                        size=fi.uncompressed,
                                        kind=EntryKind.ARCHIVE,
                                        archive_depth=task.depth,
                                    )
                                )
                            nested_targets.append(
                                (fi.filename, nested_type, member_vpath, int(fi.uncompressed or 0))
                            )
                        else:
                            local_entries.append(
                                FileEntry(
                                    directory=directory,
                                    name=name,
                                    created_at=None,
                                    modified_at=dt,
                                    size=fi.uncompressed,
                                    kind=EntryKind.ARCHIVE_MEMBER,
                                    archive_depth=task.depth,
                                )
                            )

                # Extract nested archive members via WriterFactory directly to UUID temp files
                # (never writes raw archive paths to disk: immune to ../ traversal & Windows MAX_PATH)
                if nested_targets and not self.cancel_event.is_set():
                    if task.depth + 1 > self.options.max_archive_depth:
                        for _, _, member_vpath, _ in nested_targets:
                            self._add_warning(
                                member_vpath,
                                f"최대 압축 중첩 깊이({self.options.max_archive_depth})를 초과하여 탐색을 중단했습니다.",
                            )
                    elif self._temp_root is not None:
                        self._extract_7z_nested(task, sz, nested_targets)

        except py7zr.exceptions.Bad7zFile:
            self._add_warning(task.virtual_path, "손상되었거나 유효하지 않은 7z 파일입니다.")
            return
        except py7zr.exceptions.PasswordRequired:
            self._add_warning(
                task.virtual_path,
                "암호화된 7z 파일이어서 내부를 탐색할 수 없습니다.",
            )
            return
        except Exception as exc:
            self._add_warning(task.virtual_path, f"7z 열기 오류: {exc}", exc=exc)
            return

        if candidate_dirs:
            for rel, entry in candidate_dirs.items():
                if rel not in non_empty_dirs:
                    local_entries.append(entry)

        self._finish_archive(task, SOURCE_7Z, local_entries, note)

    def _extract_7z_nested(
        self,
        task: _ArchiveTask,
        sz: py7zr.SevenZipFile,
        targets: list[tuple[str, str, str, int]],
    ) -> None:
        """Unpack a 7z's nested archives to temp files and queue them, within the temp budget.

        When they do not all fit at once they are unpacked in several passes; each pass waits
        until the archives of earlier passes have been scanned and deleted.
        """
        assert self._temp_root is not None
        limit = self._temp_limit
        capacity = None if limit is None else max(0, limit - getattr(self._tls, "held", 0))

        too_big = [t for t in targets if capacity is not None and t[3] > capacity]
        if too_big:
            self._add_warning(
                task.virtual_path,
                self._temp_shortage_text(len(too_big), max(t[3] for t in too_big)),
            )

        batches: list[list[tuple[str, str, str, int]]] = []
        batch_bytes = 0
        for target in targets:
            if capacity is not None and target[3] > capacity:
                continue
            if not batches or (capacity is not None and batch_bytes + target[3] > capacity):
                batches.append([])
                batch_bytes = 0
            batches[-1].append(target)
            batch_bytes += target[3]

        for index, batch in enumerate(batches):
            if self.cancel_event.is_set():
                return
            needed = sum(t[3] for t in batch)
            remaining = sum(len(b) for b in batches[index:])

            if not self._reserve_temp(needed):
                if not self.cancel_event.is_set():
                    self._add_warning(
                        task.virtual_path, self._temp_shortage_text(remaining, needed)
                    )
                return

            # The budget covers this scan only; other programs may have filled the disk
            free = _free_bytes(self._temp_root)
            if free is not None and needed > free:
                self._release_temp(needed)
                self._add_warning(
                    task.virtual_path,
                    f"임시 폴더 여유 공간이 부족하여 중첩 압축파일 {remaining}개의 내부를 탐색하지 "
                    f"못했습니다 (필요 {format_size(needed)}, 여유 {format_size(free)}, "
                    f"임시 폴더: {self._temp_root.parent}). {_TEMP_DIR_HINT}",
                )
                return

            log.info(
                "7z 중첩 압축파일 %d개 추출 (%d/%d회차): %s | 필요 공간 %s",
                len(batch),
                index + 1,
                len(batches),
                task.virtual_path,
                format_size(needed),
            )
            factory = _Isolated7zWriterFactory(self._temp_root)
            extracted_ok = False
            try:
                sz.reset()
                sz.extract(targets=[t[0] for t in batch], factory=factory)
                extracted_ok = True
            except py7zr.exceptions.PasswordRequired:
                self._add_warning(
                    task.virtual_path,
                    "암호화된 7z 항목이 포함되어 중첩 압축파일을 추출할 수 없습니다.",
                )
            except Exception as exc:
                self._add_warning(
                    task.virtual_path,
                    self._describe_error("7z 중첩 압축파일 추출 오류", exc),
                    exc=exc,
                )
            finally:
                factory.close_all()

            if not extracted_ok:
                for leftover in factory.outputs.values():
                    self._safe_cleanup(leftover)
                self._release_temp(needed)
                return  # the same error would repeat for the remaining passes

            handed_over = 0  # budget that now belongs to the queued archives
            for raw_name, nested_type, member_vpath, _size in batch:
                isolated_file = factory.outputs.get(raw_name)
                if isolated_file is None or not isolated_file.is_file():
                    self._add_warning(
                        member_vpath,
                        "7z에서 중첩 압축파일을 추출하지 못했습니다.",
                    )
                    continue
                if self.cancel_event.is_set():
                    self._safe_cleanup(isolated_file)
                    continue
                try:
                    file_size = isolated_file.stat().st_size
                except OSError:
                    file_size = _size
                handed_over += file_size
                self._enqueue(
                    _ArchiveTask(
                        archive_type=nested_type,
                        virtual_path=member_vpath,
                        depth=task.depth + 1,
                        source_path=isolated_file,
                        cleanup_path=isolated_file,
                        temp_charge=file_size,
                    )
                )
            if handed_over < needed:
                self._release_temp(needed - handed_over)
            elif handed_over > needed:
                self._charge_temp(handed_over - needed)

    def _build_stats(
        self,
        input_paths: list[str],
        elapsed: float,
        worker_count: int,
    ) -> ScanStats:
        regular = 0
        archives = 0
        members = 0
        dirs = 0
        total_size = 0
        max_depth = 0
        created_present = 0
        by_source: dict[str, list[int]] = {}
        for e in self._entries:
            counts = by_source.get(e.source)
            if counts is None:
                counts = by_source[e.source] = [0, 0]
            counts[1] += 1
            if e.created_at is not None:
                counts[0] += 1
                created_present += 1
            if e.archive_depth > max_depth:
                max_depth = e.archive_depth
            if e.kind == EntryKind.DIRECTORY:
                dirs += 1
            elif e.kind == EntryKind.ARCHIVE:
                archives += 1
                total_size += e.size
            elif e.kind == EntryKind.ARCHIVE_MEMBER:
                members += 1
                total_size += e.size
            else:
                regular += 1
                total_size += e.size

        return ScanStats(
            total_entries=len(self._entries),
            regular_files=regular,
            archive_files=archives,
            archives_scanned=self._archives_scanned,
            archive_members=members,
            directories=dirs,
            total_size=total_size,
            max_depth_seen=max_depth,
            warnings_count=len(self._warnings),
            elapsed_seconds=elapsed,
            cancelled=self.cancel_event.is_set(),
            worker_count=worker_count,
            input_paths=input_paths,
            created_present=created_present,
            created_missing=len(self._entries) - created_present,
            created_by_source={
                source: (by_source[source][0], by_source[source][1])
                for source in (SOURCE_FILESYSTEM, SOURCE_ZIP, SOURCE_7Z, SOURCE_TAR)
                if source in by_source
            },
            archives_without_created=self._archives_without_created,
            temp_limit_bytes=self._temp_limit,
            temp_peak_bytes=self._temp_peak,
            temp_wait_count=self._temp_wait_count,
        )
