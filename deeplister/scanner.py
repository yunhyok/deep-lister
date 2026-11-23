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


def temp_dir_problem(path: str | os.PathLike[str]) -> str | None:
    """Return why path cannot hold temporary files (user-facing text), or None when it can.

    Writability is tested by really creating a folder: os.access() ignores ACLs on Windows, and
    tempfile.mkdtemp() keeps retrying a denied mkdir there (up to TMP_MAX times) before failing.
    """
    if not os.path.isdir(path):
        return "폴더를 찾을 수 없습니다"
    probe = os.path.join(path, f"deeplister_probe_{uuid.uuid4().hex}")
    try:
        os.mkdir(probe)
        os.rmdir(probe)
    except OSError as exc:
        return f"폴더에 쓸 수 없습니다: {exc}"
    return None


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
    temp_charge: int = 0  # temp-folder bytes reserved for cleanup_path
    started: float = 0.0


class ScanEngine:
    """Multi-threaded deadlock-free scanner for folders, files, and nested archives."""

    def __init__(
        self,
        options: ScanOptions | None = None,
        progress_callback: Callable[[ProgressSnapshot], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> None:
        self.options = options or ScanOptions()
        self.progress_callback = progress_callback
        self.cancel_event = cancel_event or threading.Event()

        # (priority, sequence, task): nested archives that already hold memory or temp-folder
        # space come first so that the space is given back as early as possible
        self._task_queue: queue.PriorityQueue[tuple[int, int, _DirTask | _ArchiveTask]] = (
            queue.PriorityQueue()
        )
        self._pending_lock = threading.Lock()
        self._pending_count = 0
        self._task_seq = 0
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
        self._temp_root_key = ""
        self._worker_count = 1

        # Temp-folder budget shared by all workers (see _reserve_temp)
        self._temp_cond = threading.Condition()
        self._temp_reserved = 0  # bytes of nested archives in the temp folder or being unpacked
        self._temp_unwritten = 0  # part of _temp_reserved not written yet (free space lacks it)
        self._temp_pinned = 0  # reserved bytes of archives whose worker waits for more space
        self._temp_waiters = 0

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

        # Reset queue/accounting state so ScanEngine instances are safely reusable
        with self._pending_lock:
            self._pending_count = 0
            self._task_seq = 0
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
        self._worker_count = worker_count
        with self._temp_cond:
            self._temp_reserved = self._temp_unwritten = 0
            self._temp_pinned = self._temp_waiters = 0

        log.info("----- 스캔 시작: 대상 %d개 | %s", len(unique_paths), self.options)
        for p in unique_paths:
            log.info("대상: %s", p)

        temp_context, temp_origin = self._open_temp_dir()
        with temp_context as temp_dir:
            self._temp_root = Path(temp_dir)
            self._temp_root_key = os.path.normcase(os.path.realpath(temp_dir))
            free = _free_bytes(self._temp_root)
            log.info(
                "임시 작업 폴더(%s): %s (여유 공간 %s)",
                temp_origin,
                temp_dir,
                format_size(free) if free is not None else "알 수 없음",
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

    def _open_temp_dir(self) -> tuple[tempfile.TemporaryDirectory[str], str]:
        """Create this scan's private work folder; returns (context manager, origin label).

        A user-selected folder that is missing or not writable must not abort the scan: warn
        and fall back to the system temp directory.
        """
        custom = self.options.temp_dir
        if custom:
            problem = temp_dir_problem(custom)
            if problem is None:
                try:
                    return tempfile.TemporaryDirectory(prefix="deeplister_", dir=custom), "사용자 지정"
                except OSError as exc:
                    problem = f"폴더에 쓸 수 없습니다: {exc}"
            self._add_warning(
                str(custom),
                "지정한 임시 폴더를 사용할 수 없어 시스템 기본 임시 폴더"
                f"({tempfile.gettempdir()})를 사용합니다 — {problem}",
            )
        return tempfile.TemporaryDirectory(prefix="deeplister_"), "시스템 기본"

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

    def _reserve_temp(self, task: _ArchiveTask, path: str, count: int, nbytes: int) -> bool:
        """Set aside temp-folder space for nested archives of `task` before unpacking them.

        Workers unpack at the same time, so a free-space check per worker would let them
        overfill the disk together. When the space is taken by nested archives that other
        workers have yet to scan, wait for them. Returns False (with a warning, unless the scan
        was cancelled) when the archives cannot fit however long this worker waits.
        """
        root = self._temp_root
        if root is None or nbytes <= 0:
            return True
        free: int | None = None
        reserved = False
        wait_started = 0.0
        with self._temp_cond:
            try:
                while not self.cancel_event.is_set():
                    free = _free_bytes(root)
                    if free is None or nbytes <= free - self._temp_unwritten:
                        self._temp_reserved += nbytes
                        self._temp_unwritten += nbytes
                        reserved = True
                        break
                    if not wait_started:
                        wait_started = time.perf_counter()
                        self._temp_waiters += 1
                        self._temp_pinned += task.temp_charge
                    # Space comes back only when a worker that is not waiting finishes a nested
                    # archive. The archives waiting workers are scanning stay where they are, and
                    # if every worker waited nobody would be left to scan the queued ones.
                    reclaimable = self._temp_reserved - self._temp_pinned
                    if nbytes > free + reclaimable or self._temp_waiters >= self._worker_count:
                        break
                    self._temp_cond.wait(0.2)
            finally:
                if wait_started:
                    self._temp_waiters -= 1
                    self._temp_pinned -= task.temp_charge

        if wait_started:
            log.info(
                "임시 폴더 공간 대기 %s: %s | 필요 %s | %.1f초",
                "후 확보" if reserved else "종료(확보 실패)",
                path,
                format_size(nbytes),
                time.perf_counter() - wait_started,
            )
        if reserved:
            return True
        if not self.cancel_event.is_set() and free is not None:
            self._add_warning(
                path,
                f"임시 폴더 여유 공간이 부족하여 중첩 압축파일 {count}개의 내부를 탐색하지 못했습니다 "
                f"(필요 {format_size(nbytes)}, 여유 {format_size(free)}, "
                f"임시 폴더: {root.parent}) — 옵션의 '임시 폴더'를 여유 공간이 충분한 "
                "드라이브로 바꿔 보세요.",
            )
        return False

    def _temp_written(self, nbytes: int) -> None:
        """Reserved bytes are on disk (or will never be): the free-space figure covers them now."""
        if nbytes <= 0:
            return
        with self._temp_cond:
            self._temp_unwritten = max(0, self._temp_unwritten - nbytes)
            self._temp_cond.notify_all()

    def _release_temp(self, nbytes: int) -> None:
        if nbytes <= 0:
            return
        with self._temp_cond:
            self._temp_reserved = max(0, self._temp_reserved - nbytes)
            self._temp_cond.notify_all()

    def _release_task_resources(self, task: _ArchiveTask) -> None:
        self._release_memory(task.memory_charge)
        task.source_bytes = None
        if task.cleanup_path is not None:
            self._safe_cleanup(task.cleanup_path)
        self._release_temp(task.temp_charge)

    def _enqueue(self, task: _DirTask | _ArchiveTask) -> None:
        if self.cancel_event.is_set():
            if isinstance(task, _ArchiveTask):
                self._release_task_resources(task)
            return
        holds_space = isinstance(task, _ArchiveTask) and (
            task.cleanup_path is not None or task.source_bytes is not None
        )
        with self._pending_lock:
            self._pending_count += 1
            self._task_seq += 1
            seq = self._task_seq
        self._task_queue.put((0 if holds_space else 1, seq, task))

    def _finish_task(self) -> None:
        with self._pending_lock:
            self._pending_count -= 1
            if self._pending_count <= 0:
                self._done_event.set()

    def _worker_loop(self) -> None:
        while not self._done_event.is_set() and not self.cancel_event.is_set():
            try:
                _priority, _seq, task = self._task_queue.get(timeout=0.05)
            except queue.Empty:
                continue

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
                if isinstance(task, _ArchiveTask):
                    self._release_task_resources(task)
                self._finish_task()

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
            text += f" — 임시 폴더({self._temp_root.parent}) 여유 공간 {free_text}"
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
                    if (
                        de.name.startswith("deeplister_")
                        and os.path.normcase(de.path) == self._temp_root_key
                    ):
                        continue  # this scan's own work folder inside a scan target
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
        parent: _ArchiveTask,
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
            try:
                while True:
                    if self.cancel_event.is_set():
                        if spilled_fp is not None:
                            spilled_fp.close()
                        if spilled_path is not None:
                            self._safe_cleanup(spilled_path)
                        self._release_memory(reserved)
                        return
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    actual_size += len(chunk)
                    if spilled_fp is None:
                        if actual_size > threshold and self._temp_root is not None:
                            # The header understated the size, so the real one is unknown:
                            # spooled without a temp-space reservation
                            spilled_path = self._temp_root / f"nested_{uuid.uuid4().hex}.bin"
                            spilled_fp = open(spilled_path, "wb")
                            for prev in chunks:
                                spilled_fp.write(prev)
                            chunks.clear()
                            spilled_fp.write(chunk)
                            self._release_memory(reserved)
                            reserved = 0
                        else:
                            chunks.append(chunk)
                    else:
                        spilled_fp.write(chunk)
            except Exception:
                if spilled_fp is not None:
                    spilled_fp.close()
                if spilled_path is not None:
                    self._safe_cleanup(spilled_path)
                self._release_memory(reserved)
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
            temp_charge = max(declared_size, 0)
            if not self._reserve_temp(parent, nested_virtual_path, 1, temp_charge):
                return
            spilled_path = self._temp_root / f"nested_{uuid.uuid4().hex}.bin"
            spooled = False
            try:
                with open(spilled_path, "wb") as out_fp:
                    while not self.cancel_event.is_set():
                        chunk = stream.read(1024 * 1024)
                        if not chunk:
                            spooled = True
                            break
                        out_fp.write(chunk)
            finally:
                self._temp_written(temp_charge)
                if not spooled:  # cancelled or failed
                    self._safe_cleanup(spilled_path)
                    self._release_temp(temp_charge)
            if not spooled:
                return

            self._enqueue(
                _ArchiveTask(
                    archive_type=nested_type,
                    virtual_path=nested_virtual_path,
                    depth=next_depth,
                    source_path=spilled_path,
                    cleanup_path=spilled_path,
                    temp_charge=temp_charge,
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
                                        parent=task,
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
                                        parent=task,
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
        nested_bytes = 0  # uncompressed size the nested archives need in the temp folder
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
                            nested_bytes += size
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
                            size = int(fi.uncompressed or 0)
                            nested_targets.append((fi.filename, nested_type, member_vpath, size))
                            nested_bytes += size
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
                    elif self._temp_root is not None and self._reserve_temp(
                        task, task.virtual_path, len(nested_targets), nested_bytes
                    ):
                        factory = _Isolated7zWriterFactory(self._temp_root)
                        target_names = [t[0] for t in nested_targets]
                        extracted_ok = False
                        log.info(
                            "7z 중첩 압축파일 %d개 추출: %s | 필요 공간 %s",
                            len(nested_targets),
                            task.virtual_path,
                            format_size(nested_bytes),
                        )
                        try:
                            sz.reset()
                            sz.extract(targets=target_names, factory=factory)
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
                            self._temp_written(nested_bytes)

                        if extracted_ok:
                            for raw_name, nested_type, member_vpath, size in nested_targets:
                                isolated_file = factory.outputs.get(raw_name)
                                if isolated_file is None or not isolated_file.is_file():
                                    self._add_warning(
                                        member_vpath,
                                        "7z에서 중첩 압축파일을 추출하지 못했습니다.",
                                    )
                                    self._release_temp(size)
                                    continue
                                # _enqueue cleans up and releases the reservation when cancelled
                                self._enqueue(
                                    _ArchiveTask(
                                        archive_type=nested_type,
                                        virtual_path=member_vpath,
                                        depth=task.depth + 1,
                                        source_path=isolated_file,
                                        cleanup_path=isolated_file,
                                        temp_charge=size,
                                    )
                                )
                        else:
                            for p in factory.outputs.values():
                                self._safe_cleanup(p)
                            self._release_temp(nested_bytes)

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
        )
