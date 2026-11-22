"""Multi-threaded recursive filesystem and nested archive scanner."""

from __future__ import annotations

import io
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
    EntryKind,
    FileEntry,
    ScanOptions,
    ScanResult,
    ScanStats,
    ScanWarning,
)

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


def _parse_zip_timestamps(info: zipfile.ZipInfo) -> tuple[datetime | None, datetime | None]:
    """Extract (created_at, modified_at) from ZipInfo DOS header and extra fields."""
    created_at: datetime | None = None
    modified_at: datetime | None = None
    has_ntfs_mod = False

    try:
        y, mo, d, h, mi, s = info.date_time
        if y >= 1980:
            modified_at = datetime(y, mo, d, h, mi, min(s, 59))
    except ValueError:
        modified_at = None

    extra = info.extra or b""
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
            sub_pos = 4  # skip 4 reserved bytes
            while sub_pos + 4 <= data_size:
                tag, tag_size = struct.unpack_from("<HH", chunk, sub_pos)
                sub_pos += 4
                if sub_pos + tag_size > data_size:
                    break
                if tag == 0x0001 and tag_size == 24:
                    mtime_ft, _atime_ft, ctime_ft = struct.unpack_from("<QQQ", chunk, sub_pos)
                    ntfs_mod = _filetime_to_local(mtime_ft)
                    ntfs_cre = _filetime_to_local(ctime_ft)
                    if ntfs_mod is not None:
                        modified_at = ntfs_mod
                        has_ntfs_mod = True
                    if ntfs_cre is not None:
                        created_at = ntfs_cre
                sub_pos += tag_size

        # 0x5455: Extended Timestamp (UT, signed 32-bit Unix seconds)
        elif header_id == 0x5455 and data_size >= 1:
            flags = chunk[0]
            offset = 1
            if (flags & 0x01) and offset + 4 <= data_size:
                if not has_ntfs_mod:
                    ut_mod = _utc_ts_to_local(struct.unpack_from("<i", chunk, offset)[0])
                    if ut_mod is not None:
                        modified_at = ut_mod
                offset += 4
            if (flags & 0x02) and offset + 4 <= data_size:
                offset += 4  # atime
            if (flags & 0x04) and offset + 4 <= data_size:
                if created_at is None:
                    ut_cre = _utc_ts_to_local(struct.unpack_from("<i", chunk, offset)[0])
                    if ut_cre is not None:
                        created_at = ut_cre

    return created_at, modified_at


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

        self._task_queue: queue.Queue[_DirTask | _ArchiveTask] = queue.Queue()
        self._pending_lock = threading.Lock()
        self._pending_count = 0
        self._queued_bytes = 0
        self._done_event = threading.Event()

        self._result_lock = threading.Lock()
        self._entries: list[FileEntry] = []
        self._warnings: list[ScanWarning] = []
        self._archives_scanned = 0
        self._total_size = 0
        self._max_depth_seen = 0
        self._current_path = ""
        self._last_progress_time = 0.0
        self._start_time = 0.0
        self._temp_root: Path | None = None

    def scan(self, input_paths: list[str | Path]) -> ScanResult:
        """Scan all provided files, folders, and archives recursively using worker threads."""
        self._start_time = time.perf_counter()
        self._last_progress_time = 0.0
        self._entries.clear()
        self._warnings.clear()
        self._archives_scanned = 0
        self._total_size = 0
        self._max_depth_seen = 0
        self._current_path = ""
        self._done_event.clear()

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

        with tempfile.TemporaryDirectory(prefix="deeplister_") as temp_dir:
            self._temp_root = Path(temp_dir)

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
                        name=f"DeepLister-Worker-{i + 1}",
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

    def _enqueue(self, task: _DirTask | _ArchiveTask) -> None:
        if self.cancel_event.is_set():
            if isinstance(task, _ArchiveTask):
                self._release_memory(task.memory_charge)
                if task.cleanup_path is not None:
                    self._safe_cleanup(task.cleanup_path)
            return
        with self._pending_lock:
            self._pending_count += 1
        self._task_queue.put(task)

    def _finish_task(self) -> None:
        with self._pending_lock:
            self._pending_count -= 1
            if self._pending_count <= 0:
                self._done_event.set()

    def _worker_loop(self) -> None:
        while not self._done_event.is_set() and not self.cancel_event.is_set():
            try:
                task = self._task_queue.get(timeout=0.05)
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
                self._add_warning(target, f"처리 중 오류: {exc}")
            finally:
                if isinstance(task, _ArchiveTask):
                    self._release_memory(task.memory_charge)
                    task.source_bytes = None
                    if task.cleanup_path is not None:
                        self._safe_cleanup(task.cleanup_path)
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

    def _add_warning(self, path: str, reason: str) -> None:
        with self._result_lock:
            self._warnings.append(ScanWarning(path=path, reason=reason))
            self._current_path = path
        self._emit_progress()

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
            self._add_warning(str(path), f"파일 정보를 읽을 수 없습니다: {exc}")
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
                        self._add_warning(de.path, f"항목 접근 실패: {exc}")
        except OSError as exc:
            self._add_warning(str(dir_path), f"폴더 열기 실패: {exc}")
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
            spilled_path = self._temp_root / f"nested_{uuid.uuid4().hex}.bin"
            try:
                with open(spilled_path, "wb") as out_fp:
                    while True:
                        if self.cancel_event.is_set():
                            out_fp.close()
                            self._safe_cleanup(spilled_path)
                            return
                        chunk = stream.read(1024 * 1024)
                        if not chunk:
                            break
                        out_fp.write(chunk)
            except Exception:
                self._safe_cleanup(spilled_path)
                raise

            self._enqueue(
                _ArchiveTask(
                    archive_type=nested_type,
                    virtual_path=nested_virtual_path,
                    depth=next_depth,
                    source_path=spilled_path,
                    cleanup_path=spilled_path,
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
                                created, modified = _parse_zip_timestamps(info)
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
                    created, modified = _parse_zip_timestamps(info)
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
                                )
                            except Exception as exc:
                                self._add_warning(
                                    member_vpath,
                                    f"중첩 압축파일 읽기 실패: {exc}",
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
            self._add_warning(task.virtual_path, f"ZIP 열기 오류: {exc}")
            return

        if candidate_dirs:
            for rel, entry in candidate_dirs.items():
                if rel not in non_empty_dirs:
                    local_entries.append(entry)

        self._add_entries(local_entries, current_path=task.virtual_path)

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
                                f"TAR 내부 중첩 압축파일 읽기 실패: {exc}",
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
            self._add_warning(task.virtual_path, f"TAR 압축파일 읽기 오류: {exc}")
            return

        if candidate_dirs:
            for rel, entry in candidate_dirs.items():
                if rel not in non_empty_dirs:
                    local_entries.append(entry)

        self._add_entries(local_entries, current_path=task.virtual_path)

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
        nested_targets: list[tuple[str, str, str]] = []  # (raw_member_name, nested_type, member_vpath)

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
                            nested_targets.append((raw_name, nested_type, member_vpath))
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
                else:
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
                            nested_targets.append((fi.filename, nested_type, member_vpath))
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
                        for _, _, member_vpath in nested_targets:
                            self._add_warning(
                                member_vpath,
                                f"최대 압축 중첩 깊이({self.options.max_archive_depth})를 초과하여 탐색을 중단했습니다.",
                            )
                    elif self._temp_root is not None:
                        factory = _Isolated7zWriterFactory(self._temp_root)
                        target_names = [t[0] for t in nested_targets]
                        extracted_ok = False
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
                                f"7z 중첩 압축파일 추출 오류: {exc}",
                            )
                        finally:
                            factory.close_all()

                        if extracted_ok:
                            for raw_name, nested_type, member_vpath in nested_targets:
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
                                self._enqueue(
                                    _ArchiveTask(
                                        archive_type=nested_type,
                                        virtual_path=member_vpath,
                                        depth=task.depth + 1,
                                        source_path=isolated_file,
                                        cleanup_path=isolated_file,
                                    )
                                )
                        else:
                            for p in factory.outputs.values():
                                self._safe_cleanup(p)

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
            self._add_warning(task.virtual_path, f"7z 열기 오류: {exc}")
            return

        if candidate_dirs:
            for rel, entry in candidate_dirs.items():
                if rel not in non_empty_dirs:
                    local_entries.append(entry)

        self._add_entries(local_entries, current_path=task.virtual_path)

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
        for e in self._entries:
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
        )
