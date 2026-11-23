"""Data models and formatting helpers for DeepLister."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class EntryKind(str, Enum):
    FILE = "일반 파일"
    ARCHIVE = "압축 파일"
    ARCHIVE_MEMBER = "압축 내부"
    DIRECTORY = "폴더"


# Where an entry's metadata was read from (drives the created-date statistics)
SOURCE_FILESYSTEM = "fs"
SOURCE_ZIP = "zip"
SOURCE_7Z = "7z"
SOURCE_TAR = "tar"

SOURCE_LABELS = {
    SOURCE_FILESYSTEM: "파일 시스템",
    SOURCE_ZIP: "ZIP 내부",
    SOURCE_7Z: "7z 내부",
    SOURCE_TAR: "TAR 내부",
}

# Why a created date can legitimately be empty, per metadata source
CREATED_MISSING_HINTS = {
    SOURCE_FILESYSTEM: "파일 시스템이 생성 시각을 제공하지 않았습니다.",
    SOURCE_ZIP: "이 ZIP 항목에는 생성 시각(NTFS/UT 확장 필드)이 저장되어 있지 않습니다.",
    SOURCE_7Z: (
        "이 7z 압축파일에는 생성 시각이 저장되어 있지 않습니다. "
        "(7-Zip 기본 설정은 수정 시각만 저장합니다)"
    ),
    SOURCE_TAR: "TAR 형식은 생성 시각을 저장하지 않습니다.",
}


@dataclass(slots=True)
class FileEntry:
    """Single discovered file or folder entry."""

    directory: str
    name: str
    created_at: datetime | None
    modified_at: datetime | None
    size: int
    kind: EntryKind = EntryKind.FILE
    archive_depth: int = 0
    source: str = SOURCE_FILESYSTEM

    @property
    def kind_label(self) -> str:
        if self.archive_depth > 0:
            if self.kind == EntryKind.ARCHIVE:
                return f"중첩 압축 (깊이 {self.archive_depth})"
            if self.kind == EntryKind.DIRECTORY:
                return f"압축 내 폴더 (깊이 {self.archive_depth})"
            return f"압축 내부 (깊이 {self.archive_depth})"
        return self.kind.value


@dataclass(slots=True)
class ScanWarning:
    """Non-fatal issue encountered during scanning."""

    path: str
    reason: str


@dataclass(slots=True)
class ScanOptions:
    """User-configurable scan behavior."""

    scan_archives: bool = True
    include_archive_files: bool = True
    include_empty_dirs: bool = False
    max_archive_depth: int = 10
    max_workers: int = 8
    max_memory_archive_bytes: int = 32 * 1024 * 1024  # 32 MB per-archive memory cap
    max_total_memory_bytes: int = 128 * 1024 * 1024  # 128 MB global queued memory cap
    # Folder to unpack nested archives in; None = system temp directory
    temp_dir: str | None = None


@dataclass
class ScanStats:
    """Aggregate statistics of a scan run."""

    total_entries: int = 0
    regular_files: int = 0
    archive_files: int = 0
    archives_scanned: int = 0
    archive_members: int = 0
    directories: int = 0
    total_size: int = 0
    max_depth_seen: int = 0
    warnings_count: int = 0
    elapsed_seconds: float = 0.0
    cancelled: bool = False
    worker_count: int = 1
    input_paths: list[str] = field(default_factory=list)
    # Created-date coverage: how many entries carry a creation timestamp, overall and per source
    created_present: int = 0
    created_missing: int = 0
    created_by_source: dict[str, tuple[int, int]] = field(default_factory=dict)  # (present, total)
    archives_without_created: int = 0
    log_path: str = ""


@dataclass
class ScanResult:
    """Complete output of a scan operation."""

    entries: list[FileEntry]
    warnings: list[ScanWarning]
    stats: ScanStats


def format_size(size_bytes: int) -> str:
    """Format byte size into a human-readable string."""
    if size_bytes < 0:
        return "-"
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    value = float(size_bytes)
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(value):,} B"
            return f"{value:,.2f} {unit}"
        value /= 1024.0
    return f"{size_bytes:,} B"


def format_datetime(dt: datetime | None) -> str:
    """Format datetime consistently for display and export."""
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S")
