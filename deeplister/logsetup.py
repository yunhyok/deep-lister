"""Diagnostic file logging: one detailed log file per application session."""

from __future__ import annotations

import codecs
import logging
import os
import platform
import shutil
import sys
import tempfile
import threading
from datetime import datetime
from pathlib import Path

from . import APP_NAME, __version__
from .models import format_size

LOGGER_NAME = "deeplister"
LOG_FILE_PREFIX = "DeepLister_"
MAX_LOG_FILES = 30

_LOG_FORMAT = "%(asctime)s.%(msecs)03d %(levelname)-7s [%(threadName)s] %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

log = logging.getLogger(LOGGER_NAME)

_lock = threading.Lock()
_handler: logging.FileHandler | None = None
_log_path: Path | None = None
_hooks_installed = False


def default_log_dir() -> Path:
    """Per-user log folder (%LOCALAPPDATA%\\DeepLister\\logs on Windows)."""
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / APP_NAME / "logs"
    return Path.home() / f".{APP_NAME.lower()}" / "logs"


def free_space_text(path: str | Path) -> str:
    """Human-readable free disk space of the volume holding path ('알 수 없음' on failure)."""
    try:
        return format_size(shutil.disk_usage(path).free)
    except OSError:
        return "알 수 없음"


def start_file_logging(log_dir: str | Path | None = None) -> Path | None:
    """Route the 'deeplister' logger to a new timestamped file.

    Returns the log file path, or None when the folder is not writable (logging then stays off
    so a read-only profile can never break scanning).
    """
    global _handler, _log_path
    with _lock:
        if _handler is not None:
            return _log_path
        directory = Path(log_dir) if log_dir else default_log_dir()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = directory / f"{LOG_FILE_PREFIX}{stamp}_{os.getpid()}.log"
        try:
            directory.mkdir(parents=True, exist_ok=True)
            # utf-8-sig: the BOM lets every Windows text viewer detect Korean text correctly
            handler = logging.FileHandler(path, encoding="utf-8-sig")
        except OSError:
            return None
        handler.setFormatter(logging.Formatter(_LOG_FORMAT, _DATE_FORMAT))
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        _handler, _log_path = handler, path

    _prune_old_logs(directory, keep=MAX_LOG_FILES, current=path)
    _write_session_header(path)
    return path


def stop_file_logging() -> None:
    """Detach and close the session log file (safe to call repeatedly)."""
    global _handler, _log_path
    with _lock:
        handler, _handler, _log_path = _handler, None, None
    if handler is not None:
        log.removeHandler(handler)
        handler.close()


def current_log_path() -> Path | None:
    return _log_path


def current_log_size() -> int:
    """Flushed size in bytes of the session log; marks where a scan's records begin."""
    handler, path = _handler, _log_path
    if handler is None or path is None:
        return 0
    try:
        handler.flush()
        return path.stat().st_size
    except OSError:
        return 0


def export_log_slice(dest: str | Path, start_offset: int = 0) -> Path | None:
    """Copy the session log from start_offset (bytes) to dest; None when logging is off."""
    handler, path = _handler, _log_path
    if handler is None or path is None:
        return None
    handler.flush()
    out = Path(dest)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "rb") as src, open(out, "wb") as dst:
        if start_offset > 0:
            dst.write(codecs.BOM_UTF8)
            src.seek(start_offset)
        shutil.copyfileobj(src, dst)
    return out


def install_exception_hooks() -> None:
    """Record otherwise-invisible unhandled exceptions (windowed builds have no console)."""
    global _hooks_installed
    if _hooks_installed:
        return
    _hooks_installed = True

    previous_hook = sys.excepthook
    previous_thread_hook = threading.excepthook

    def _excepthook(exc_type, exc, tb) -> None:
        if not issubclass(exc_type, KeyboardInterrupt):
            log.critical("처리되지 않은 예외", exc_info=(exc_type, exc, tb))
        previous_hook(exc_type, exc, tb)

    def _thread_excepthook(args: threading.ExceptHookArgs) -> None:
        if args.exc_type is not SystemExit:
            log.critical(
                "스레드에서 처리되지 않은 예외",
                exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
            )
        previous_thread_hook(args)

    sys.excepthook = _excepthook
    threading.excepthook = _thread_excepthook


def _prune_old_logs(directory: Path, keep: int, current: Path) -> None:
    """Keep the current log plus the most recently written older ones, `keep` files in total."""
    try:
        older = sorted(
            (
                p
                for p in directory.glob(f"{LOG_FILE_PREFIX}*.log")
                if p.is_file() and p != current
            ),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        return
    for stale in older[max(0, keep - 1) :]:
        try:
            stale.unlink()
        except OSError:
            pass  # still open in another DeepLister window


def _library_versions() -> str:
    parts: list[str] = []
    for module_name in ("PySide6", "py7zr", "openpyxl"):
        try:
            module = __import__(module_name)
            parts.append(f"{module_name} {getattr(module, '__version__', '?')}")
        except Exception:
            parts.append(f"{module_name} (불러오기 실패)")
    return ", ".join(parts)


def _write_session_header(path: Path) -> None:
    temp_dir = tempfile.gettempdir()
    log.info("===== %s %s 세션 시작 =====", APP_NAME, __version__)
    log.info(
        "실행 환경: %s | Python %s | 패키징 실행파일=%s",
        platform.platform(),
        platform.python_version(),
        bool(getattr(sys, "frozen", False)),
    )
    log.info("라이브러리: %s", _library_versions())
    log.info("임시 폴더: %s (여유 공간 %s)", temp_dir, free_space_text(temp_dir))
    log.info("로그 파일: %s", path)
