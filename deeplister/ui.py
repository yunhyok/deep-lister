"""PySide6 dark-themed GUI for DeepLister."""

from __future__ import annotations

import logging
import os
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
    QThread,
    QTimer,
    QUrl,
    Signal,
)
from PySide6.QtGui import (
    QDesktopServices,
    QDragEnterEvent,
    QDropEvent,
    QKeySequence,
    QPixmap,
    QShortcut,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStatusBar,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from . import APP_NAME, __version__, logsetup
from .exporter import export_to_excel
from .models import (
    CREATED_MISSING_HINTS,
    FileEntry,
    ScanOptions,
    ScanResult,
    ScanWarning,
    format_datetime,
    format_size,
)
from .scanner import (
    SUPPORTED_ARCHIVE_EXTENSIONS,
    ProgressSnapshot,
    ScanEngine,
    is_supported_archive,
    temp_dir_problem,
)
from .theme import apply_theme, assets_dir

log = logging.getLogger("deeplister.ui")


class FileEntryTableModel(QAbstractTableModel):
    """Virtual table model backed directly by list[FileEntry] for smooth large-list rendering."""

    HEADERS = (
        "No.",
        "디렉토리 이름",
        "파일 이름",
        "생성 날짜",
        "수정된 날짜",
        "용량 (Bytes)",
        "구분",
    )

    SORT_ROLE = Qt.ItemDataRole.UserRole + 1

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._entries: list[FileEntry] = []

    def set_entries(self, entries: list[FileEntry]) -> None:
        self.beginResetModel()
        self._entries = entries
        self.endResetModel()

    def entry_at(self, row: int) -> FileEntry | None:
        if 0 <= row < len(self._entries):
            return self._entries[row]
        return None

    def clear(self) -> None:
        self.set_entries([])

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._entries)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self.HEADERS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            if 0 <= section < len(self.HEADERS):
                return self.HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()
        if row < 0 or row >= len(self._entries):
            return None
        entry = self._entries[row]

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return f"{row + 1:,}"
            if col == 1:
                return entry.directory
            if col == 2:
                return entry.name
            if col == 3:
                return format_datetime(entry.created_at) or "-"
            if col == 4:
                return format_datetime(entry.modified_at) or "-"
            if col == 5:
                return f"{entry.size:,}"
            if col == 6:
                return entry.kind_label

        if role == self.SORT_ROLE:
            if col == 0:
                return row + 1
            if col == 1:
                return entry.directory.casefold()
            if col == 2:
                return entry.name.casefold()
            if col == 3:
                return format_datetime(entry.created_at)
            if col == 4:
                return format_datetime(entry.modified_at)
            if col == 5:
                return entry.size
            if col == 6:
                return entry.kind_label

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (0, 5):
                return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            if col in (3, 4, 6):
                return int(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignVCenter)
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        if role == Qt.ItemDataRole.ToolTipRole:
            if col in (1, 2):
                return f"{entry.directory}{os.sep}{entry.name}"
            if col == 3 and entry.created_at is None:
                return CREATED_MISSING_HINTS.get(entry.source)
            if col == 5:
                return format_size(entry.size)

        return None


class WarningTableModel(QAbstractTableModel):
    """Table model for scan warnings and skipped items."""

    HEADERS = ("No.", "대상 경로", "사유")

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._warnings: list[ScanWarning] = []

    def set_warnings(self, warnings: list[ScanWarning]) -> None:
        self.beginResetModel()
        self._warnings = warnings
        self.endResetModel()

    def clear(self) -> None:
        self.set_warnings([])

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._warnings)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        w = self._warnings[index.row()]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return str(index.row() + 1)
            if col == 1:
                return w.path
            if col == 2:
                return w.reason
        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col == 0:
                return int(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignVCenter)
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        if role == Qt.ItemDataRole.ToolTipRole:
            return f"{w.path}\n{w.reason}"
        return None


class MultiColumnFilterProxy(QSortFilterProxyModel):
    """Fast case-insensitive substring filter directly reading FileEntry fields."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._needle = ""
        self.setSortRole(FileEntryTableModel.SORT_ROLE)

    def set_search_text(self, text: str) -> None:
        needle = text.strip().casefold()
        if needle == self._needle:
            return
        if hasattr(self, "beginFilterChange"):
            self.beginFilterChange()
            self._needle = needle
            self.endFilterChange()
        else:
            self._needle = needle
            self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        if not self._needle:
            return True
        model = self.sourceModel()
        if isinstance(model, FileEntryTableModel):
            entry = model.entry_at(source_row)
            if entry is None:
                return False
            needle = self._needle
            return (
                needle in entry.name.casefold()
                or needle in entry.directory.casefold()
                or needle in entry.kind_label.casefold()
            )
        return True


class ScanWorkerThread(QThread):
    """Background Qt thread hosting the multi-threaded ScanEngine."""

    progress = Signal(object)  # ProgressSnapshot
    finished_result = Signal(object)  # ScanResult
    failed = Signal(str)

    def __init__(self, input_paths: list[str], options: ScanOptions) -> None:
        super().__init__()
        self._input_paths = list(input_paths)
        self._options = options
        self._cancel_event = threading.Event()

    def request_cancel(self) -> None:
        self._cancel_event.set()

    def run(self) -> None:
        threading.current_thread().name = "Scan"
        try:
            engine = ScanEngine(
                options=self._options,
                progress_callback=lambda snap: self.progress.emit(snap),
                cancel_event=self._cancel_event,
            )
            result = engine.scan(self._input_paths)
            log_path = logsetup.current_log_path()
            if log_path is not None:
                result.stats.log_path = str(log_path)
            self.finished_result.emit(result)
        except Exception as exc:
            log.exception("스캔이 예외로 중단되었습니다")
            self.failed.emit(str(exc))


class ExportWorkerThread(QThread):
    """Background Qt thread for Excel generation."""

    finished_path = Signal(str, str)  # saved .xlsx path, saved .log path ("" when not saved)
    failed = Signal(str)

    def __init__(
        self,
        result: ScanResult,
        output_path: str,
        log_offset: int | None = None,
    ) -> None:
        super().__init__()
        self._result = result
        self._output_path = output_path
        # Byte offset where this scan's records start in the session log; None = don't save a log
        self._log_offset = log_offset

    def run(self) -> None:
        threading.current_thread().name = "Export"
        try:
            started = time.perf_counter()
            saved = export_to_excel(self._result, self._output_path)
            log.info(
                "Excel 저장 완료: %s | %d행 | %.2f초",
                saved,
                len(self._result.entries),
                time.perf_counter() - started,
            )
            log_copy = ""
            if self._log_offset is not None:
                try:
                    copied = logsetup.export_log_slice(saved.with_suffix(".log"), self._log_offset)
                    log_copy = str(copied) if copied is not None else ""
                except OSError:
                    log.exception("로그 파일을 Excel 옆에 저장하지 못했습니다")
            self.finished_path.emit(str(saved), log_copy)
        except Exception as exc:
            log.exception("Excel 저장 실패: %s", self._output_path)
            self.failed.emit(str(exc))


class DropZoneFrame(QFrame):
    """Highlighted drag-and-drop zone for files, folders, and archives."""

    paths_dropped = Signal(list)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("DropZone")
        self.setAcceptDrops(True)
        self.setProperty("dragActive", False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(4)

        title = QLabel("폴더, 파일, 또는 압축파일(.zip, .7z, .tar 등)을 여기에 드래그 앤 드롭하세요")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setProperty("accent", True)

        sub = QLabel(
            "여러 항목을 동시에 끌어다 놓을 수 있으며, 압축파일 내부의 중첩 압축파일까지 재귀적으로 탐색합니다."
        )
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setProperty("muted", True)

        layout.addWidget(title)
        layout.addWidget(sub)

    def _set_drag_active(self, active: bool) -> None:
        self.setProperty("dragActive", active)
        self.style().unpolish(self)
        self.style().polish(self)
        self.update()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if not self.isEnabled():
            event.ignore()
            return
        if event.mimeData().hasUrls():
            urls = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]
            if urls:
                self._set_drag_active(True)
                event.acceptProposedAction()
                return
        event.ignore()

    def dragLeaveEvent(self, event) -> None:
        self._set_drag_active(False)
        super().dragLeaveEvent(event)

    def dropEvent(self, event: QDropEvent) -> None:
        self._set_drag_active(False)
        if not self.isEnabled():
            event.ignore()
            return
        if event.mimeData().hasUrls():
            paths = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]
            if paths:
                self.paths_dropped.emit(paths)
                event.acceptProposedAction()
                return
        event.ignore()


class MainWindow(QMainWindow):
    """Main DeepLister desktop application window."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{__version__}")
        self.resize(1260, 820)
        self.setMinimumSize(980, 680)  # height: room for the temp-folder row
        self.setAcceptDrops(True)

        self._input_paths: list[str] = []
        self._last_result: ScanResult | None = None
        self._scan_thread: ScanWorkerThread | None = None
        self._export_thread: ExportWorkerThread | None = None
        self._is_scanning = False
        self._is_exporting = False
        self._last_export_path: Path | None = None
        self._scan_log_offset = 0
        self._temp_dir: str | None = None  # None = system temp directory

        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(150)
        self._filter_timer.timeout.connect(self._apply_filter_now)

        self._build_ui()
        apply_theme(self)
        self._refresh_temp_dir()
        self._update_button_states()

    def _build_ui(self) -> None:
        central = QWidget(self)
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(14, 12, 14, 10)
        root_layout.setSpacing(10)

        # Header
        header_row = QHBoxLayout()
        header_row.setSpacing(10)

        icon_label = QLabel()
        png_path = assets_dir() / "app.png"
        if png_path.exists():
            pix = QPixmap(str(png_path)).scaled(
                36,
                36,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            icon_label.setPixmap(pix)
        icon_label.setFixedSize(38, 38)

        title_col = QVBoxLayout()
        title_col.setSpacing(1)
        title_lbl = QLabel(APP_NAME)
        title_lbl.setProperty("heading", True)
        subtitle_lbl = QLabel(
            "폴더 · 파일 · 중첩 압축파일 재귀 탐색 및 Excel(.xlsx) 목록 생성기"
        )
        subtitle_lbl.setProperty("muted", True)
        title_col.addWidget(title_lbl)
        title_col.addWidget(subtitle_lbl)

        header_row.addWidget(icon_label)
        header_row.addLayout(title_col, 1)

        ver_badge = QLabel(f"v{__version__}")
        ver_badge.setProperty("badge", True)
        header_row.addWidget(ver_badge)
        root_layout.addLayout(header_row)

        # Splitter: top input/options area vs bottom results area
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)
        root_layout.addWidget(splitter, 1)

        # Top Section: Input & Options
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(8)

        input_group = QGroupBox("스캔 대상 입력 (드래그 앤 드롭 지원)")
        input_layout = QVBoxLayout(input_group)
        input_layout.setSpacing(8)

        self.drop_zone = DropZoneFrame()
        self.drop_zone.paths_dropped.connect(self.add_paths)
        input_layout.addWidget(self.drop_zone)

        queue_row = QHBoxLayout()
        queue_row.setSpacing(8)

        self.input_list = QListWidget()
        self.input_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.input_list.setAlternatingRowColors(True)
        self.input_list.setMaximumHeight(110)
        self.input_list.setMinimumHeight(74)
        queue_row.addWidget(self.input_list, 1)

        btn_col = QVBoxLayout()
        btn_col.setSpacing(5)
        self.btn_add_folder = QPushButton("폴더 추가...")
        self.btn_add_folder.clicked.connect(self._choose_folder)
        self.btn_add_files = QPushButton("파일·압축파일 추가...")
        self.btn_add_files.clicked.connect(self._choose_files)
        self.btn_remove_selected = QPushButton("선택 제거")
        self.btn_remove_selected.clicked.connect(self._remove_selected_inputs)
        self.btn_clear_inputs = QPushButton("전체 비우기")
        self.btn_clear_inputs.clicked.connect(self._clear_inputs)

        for b in (
            self.btn_add_folder,
            self.btn_add_files,
            self.btn_remove_selected,
            self.btn_clear_inputs,
        ):
            b.setMinimumWidth(145)
            btn_col.addWidget(b)
        btn_col.addStretch(1)
        queue_row.addLayout(btn_col)
        input_layout.addLayout(queue_row)
        top_layout.addWidget(input_group)

        # Options + Actions panel
        options_panel = QFrame()
        options_panel.setProperty("panel", True)
        opt_outer = QVBoxLayout(options_panel)
        opt_outer.setContentsMargins(12, 10, 12, 10)
        opt_outer.setSpacing(8)

        opt_row = QHBoxLayout()
        opt_row.setSpacing(14)

        self.chk_scan_archives = QCheckBox("압축파일 내부 재귀 탐색 (zip, 7z, tar)")
        self.chk_scan_archives.setChecked(True)
        self.chk_scan_archives.toggled.connect(self._update_button_states)
        self.chk_include_archives = QCheckBox("압축파일 자체도 목록에 포함")
        self.chk_include_archives.setChecked(True)
        self.chk_include_empty_dirs = QCheckBox("빈 폴더 포함")
        self.chk_include_empty_dirs.setChecked(False)

        opt_row.addWidget(self.chk_scan_archives)
        opt_row.addWidget(self.chk_include_archives)
        opt_row.addWidget(self.chk_include_empty_dirs)
        opt_row.addStretch(1)

        lbl_threads = QLabel("스레드 수:")
        lbl_threads.setProperty("muted", True)
        self.spin_threads = QSpinBox()
        self.spin_threads.setRange(1, 32)
        default_threads = min(16, max(4, (os.cpu_count() or 4) * 2))
        self.spin_threads.setValue(default_threads)
        self.spin_threads.setToolTip("병렬 디렉토리/압축파일 탐색에 사용할 워커 스레드 개수")

        lbl_depth = QLabel("최대 중첩 깊이:")
        lbl_depth.setProperty("muted", True)
        self.spin_depth = QSpinBox()
        self.spin_depth.setRange(1, 20)
        self.spin_depth.setValue(10)
        self.spin_depth.setToolTip("압축파일 내부의 압축파일을 몇 단계까지 재귀 탐색할지 설정")

        opt_row.addWidget(lbl_threads)
        opt_row.addWidget(self.spin_threads)
        opt_row.addWidget(lbl_depth)
        opt_row.addWidget(self.spin_depth)
        opt_outer.addLayout(opt_row)

        # Temp work folder: nested archives are unpacked here before they can be listed
        temp_row = QHBoxLayout()
        temp_row.setSpacing(8)
        lbl_temp = QLabel("임시 폴더:")
        lbl_temp.setProperty("muted", True)
        self.edit_temp_dir = QLineEdit()
        self.edit_temp_dir.setReadOnly(True)
        self.lbl_temp_free = QLabel("")
        self.lbl_temp_free.setProperty("muted", True)
        self.btn_temp_browse = QPushButton("변경...")
        self.btn_temp_browse.setToolTip("여유 공간이 충분한 드라이브의 폴더를 임시 폴더로 지정합니다.")
        self.btn_temp_browse.clicked.connect(self._choose_temp_dir)
        self.btn_temp_reset = QPushButton("기본값")
        self.btn_temp_reset.setToolTip("시스템 기본 임시 폴더로 되돌립니다.")
        self.btn_temp_reset.clicked.connect(self._reset_temp_dir)

        temp_row.addWidget(lbl_temp)
        temp_row.addWidget(self.edit_temp_dir, 1)
        temp_row.addWidget(self.lbl_temp_free)
        temp_row.addWidget(self.btn_temp_browse)
        temp_row.addWidget(self.btn_temp_reset)
        opt_outer.addLayout(temp_row)

        action_row = QHBoxLayout()
        action_row.setSpacing(8)

        self.btn_scan = QPushButton("스캔 시작")
        self.btn_scan.setProperty("primary", True)
        self.btn_scan.setMinimumWidth(130)
        self.btn_scan.clicked.connect(self.start_scan)

        self.btn_stop = QPushButton("중지")
        self.btn_stop.setProperty("danger", True)
        self.btn_stop.setMinimumWidth(90)
        self.btn_stop.clicked.connect(self.stop_scan)

        self.btn_export = QPushButton("Excel로 내보내기 (.xlsx)")
        self.btn_export.setProperty("success", True)
        self.btn_export.setMinimumWidth(195)
        self.btn_export.clicked.connect(self.export_excel_dialog)

        self.chk_open_after_export = QCheckBox("저장 후 Excel 바로 열기")
        self.chk_open_after_export.setChecked(True)

        self.chk_save_log = QCheckBox("로그(.log)도 함께 저장")
        self.chk_save_log.setChecked(False)
        self.chk_save_log.setToolTip(
            "Excel 파일과 같은 위치·같은 이름으로 이번 스캔의 상세 로그(.log)를 저장합니다.\n"
            "압축파일별 생성/수정 시각 기록 현황과 오류의 상세 원인이 담깁니다."
        )

        action_row.addWidget(self.btn_scan)
        action_row.addWidget(self.btn_stop)
        action_row.addSpacing(8)
        action_row.addWidget(self.btn_export)
        action_row.addWidget(self.chk_open_after_export)
        action_row.addWidget(self.chk_save_log)
        action_row.addStretch(1)

        # Stats badges
        self.lbl_stat_entries = QLabel("항목: 0")
        self.lbl_stat_archives = QLabel("탐색 압축: 0")
        self.lbl_stat_size = QLabel("용량: 0 B")
        self.lbl_stat_time = QLabel("시간: 0.00s")
        for lbl in (
            self.lbl_stat_entries,
            self.lbl_stat_archives,
            self.lbl_stat_size,
            self.lbl_stat_time,
        ):
            lbl.setProperty("badge", True)
            action_row.addWidget(lbl)

        opt_outer.addLayout(action_row)

        # Progress bar + current path
        prog_row = QHBoxLayout()
        prog_row.setSpacing(10)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("대기 중")
        self.progress_bar.setFixedWidth(220)

        self.lbl_current_path = QLabel("스캔할 폴더, 파일 또는 압축파일을 추가하세요.")
        self.lbl_current_path.setProperty("muted", True)
        self.lbl_current_path.setMinimumWidth(120)

        self.btn_open_log = QPushButton("로그 열기")
        self.btn_open_log.setToolTip("현재 실행 중 기록된 상세 로그 파일을 엽니다.")
        self.btn_open_log.clicked.connect(self._open_log_file)
        self.btn_open_log_dir = QPushButton("로그 폴더")
        self.btn_open_log_dir.setToolTip("로그 파일이 저장되는 폴더를 엽니다. (최근 30개 보관)")
        self.btn_open_log_dir.clicked.connect(self._open_log_dir)

        prog_row.addWidget(self.progress_bar)
        prog_row.addWidget(self.lbl_current_path, 1)
        prog_row.addWidget(self.btn_open_log)
        prog_row.addWidget(self.btn_open_log_dir)
        opt_outer.addLayout(prog_row)

        top_layout.addWidget(options_panel)
        splitter.addWidget(top_widget)

        # Bottom Section: Results & Warnings Tabs
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        bottom_layout.setSpacing(6)

        filter_row = QHBoxLayout()
        filter_row.setSpacing(8)
        lbl_filter = QLabel("결과 필터:")
        lbl_filter.setProperty("sectionTitle", True)
        self.edit_filter = QLineEdit()
        self.edit_filter.setPlaceholderText("디렉토리 이름, 파일 이름, 구분으로 실시간 검색...")
        self.edit_filter.setClearButtonEnabled(True)
        self.edit_filter.textChanged.connect(self._on_filter_text_changed)

        self.lbl_filter_count = QLabel("")
        self.lbl_filter_count.setProperty("muted", True)

        filter_row.addWidget(lbl_filter)
        filter_row.addWidget(self.edit_filter, 1)
        filter_row.addWidget(self.lbl_filter_count)
        bottom_layout.addLayout(filter_row)

        self.tabs = QTabWidget()

        # Tab 1: File entries table
        self.table_model = FileEntryTableModel(self)
        self.proxy_model = MultiColumnFilterProxy(self)
        self.proxy_model.setSourceModel(self.table_model)

        self.table_view = QTableView()
        self.table_view.setModel(self.proxy_model)
        self.table_view.setSortingEnabled(True)
        # Qt's default sort indicator is column 0 descending, which listed results last-to-first
        self.table_view.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.table_view.setAlternatingRowColors(True)
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_view.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table_view.verticalHeader().setVisible(False)
        self.table_view.verticalHeader().setDefaultSectionSize(24)
        self.table_view.setWordWrap(False)

        hdr = self.table_view.horizontalHeader()
        hdr.setStretchLastSection(False)
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        col_widths = (55, 340, 210, 145, 145, 115, 125)
        for idx, width in enumerate(col_widths):
            self.table_view.setColumnWidth(idx, width)

        self.tabs.addTab(self.table_view, "파일 목록 (0)")

        # Tab 2: Warnings table
        self.warning_model = WarningTableModel(self)
        self.warning_view = QTableView()
        self.warning_view.setModel(self.warning_model)
        self.warning_view.setAlternatingRowColors(True)
        self.warning_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.warning_view.verticalHeader().setVisible(False)
        self.warning_view.verticalHeader().setDefaultSectionSize(24)
        whdr = self.warning_view.horizontalHeader()
        whdr.setStretchLastSection(True)
        self.warning_view.setColumnWidth(0, 55)
        self.warning_view.setColumnWidth(1, 540)

        self.tabs.addTab(self.warning_view, "경고 및 오류 (0)")
        bottom_layout.addWidget(self.tabs, 1)

        splitter.addWidget(bottom_widget)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("준비 완료 — 폴더, 파일 또는 압축파일을 드래그 앤 드롭하세요.")

        # Keyboard shortcuts
        QShortcut(QKeySequence("Delete"), self.input_list, activated=self._remove_selected_inputs)
        QShortcut(QKeySequence("Ctrl+F"), self, activated=self.edit_filter.setFocus)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if self._is_busy():
            event.ignore()
            return
        if event.mimeData().hasUrls():
            urls = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]
            if urls:
                event.acceptProposedAction()
                return
        event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:
        if self._is_busy():
            event.ignore()
            return
        if event.mimeData().hasUrls():
            paths = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]
            if paths:
                self.add_paths(paths)
                event.acceptProposedAction()
                return
        event.ignore()

    def add_paths(self, paths: list[str]) -> None:
        if self._is_busy():
            return
        existing = {os.path.normcase(p) for p in self._input_paths}
        added = 0
        for raw in paths:
            try:
                p = str(Path(raw).resolve())
            except OSError:
                p = str(Path(raw))
            key = os.path.normcase(p)
            if key in existing:
                continue
            existing.add(key)
            self._input_paths.append(p)
            path_obj = Path(p)
            if path_obj.is_dir():
                tag = "[폴더]"
            elif is_supported_archive(path_obj.name):
                tag = "[압축]"
            else:
                tag = "[파일]"
            item = QListWidgetItem(f"{tag}  {p}")
            item.setData(Qt.ItemDataRole.UserRole, p)
            self.input_list.addItem(item)
            added += 1

        if added:
            self.status_bar.showMessage(
                f"{added}개 대상이 추가되었습니다. (총 {len(self._input_paths)}개)"
            )
        self._update_button_states()

    def _choose_folder(self) -> None:
        if self._is_busy():
            return
        folder = QFileDialog.getExistingDirectory(self, "스캔할 폴더 선택")
        if folder:
            self.add_paths([folder])

    def _choose_files(self) -> None:
        if self._is_busy():
            return
        arc_patterns = " ".join(f"*{ext}" for ext in SUPPORTED_ARCHIVE_EXTENSIONS)
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "스캔할 파일 또는 압축파일 선택",
            "",
            f"모든 파일 (*.*);;지원 압축파일 ({arc_patterns})",
        )
        if files:
            self.add_paths(files)

    def _remove_selected_inputs(self) -> None:
        if self._is_busy():
            return
        selected = self.input_list.selectedItems()
        if not selected:
            return
        to_remove = {item.data(Qt.ItemDataRole.UserRole) for item in selected}
        for item in selected:
            row = self.input_list.row(item)
            self.input_list.takeItem(row)
        self._input_paths = [p for p in self._input_paths if p not in to_remove]
        self._update_button_states()

    def _clear_inputs(self) -> None:
        if self._is_busy():
            return
        self.input_list.clear()
        self._input_paths.clear()
        self._update_button_states()

    def _is_busy(self) -> bool:
        return self._is_scanning or self._is_exporting

    def _update_button_states(self) -> None:
        busy = self._is_busy()
        has_inputs = len(self._input_paths) > 0
        has_exportable = self._last_result is not None and (
            len(self._last_result.entries) > 0 or len(self._last_result.warnings) > 0
        )
        scan_arc_enabled = self.chk_scan_archives.isChecked()

        self.drop_zone.setEnabled(not busy)
        self.btn_scan.setEnabled(has_inputs and not busy)
        self.btn_stop.setEnabled(self._is_scanning)
        self.btn_export.setEnabled(has_exportable and not busy)
        self.btn_add_folder.setEnabled(not busy)
        self.btn_add_files.setEnabled(not busy)
        self.btn_remove_selected.setEnabled(has_inputs and not busy)
        self.btn_clear_inputs.setEnabled(has_inputs and not busy)
        self.chk_scan_archives.setEnabled(not busy)
        self.chk_include_archives.setEnabled(not busy and scan_arc_enabled)
        self.chk_include_empty_dirs.setEnabled(not busy)
        self.spin_threads.setEnabled(not busy)
        self.spin_depth.setEnabled(not busy and scan_arc_enabled)
        self.edit_temp_dir.setEnabled(not busy and scan_arc_enabled)
        self.btn_temp_browse.setEnabled(not busy and scan_arc_enabled)
        self.btn_temp_reset.setEnabled(
            not busy and scan_arc_enabled and self._temp_dir is not None
        )

        logging_on = logsetup.current_log_path() is not None
        self.chk_save_log.setEnabled(logging_on and not busy)
        self.btn_open_log.setEnabled(logging_on)
        self.btn_open_log_dir.setEnabled(logging_on)

    def set_temp_dir(self, path: str | None) -> None:
        """Select the folder nested archives are unpacked in; None restores the system default."""
        self._temp_dir = os.path.abspath(path) if path else None
        log.info("임시 폴더 설정: %s", self._temp_dir or "시스템 기본")
        self._refresh_temp_dir()
        self._update_button_states()

    def _reset_temp_dir(self) -> None:
        # A bound-method slot: a lambda capturing self would keep the window alive in a
        # reference cycle until interpreter shutdown, where Qt teardown then crashes
        self.set_temp_dir(None)

    def _refresh_temp_dir(self) -> None:
        """Show the temp folder in use and the free space of its drive."""
        folder = self._temp_dir or tempfile.gettempdir()
        self.edit_temp_dir.setText(folder)
        self.edit_temp_dir.setCursorPosition(0)  # keep the drive visible when the path is long
        usable = os.path.isdir(folder)
        self.lbl_temp_free.setText(
            f"여유 {logsetup.free_space_text(folder)}" if usable else "폴더 없음"
        )
        tip = (
            "압축파일 안의 중첩 압축파일을 풀어 두는 임시 작업 폴더입니다. "
            "스캔이 끝나면 자동으로 비워집니다.\n"
            "공간이 모자라면 중첩 압축파일 내부를 탐색하지 못하므로, "
            "여유 공간이 충분한 드라이브의 폴더로 바꾸세요.\n\n"
            f"{'사용자 지정' if self._temp_dir else '시스템 기본'}: {folder}"
        )
        if not usable:
            tip += "\n폴더를 찾을 수 없어 스캔할 때 시스템 기본 임시 폴더를 대신 사용합니다."
        self.edit_temp_dir.setToolTip(tip)
        self.lbl_temp_free.setToolTip(tip)

    def _choose_temp_dir(self) -> None:
        if self._is_busy():
            return
        folder = QFileDialog.getExistingDirectory(
            self,
            "중첩 압축파일을 풀 임시 폴더 선택",
            self._temp_dir or tempfile.gettempdir(),
        )
        if not folder:
            return
        folder = os.path.abspath(folder)
        problem = temp_dir_problem(folder)
        if problem is not None:
            QMessageBox.warning(
                self,
                "임시 폴더",
                f"이 폴더는 임시 폴더로 사용할 수 없습니다:\n{folder}\n\n{problem}",
            )
            return
        self.set_temp_dir(folder)
        self.status_bar.showMessage(
            f"임시 폴더를 변경했습니다: {folder} ({self.lbl_temp_free.text()})"
        )

    def _open_log_file(self) -> None:
        path = logsetup.current_log_path()
        if path is None:
            return
        logsetup.current_log_size()  # flush pending records before the viewer reads the file
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _open_log_dir(self) -> None:
        path = logsetup.current_log_path()
        if path is None:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path.parent)))

    def start_scan(self) -> None:
        if not self._input_paths or self._is_busy() or self._scan_thread is not None:
            return

        options = ScanOptions(
            scan_archives=self.chk_scan_archives.isChecked(),
            include_archive_files=self.chk_include_archives.isChecked(),
            include_empty_dirs=self.chk_include_empty_dirs.isChecked(),
            max_archive_depth=self.spin_depth.value(),
            max_workers=self.spin_threads.value(),
            temp_dir=self._temp_dir,
        )

        self._is_scanning = True
        self._last_result = None
        self._scan_log_offset = logsetup.current_log_size()
        self.table_model.clear()
        self.warning_model.clear()
        self.tabs.setTabText(0, "파일 목록 (0)")
        self.tabs.setTabText(1, "경고 및 오류 (0)")
        self.lbl_filter_count.setText("")

        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFormat("스캔 중...")
        self.lbl_current_path.setText("멀티스레드 스캔을 시작하는 중...")
        self.status_bar.showMessage(
            f"스캔 실행 중 (워커 스레드 {options.max_workers}개)..."
        )

        thread = ScanWorkerThread(self._input_paths, options)
        thread.progress.connect(self._on_scan_progress)
        thread.finished_result.connect(self._on_scan_finished)
        thread.failed.connect(self._on_scan_failed)
        thread.finished.connect(self._on_scan_thread_cleanup)
        self._scan_thread = thread
        self._update_button_states()
        thread.start()

    def stop_scan(self) -> None:
        if self._scan_thread is not None and self._is_scanning:
            self._scan_thread.request_cancel()
            self.btn_stop.setEnabled(False)
            self.progress_bar.setFormat("중지 중...")
            self.status_bar.showMessage("스캔 중지를 요청했습니다...")

    def _on_scan_progress(self, snap: ProgressSnapshot) -> None:
        self.lbl_stat_entries.setText(f"항목: {snap.entries_found:,}")
        self.lbl_stat_archives.setText(f"탐색 압축: {snap.archives_scanned:,}")
        self.lbl_stat_size.setText(f"용량: {format_size(snap.total_size)}")
        self.lbl_stat_time.setText(f"시간: {snap.elapsed_seconds:.2f}s")
        if snap.current_path:
            display = snap.current_path
            if len(display) > 110:
                display = "..." + display[-107:]
            self.lbl_current_path.setText(display)

    def _on_scan_finished(self, result: ScanResult) -> None:
        self._is_scanning = False
        self._last_result = result
        self.table_model.set_entries(result.entries)
        self.warning_model.set_warnings(result.warnings)

        stats = result.stats
        self.tabs.setTabText(0, f"파일 목록 ({stats.total_entries:,})")
        self.tabs.setTabText(1, f"경고 및 오류 ({len(result.warnings):,})")

        self.lbl_stat_entries.setText(f"항목: {stats.total_entries:,}")
        self.lbl_stat_archives.setText(f"탐색 압축: {stats.archives_scanned:,}")
        self.lbl_stat_size.setText(f"용량: {format_size(stats.total_size)}")
        self.lbl_stat_time.setText(f"시간: {stats.elapsed_seconds:.2f}s")

        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        if stats.cancelled:
            self.progress_bar.setFormat("중지됨")
            msg = f"스캔이 중지되었습니다 — {stats.total_entries:,}개 항목 수집 ({stats.elapsed_seconds:.2f}초)"
        else:
            self.progress_bar.setFormat("완료")
            msg = (
                f"스캔 완료 — 총 {stats.total_entries:,}개 항목, "
                f"{format_size(stats.total_size)}, "
                f"최대 압축 깊이 {stats.max_depth_seen}단계 "
                f"({stats.elapsed_seconds:.2f}초, 스레드 {stats.worker_count}개)"
            )
            if stats.created_missing:
                msg += f" · 생성 날짜 없음 {stats.created_missing:,}개"
        self.lbl_current_path.setText(msg)
        self.status_bar.showMessage(msg)
        self._apply_filter_now()
        self._update_button_states()

    def _on_scan_failed(self, error_msg: str) -> None:
        self._is_scanning = False
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("오류")
        self.lbl_current_path.setText(f"오류 발생: {error_msg}")
        self.status_bar.showMessage("스캔 중 오류가 발생했습니다.")
        QMessageBox.critical(self, "스캔 오류", f"스캔 처리 중 오류가 발생했습니다:\n{error_msg}")
        self._update_button_states()

    def _on_scan_thread_cleanup(self) -> None:
        thread = self._scan_thread
        self._scan_thread = None
        self._is_scanning = False
        if thread is not None:
            thread.deleteLater()
        self._refresh_temp_dir()  # free space may have changed
        self._update_button_states()

    def _on_filter_text_changed(self, _text: str) -> None:
        self._filter_timer.start()

    def _apply_filter_now(self) -> None:
        text = self.edit_filter.text()
        self.proxy_model.set_search_text(text)
        total = self.table_model.rowCount()
        shown = self.proxy_model.rowCount()
        if text.strip():
            self.lbl_filter_count.setText(f"{shown:,} / {total:,} 표시")
        else:
            self.lbl_filter_count.setText(f"총 {total:,}개" if total else "")

    def _suggest_export_filename(self) -> str:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scanned_paths = (
            self._last_result.stats.input_paths
            if self._last_result is not None
            else self._input_paths
        )
        if len(scanned_paths) == 1:
            base = Path(scanned_paths[0]).stem or "DeepLister"
            safe_base = "".join(c if c not in r'<>:"/\|?*' else "_" for c in base)[:40]
            return f"{safe_base}_filelist_{stamp}.xlsx"
        return f"DeepLister_{stamp}.xlsx"

    def export_excel_dialog(self) -> None:
        if self._last_result is None or self._is_busy() or self._export_thread is not None:
            return

        scanned_paths = self._last_result.stats.input_paths
        default_dir = (
            str(Path(scanned_paths[0]).parent)
            if scanned_paths
            else str(Path.home() / "Desktop")
        )
        default_path = str(Path(default_dir) / self._suggest_export_filename())

        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Excel 파일로 저장",
            default_path,
            "Excel 통합 문서 (*.xlsx)",
        )
        if not save_path:
            return
        if not save_path.lower().endswith(".xlsx"):
            save_path += ".xlsx"

        self._is_exporting = True
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFormat("Excel 저장 중...")
        self.status_bar.showMessage(f"Excel 파일 생성 중: {save_path}")

        log_offset = self._scan_log_offset if self.chk_save_log.isChecked() else None
        thread = ExportWorkerThread(self._last_result, save_path, log_offset)
        thread.finished_path.connect(self._on_export_finished)
        thread.failed.connect(self._on_export_failed)
        thread.finished.connect(self._on_export_thread_cleanup)
        self._export_thread = thread
        self._update_button_states()
        thread.start()

    def _on_export_finished(self, saved_path: str, log_copy_path: str = "") -> None:
        self._is_exporting = False
        self._last_export_path = Path(saved_path)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("저장 완료")
        status = f"Excel 저장 완료: {saved_path}"
        if log_copy_path:
            status += f" · 로그: {Path(log_copy_path).name}"
        self.status_bar.showMessage(status)
        self._update_button_states()

        if self.chk_open_after_export.isChecked():
            try:
                os.startfile(saved_path)  # type: ignore[attr-defined]
            except Exception as exc:
                QMessageBox.information(
                    self,
                    "저장 완료",
                    f"Excel 파일이 저장되었습니다:\n{saved_path}\n\n(자동 열기 실패: {exc})",
                )
        else:
            detail = f"\n\n로그 파일:\n{log_copy_path}" if log_copy_path else ""
            QMessageBox.information(
                self,
                "저장 완료",
                f"Excel 파일이 성공적으로 저장되었습니다:\n{saved_path}{detail}",
            )

    def _on_export_failed(self, error_msg: str) -> None:
        self._is_exporting = False
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("저장 오류")
        self.status_bar.showMessage("Excel 저장 실패")
        QMessageBox.critical(
            self,
            "Excel 저장 오류",
            f"Excel 파일을 저장하지 못했습니다:\n{error_msg}\n\n"
            "대상 파일이 Excel에서 열려 있다면 닫고 다시 시도하세요.",
        )
        self._update_button_states()

    def _on_export_thread_cleanup(self) -> None:
        thread = self._export_thread
        self._export_thread = None
        self._is_exporting = False
        if thread is not None:
            thread.deleteLater()
        self._update_button_states()

    def closeEvent(self, event) -> None:
        if self._export_thread is not None and self._export_thread.isRunning():
            QMessageBox.information(
                self,
                "Excel 저장 진행 중",
                "Excel 파일 저장이 진행 중입니다. 파일 손상을 방지하기 위해 저장이 완료된 뒤 창을 닫아 주세요.",
            )
            event.ignore()
            return

        if self._scan_thread is not None and self._scan_thread.isRunning():
            self._scan_thread.request_cancel()
            if not self._scan_thread.wait(5000):
                QMessageBox.warning(
                    self,
                    "스캔 종료 대기",
                    "백그라운드 스캔이 정리 중입니다. 잠시 후 다시 창을 닫아 주세요.",
                )
                event.ignore()
                return

        super().closeEvent(event)


def run_gui(
    smoke_test: bool = False,
    initial_paths: list[str] | None = None,
    log_dir: str | None = None,
    temp_dir: str | None = None,
) -> int:
    """Launch the DeepLister Qt application."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)

    logsetup.start_file_logging(log_dir)
    logsetup.install_exception_hooks()
    try:
        window = MainWindow()
        if temp_dir:
            window.set_temp_dir(temp_dir)
        if initial_paths:
            window.add_paths(initial_paths)

        if smoke_test:
            window.show()
            app.processEvents()
            window.close()
            return 0

        window.show()
        return app.exec()
    finally:
        log.info("===== 세션 종료 =====")
        logsetup.stop_file_logging()
