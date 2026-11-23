"""Offscreen PySide6 GUI smoke and workflow tests."""

from __future__ import annotations

import os
import tempfile
import zipfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox

import main
from deeplister import logsetup
from deeplister import ui as ui_module
from deeplister.models import CREATED_MISSING_HINTS, SOURCE_ZIP
from deeplister.ui import ExportWorkerThread, FileEntryTableModel, MainWindow


def _ensure_app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_gui_scan_and_filter(tmp_path: Path) -> None:
    app = _ensure_app()

    zpath = tmp_path / "bundle.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("report/summary.txt", b"hello gui")

    win = MainWindow()
    win.show()
    win.add_paths([str(tmp_path)])
    assert win.input_list.count() == 1
    assert win.btn_scan.isEnabled()

    win.start_scan()
    assert win._scan_thread is not None
    win._scan_thread.wait(10_000)
    app.processEvents()

    assert win._last_result is not None
    assert win.table_model.rowCount() == 2  # bundle.zip + summary.txt
    assert win.btn_export.isEnabled()

    # Rows are listed first-to-last by default, matching the exported workbook
    assert win.proxy_model.data(win.proxy_model.index(0, 0)) == "1"
    assert win.proxy_model.data(win.proxy_model.index(1, 0)) == "2"

    # Size is shown once, in bytes: the duplicate human-readable column is gone
    model = win.table_model
    assert model.columnCount() == 7
    assert list(FileEntryTableModel.HEADERS) == [
        "No.",
        "디렉토리 이름",
        "파일 이름",
        "생성 날짜",
        "수정된 날짜",
        "용량 (Bytes)",
        "구분",
    ]
    member_row = next(r for r in range(2) if model.entry_at(r).name == "summary.txt")
    assert model.data(model.index(member_row, 5)) == "9"
    assert model.data(model.index(member_row, 6)).startswith("압축 내부")
    # A missing created date explains itself instead of looking like a bug
    assert model.data(model.index(member_row, 3)) == "-"
    assert (
        model.data(model.index(member_row, 3), Qt.ItemDataRole.ToolTipRole)
        == CREATED_MISSING_HINTS[SOURCE_ZIP]
    )
    assert "생성 날짜 없음" in win.status_bar.currentMessage()

    # Without an active log file the log controls stay disabled
    assert not win.chk_save_log.isEnabled()
    assert not win.btn_open_log.isEnabled()

    win.edit_filter.setText("summary.txt")
    win._apply_filter_now()
    app.processEvents()
    assert win.proxy_model.rowCount() == 1

    win.close()
    app.processEvents()


def test_gui_export_saves_scan_log_next_to_excel(tmp_path: Path) -> None:
    app = _ensure_app()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    with zipfile.ZipFile(data_dir / "bundle.zip", "w") as zf:
        zf.writestr("report/summary.txt", b"hello gui")

    log_path = logsetup.start_file_logging(tmp_path / "logs")
    assert log_path is not None
    try:
        win = MainWindow()
        win.show()
        win.add_paths([str(data_dir)])
        assert win.chk_save_log.isEnabled()
        assert win.btn_open_log.isEnabled()
        assert not win.chk_save_log.isChecked()  # opt-in

        win.start_scan()
        win._scan_thread.wait(10_000)
        app.processEvents()
        assert win._last_result is not None
        assert win._last_result.stats.log_path == str(log_path)

        xlsx_path = tmp_path / "out" / "list.xlsx"
        exporter = ExportWorkerThread(win._last_result, str(xlsx_path), win._scan_log_offset)
        saved: list[tuple[str, str]] = []
        exporter.finished_path.connect(lambda x, lg: saved.append((x, lg)))
        exporter.start()
        exporter.wait(10_000)
        app.processEvents()

        scan_log = tmp_path / "out" / "list.log"
        assert saved == [(str(xlsx_path), str(scan_log))]
        assert xlsx_path.is_file()
        text = scan_log.read_text(encoding="utf-8-sig")
        assert "ZIP 스캔 완료" in text and "bundle.zip" in text
        assert "Excel 저장 완료" in text

        # Not requested (log_offset=None): only the workbook is written
        plain_path = tmp_path / "out" / "plain.xlsx"
        exporter = ExportWorkerThread(win._last_result, str(plain_path))
        exporter.start()
        exporter.wait(10_000)
        app.processEvents()
        assert plain_path.is_file()
        assert not plain_path.with_suffix(".log").exists()

        win.close()
        app.processEvents()
    finally:
        logsetup.stop_file_logging()


def test_temp_dir_option_reaches_scan_options(tmp_path: Path) -> None:
    app = _ensure_app()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    with zipfile.ZipFile(data_dir / "bundle.zip", "w") as zf:
        zf.writestr("report/summary.txt", b"hello gui")
    work = tmp_path / "work"
    work.mkdir()

    def _scan_and_get_options():
        win.start_scan()
        thread = win._scan_thread
        assert thread is not None
        assert not win.btn_temp_browse.isEnabled()  # locked while a scan runs
        options = thread._options
        thread.wait(10_000)
        app.processEvents()
        assert win._scan_thread is None
        return options

    win = MainWindow()
    win.show()
    win.add_paths([str(data_dir)])

    # Default: the system temp folder is shown, there is nothing to reset
    assert win.edit_temp_dir.isReadOnly()
    assert win.edit_temp_dir.text() == tempfile.gettempdir()
    assert win.lbl_temp_free.text().startswith("여유 ")
    assert win.btn_temp_browse.isEnabled()
    assert not win.btn_temp_reset.isEnabled()
    assert _scan_and_get_options().temp_dir is None

    win.set_temp_dir(str(work))
    assert win.edit_temp_dir.text() == str(work)
    assert win.lbl_temp_free.text().startswith("여유 ")
    assert win.btn_temp_reset.isEnabled()
    assert _scan_and_get_options().temp_dir == str(work)
    assert win._last_result is not None and not win._last_result.warnings
    assert list(work.iterdir()) == []

    # A folder that does not exist (e.g. from --temp-dir) is shown as such, not hidden
    win.set_temp_dir(str(tmp_path / "unplugged"))
    assert win.lbl_temp_free.text() == "폴더 없음"

    win.btn_temp_reset.click()
    assert win.edit_temp_dir.text() == tempfile.gettempdir()
    assert not win.btn_temp_reset.isEnabled()
    assert _scan_and_get_options().temp_dir is None

    # The temp folder only matters when archives are scanned
    win.chk_scan_archives.setChecked(False)
    assert not win.btn_temp_browse.isEnabled()

    win.close()
    app.processEvents()


def test_temp_dir_browse_rejects_unusable_folder(tmp_path: Path, monkeypatch) -> None:
    app = _ensure_app()
    good = tmp_path / "good"
    good.mkdir()
    bad = tmp_path / "bad"
    bad.mkdir()
    win = MainWindow()

    picked: list[str] = [str(good)]
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *args, **kwargs: picked[0])
    win.btn_temp_browse.click()
    assert win._temp_dir == str(good)
    assert list(good.iterdir()) == []  # the writability probe cleans up after itself

    # A folder nothing can be written to is refused with a message; the selection stays
    shown: list[str] = []
    monkeypatch.setattr(QMessageBox, "warning", lambda _parent, _title, text: shown.append(text))
    monkeypatch.setattr(
        ui_module,
        "temp_dir_problem",
        lambda path: "폴더에 쓸 수 없습니다: 액세스가 거부되었습니다" if Path(path) == bad else None,
    )
    picked[0] = str(bad)
    win.btn_temp_browse.click()
    assert win._temp_dir == str(good)
    assert len(shown) == 1 and str(bad) in shown[0] and "쓸 수 없습니다" in shown[0]

    picked[0] = ""  # dialog cancelled
    win.btn_temp_browse.click()
    assert win._temp_dir == str(good)

    win.close()
    app.processEvents()


def test_temp_dir_command_line_argument(monkeypatch) -> None:
    assert main.parse_args([]).temp_dir is None
    assert main.parse_args(["--temp-dir", "work dir", "some.zip"]).temp_dir == "work dir"

    received: dict = {}
    monkeypatch.setattr(main, "run_gui", lambda **kwargs: received.update(kwargs) or 0)
    assert main.main(["--temp-dir", "work dir"]) == 0
    assert received["temp_dir"] == "work dir"
