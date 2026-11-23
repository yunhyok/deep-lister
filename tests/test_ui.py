"""Offscreen PySide6 GUI smoke and workflow tests."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QApplication

from deeplister import logsetup
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

    # Size is shown once, in bytes, followed by SPD metadata columns
    model = win.table_model
    assert model.columnCount() == 10
    assert list(FileEntryTableModel.HEADERS) == [
        "No.",
        "디렉토리 이름",
        "파일 이름",
        "생성 날짜",
        "수정된 날짜",
        "용량 (Bytes)",
        "구분",
        "활성 NET 수",
        "Component Type 수",
        "RefDes 수",
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


def _scan_and_wait(app: QApplication, win: MainWindow) -> None:
    win.start_scan()
    win._scan_thread.wait(10_000)
    app.processEvents()


def test_gui_temp_dir_is_used_validated_and_remembered(tmp_path: Path) -> None:
    app = _ensure_app()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    with zipfile.ZipFile(data_dir / "bundle.zip", "w") as zf:
        zf.writestr("a.txt", b"a")
    work_dir = tmp_path / "임시 작업"  # non-ASCII and a space must survive the settings file
    work_dir.mkdir()
    settings_file = tmp_path / "settings.ini"

    win = MainWindow(QSettings(str(settings_file), QSettings.Format.IniFormat))
    win.show()

    # Default: the system temp folder, nothing to reset, automatic space limit
    assert win.temp_limit_gb() == 0
    assert win.spin_temp_limit.text() == "자동"
    assert win.temp_dir() is None
    assert win.edit_temp_dir.text() == tempfile.gettempdir()
    assert win.lbl_temp_state.text().startswith("기본값 · 여유 ")
    assert not win.btn_temp_reset.isEnabled()

    # An unusable folder is rejected and the previous choice stays
    assert not win.set_temp_dir(str(tmp_path / "missing"))
    assert win.temp_dir() is None

    assert win.set_temp_dir(str(work_dir))
    assert win.temp_dir() == str(work_dir)
    assert win.edit_temp_dir.text() == str(work_dir)
    assert win.lbl_temp_state.text().startswith("사용자 지정 · 여유 ")
    assert win.btn_temp_reset.isEnabled()

    win.spin_temp_limit.setValue(50)  # as typed by the user
    assert win.temp_limit_gb() == 50
    assert win.spin_temp_limit.text() == "50 GB"

    # The choices reach the scan
    win.add_paths([str(data_dir)])
    win.start_scan()
    scan_thread = win._scan_thread
    assert scan_thread._options.temp_dir == str(work_dir)
    assert scan_thread._options.max_temp_bytes == 50 * 1024**3
    assert not win.btn_temp_browse.isEnabled()  # locked while scanning
    assert not win.spin_temp_limit.isEnabled()
    scan_thread.wait(10_000)
    app.processEvents()
    assert win._last_result is not None
    assert not win._last_result.warnings
    assert list(work_dir.iterdir()) == []
    win.close()
    app.processEvents()

    # ...and are remembered by the next window
    reopened = MainWindow(QSettings(str(settings_file), QSettings.Format.IniFormat))
    assert reopened.temp_dir() == str(work_dir)
    assert reopened.edit_temp_dir.text() == str(work_dir)
    assert reopened.temp_limit_gb() == 50
    assert reopened.spin_temp_limit.value() == 50

    reopened.btn_temp_reset.click()
    assert reopened.temp_dir() is None
    assert reopened.edit_temp_dir.text() == tempfile.gettempdir()
    reopened.spin_temp_limit.setValue(0)
    reopened.add_paths([str(data_dir)])
    reopened.start_scan()
    scan_thread = reopened._scan_thread
    assert scan_thread._options.max_temp_bytes is None  # automatic
    scan_thread.wait(10_000)
    app.processEvents()
    reopened.close()
    app.processEvents()

    third = MainWindow(QSettings(str(settings_file), QSettings.Format.IniFormat))
    assert third.temp_dir() is None
    assert third.temp_limit_gb() == 0
    third.close()
    app.processEvents()


def test_gui_saved_temp_dir_that_disappeared_falls_back_with_a_warning(tmp_path: Path) -> None:
    app = _ensure_app()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    with zipfile.ZipFile(data_dir / "bundle.zip", "w") as zf:
        zf.writestr("a.txt", b"a")
    gone = tmp_path / "unplugged_drive"

    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat)
    settings.setValue("scan/temp_dir", str(gone))
    settings.sync()

    win = MainWindow(settings)
    win.show()
    assert win.temp_dir() == str(gone)  # kept: the drive may come back
    assert "사용할 수 없음" in win.lbl_temp_state.text()

    win.add_paths([str(data_dir)])
    _scan_and_wait(app, win)
    result = win._last_result
    assert result is not None
    assert "a.txt" in {e.name for e in result.entries}
    assert any("지정한 임시 폴더를 사용할 수 없어" in w.reason for w in result.warnings)
    win.close()
    app.processEvents()


def test_app_starts_and_exits_cleanly(tmp_path: Path) -> None:
    """Qt teardown crashes happen at interpreter exit: only a separate process can observe them."""
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen", LOCALAPPDATA=str(tmp_path / "appdata"))
    main_script = Path(__file__).resolve().parent.parent / "main.py"

    proc = subprocess.run(
        [
            sys.executable,
            str(main_script),
            "--smoke-test",
            "--temp-dir",
            str(work_dir),
            "--temp-limit-gb",
            "7",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert proc.returncode == 0, proc.stderr
    logs = list((tmp_path / "appdata" / "DeepLister" / "logs").glob("DeepLister_*.log"))
    assert len(logs) == 1
    text = logs[0].read_text(encoding="utf-8-sig")
    assert f"임시 폴더 설정: {work_dir}" in text
    assert "임시 공간 한도 설정: 7 GB" in text
    assert "세션 종료" in text
    # Command-line temp settings apply to that run only and are not saved
    assert not (tmp_path / "appdata" / "DeepLister" / "settings.ini").exists()
