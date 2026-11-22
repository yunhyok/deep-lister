"""Offscreen PySide6 GUI smoke and workflow tests."""

from __future__ import annotations

import os
import zipfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from deeplister.ui import MainWindow


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

    win.edit_filter.setText("summary.txt")
    win._apply_filter_now()
    app.processEvents()
    assert win.proxy_model.rowCount() == 1

    win.close()
    app.processEvents()
