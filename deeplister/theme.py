"""Spectrum-inspired dark desktop theme matching yunhyok's recent Windows apps."""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtGui import QColor, QIcon, QPalette
from PySide6.QtWidgets import QApplication, QWidget

from . import APP_ID


def assets_dir() -> Path:
    """Resolve bundled assets directory for both source and PyInstaller runs."""
    base = getattr(sys, "_MEIPASS", None)
    if base is not None:
        candidate = Path(base) / "deeplister" / "assets"
        if candidate.exists():
            return candidate
    return Path(__file__).resolve().parent / "assets"


def app_icon() -> QIcon:
    """Load the bundled application icon (.ico preferred, .png fallback)."""
    assets = assets_dir()
    ico = assets / "app.ico"
    if ico.exists():
        return QIcon(str(ico))
    png = assets / "app.png"
    if png.exists():
        return QIcon(str(png))
    return QIcon()


def apply_theme(window: QWidget) -> None:
    """Apply Spectrum-inspired Dark Theme and Windows native dark title bar."""
    app = QApplication.instance()
    if app is not None:
        if app.style().objectName().lower() != "fusion":
            app.setStyle("Fusion")

    palette = QPalette()
    for role, color in {
        QPalette.ColorRole.Window: "#202226",
        QPalette.ColorRole.WindowText: "#eceef1",
        QPalette.ColorRole.Base: "#1d2025",
        QPalette.ColorRole.AlternateBase: "#25282e",
        QPalette.ColorRole.Text: "#eceef1",
        QPalette.ColorRole.Button: "#363b43",
        QPalette.ColorRole.ButtonText: "#eceef1",
        QPalette.ColorRole.Highlight: "#345d8c",
        QPalette.ColorRole.HighlightedText: "#ffffff",
        QPalette.ColorRole.ToolTipBase: "#363b43",
        QPalette.ColorRole.ToolTipText: "#ffffff",
        QPalette.ColorRole.PlaceholderText: "#a4aebb",
        QPalette.ColorRole.Link: "#8fc1ff",
        QPalette.ColorRole.Light: "#626b78",
        QPalette.ColorRole.Midlight: "#444a54",
        QPalette.ColorRole.Mid: "#555e6b",
        QPalette.ColorRole.Dark: "#15171a",
        QPalette.ColorRole.Shadow: "#111316",
    }.items():
        palette.setColor(role, QColor(color))

    for role in (
        QPalette.ColorRole.Text,
        QPalette.ColorRole.WindowText,
        QPalette.ColorRole.ButtonText,
        QPalette.ColorRole.PlaceholderText,
    ):
        palette.setColor(QPalette.ColorGroup.Disabled, role, QColor("#929ba8"))

    if app is not None:
        app.setPalette(palette)
        font = app.font()
        font.setFamilies(["Segoe UI", "Malgun Gothic"])
        font.setPointSize(10)
        app.setFont(font)

    window.setPalette(palette)
    win_font = window.font()
    win_font.setFamilies(["Segoe UI", "Malgun Gothic"])
    win_font.setPointSize(10)
    window.setFont(win_font)

    icon = app_icon()
    if not icon.isNull():
        if app is not None:
            app.setWindowIcon(icon)
        window.setWindowIcon(icon)

    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
            dark = wintypes.BOOL(True)
            hwnd = wintypes.HWND(int(window.winId()))
            # DWMWA_USE_IMMERSIVE_DARK_MODE (20 on Windows 10 2004+ / Windows 11)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 20, ctypes.byref(dark), ctypes.sizeof(dark)
            )
        except Exception:
            pass

    window.setStyleSheet("""
        QMainWindow, QDialog {
            background: #202226;
        }
        QGroupBox, QFrame[panel="true"] {
            background: #2b2e34;
            border: 1px solid #505761;
            border-radius: 5px;
        }
        QGroupBox {
            margin-top: 12px;
            padding: 12px 10px 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top left;
            left: 10px;
            padding: 0 5px;
            color: #dce3ed;
            font-weight: 600;
        }
        QFrame#DropZone {
            background: #1d2025;
            border: 2px dashed #556173;
            border-radius: 6px;
        }
        QFrame#DropZone[dragActive="true"] {
            background: #233042;
            border: 2px dashed #8fc1ff;
        }
        QLabel {
            background: transparent;
            border: none;
            color: #eceef1;
        }
        QLabel[heading="true"] {
            font-size: 18px;
            font-weight: 700;
            color: #f3f6fa;
        }
        QLabel[sectionTitle="true"] {
            color: #dce3ed;
            font-weight: 600;
        }
        QLabel[muted="true"] {
            color: #b9c1cc;
        }
        QLabel[accent="true"] {
            color: #8fc1ff;
            font-weight: 600;
        }
        QLabel[badge="true"] {
            background: #262a31;
            border: 1px solid #4d5563;
            border-radius: 4px;
            padding: 3px 8px;
            color: #dce3ed;
        }
        QLineEdit, QComboBox, QAbstractSpinBox, QAbstractItemView, QTextEdit, QPlainTextEdit {
            background: #1d2025;
            color: #eceef1;
            border: 1px solid #626c7a;
            border-radius: 3px;
            selection-background-color: #345d8c;
            selection-color: #ffffff;
        }
        QLineEdit, QComboBox, QAbstractSpinBox {
            padding: 4px 7px;
            min-height: 20px;
        }
        QLineEdit:focus, QComboBox:focus, QAbstractSpinBox:focus,
        QAbstractItemView:focus, QTextEdit:focus, QPlainTextEdit:focus {
            border: 1px solid #8fc1ff;
        }
        QLineEdit:read-only {
            background: #25282e;
            border-color: #4d5563;
        }
        QLineEdit:disabled, QComboBox:disabled, QAbstractSpinBox:disabled, QAbstractItemView:disabled {
            color: #929ba8;
            background: #292d33;
            border-color: #444b55;
        }
        QAbstractItemView {
            alternate-background-color: #25282e;
            gridline-color: #3a404a;
        }
        QAbstractItemView::item:selected {
            background: #345d8c;
            color: #ffffff;
        }
        QListWidget::item {
            padding: 4px 6px;
        }
        QListWidget::item:hover {
            background: #303946;
        }
        QHeaderView::section {
            background: #353a42;
            color: #eceef1;
            padding: 6px 8px;
            border: 1px solid #505761;
            font-weight: 600;
        }
        QTableView {
            gridline-color: #3c424d;
        }
        QPushButton {
            background: #363b43;
            color: #eceef1;
            border: 1px solid #626c7a;
            border-radius: 4px;
            padding: 6px 12px;
            min-height: 20px;
            font-weight: 500;
        }
        QPushButton:hover {
            background: #454c57;
            border-color: #798596;
        }
        QPushButton:pressed {
            background: #252a31;
        }
        QPushButton:focus {
            border: 1px solid #c1dcff;
        }
        QPushButton:disabled {
            background: #2c3138;
            color: #929ba8;
            border-color: #49515e;
        }
        QPushButton[primary="true"] {
            background: #386cb0;
            border-color: #7fa9e0;
            color: #ffffff;
            font-weight: 600;
        }
        QPushButton[primary="true"]:hover {
            background: #437dc7;
        }
        QPushButton[primary="true"]:pressed {
            background: #2d588f;
        }
        QPushButton[primary="true"]:disabled {
            background: #2d425c;
            color: #9aa7b8;
            border-color: #445a75;
        }
        QPushButton[success="true"] {
            background: #287552;
            border-color: #54a880;
            color: #ffffff;
            font-weight: 600;
        }
        QPushButton[success="true"]:hover {
            background: #318a62;
        }
        QPushButton[success="true"]:pressed {
            background: #216144;
        }
        QPushButton[success="true"]:disabled {
            background: #254537;
            color: #92aba0;
            border-color: #3c5c4e;
        }
        QPushButton[danger="true"] {
            background: #8c3d35;
            border-color: #ba6b63;
            color: #ffffff;
            font-weight: 600;
        }
        QPushButton[danger="true"]:hover {
            background: #a34940;
        }
        QPushButton[danger="true"]:disabled {
            background: #4a3130;
            color: #a18d8c;
            border-color: #5c4140;
        }
        QCheckBox {
            spacing: 6px;
            color: #eceef1;
        }
        QTabWidget::pane {
            border: 1px solid #505761;
            border-radius: 4px;
            background: #2b2e34;
        }
        QTabBar::tab {
            background: #2b2e34;
            color: #b9c1cc;
            border: 1px solid #505761;
            border-bottom: none;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            padding: 6px 14px;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background: #3b4656;
            color: #ffffff;
            font-weight: 600;
        }
        QSplitter::handle {
            background: #202226;
        }
        QSplitter::handle:hover {
            background: #6287b4;
        }
        QStatusBar {
            background: #292d33;
            color: #b9c7d9;
            border-top: 1px solid #444a54;
        }
        QStatusBar::item {
            border: none;
        }
        QProgressBar {
            background: #1d2025;
            border: 1px solid #626c7a;
            border-radius: 3px;
            text-align: center;
            color: #eceef1;
            min-height: 18px;
        }
        QProgressBar::chunk {
            background: #386cb0;
            border-radius: 2px;
        }
        QToolTip {
            background: #363b43;
            color: #ffffff;
            border: 1px solid #7e8999;
            padding: 6px;
        }
        QScrollBar:vertical {
            background: #1d2025;
            width: 11px;
            margin: 0;
        }
        QScrollBar::handle:vertical {
            background: #4b525e;
            min-height: 24px;
            border-radius: 4px;
            margin: 2px;
        }
        QScrollBar::handle:vertical:hover {
            background: #636d7d;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0;
        }
        QScrollBar:horizontal {
            background: #1d2025;
            height: 11px;
            margin: 0;
        }
        QScrollBar::handle:horizontal {
            background: #4b525e;
            min-width: 24px;
            border-radius: 4px;
            margin: 2px;
        }
        QScrollBar::handle:horizontal:hover {
            background: #636d7d;
        }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            width: 0;
        }
    """)
