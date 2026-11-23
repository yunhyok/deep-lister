"""Tests for Cadence PowerSI (.spd) extraction across folders, archives, and Excel export."""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import py7zr
from openpyxl import load_workbook

from deeplister.exporter import export_to_excel
from deeplister.models import ScanOptions
from deeplister.scanner import ScanEngine
from deeplister.spd import SpdCounter, parse_spd_file

SAMPLE_SPD = (
    "\ufeff* Cadence PowerSI board file\r\n"
    ".PartialCkt CAP_0402 ExtNode = 1 2\r\n"
    "* .Connect FAKE_REF FAKE_COMP\r\n"
    ".NetList\r\n"
    "FAKE_NET -> PowerNets\r\n"
    ".EndNetList\r\n"
    "C1 1 2 1u\r\n"
    ".EndPartialCkt\r\n"
    ".PARTIALCKT RES_0402 EXTNODE = A B\r\n"
    ".EndPartialCktExtra keep-me\r\n"
    "R1 A B 10\r\n"
    ".endpartialckt\r\n"
    ".PartialCkt UNUSED_MODEL ExtNode = 1 2\r\n"
    "L1 1 2 1n\r\n"
    ".EndPartialCkt\r\n"
    ".Connect C1 CAP_0402 Checked = 1\r\n"
    "1 $Package.Node1!!1::VDD_1V8\r\n"
    "2 $Package.Node2!!2::DGND\r\n"
    ".EndC\r\n"
    ".Connect C2 CAP_0402 Usage = 0b1000 Checked = 1\r\n"
    ".EndC\r\n"
    ".Connect R1 RES_0402 Usage = 0b111000 Checked = 1\r\n"
    ".EndC\r\n"
    ".Connect U1 DUT_BGA Checked = 1\r\n"
    ".EndC\r\n"
    ".NetList\r\n"
    "\t* Comment inside NetList\r\n"
    "\t::Unselected||DropShape RiseTime = 0ps %Coupling = 0\r\n"
    "\tSIG_OFF::Unselected||DropShape Color = RED\r\n"
    "\tSIG_ON||DropShape Color = RED\r\n"
    "\t+3_3V Color = GREEN\r\n"
    "\t+5V::Unselected Color = BLUE\r\n"
    "\tDGND -> GroundNets Color = YELLOW Voltage = 0\r\n"
    "\tAGND Color = YELLOW\r\n"
    "\tVDD_OFF -> PowerNets::Unselected||DropShape Voltage = 0.9 GroundNet = DGND\r\n"
    "\tVDD_1V8 Voltage = 1.8 GroundNet = DGND\r\n"
    "\tVDD_AUX::Unselected -> PowerNets Color = BLUE\r\n"
    "\t+ Voltage = 1.2\r\n"
    ".EndNetList\r\n"
)
# Expected counts for SAMPLE_SPD:
# active_nets: SIG_ON, +3_3V, DGND, AGND, VDD_1V8 -> 5
# component_types: CAP_0402, RES_0402, UNUSED_MODEL, DUT_BGA -> 4
# refdes_count: C1, C2, R1, U1 -> 4


def test_spd_counter_handles_chunk_boundaries_and_non_utf8(tmp_path: Path) -> None:
    raw = SAMPLE_SPD.encode("utf-8") + b"* vendor \xff\xfe comment\n"
    counter = SpdCounter()
    # Feed 7 bytes at a time to exercise arbitrary line splits across chunks
    for offset in range(0, len(raw), 7):
        counter.feed(raw[offset : offset + 7])
    info = counter.finish()

    assert info.active_nets == 5
    assert info.component_types == 4
    assert info.refdes_count == 4

    spd_path = tmp_path / "board.spd"
    spd_path.write_bytes(raw)
    assert parse_spd_file(spd_path) == info


def test_spd_scanned_from_folder_zip_tar_and_7z_and_exported_to_excel(tmp_path: Path) -> None:
    root = tmp_path / "sim_root"
    root.mkdir()
    spd_bytes = SAMPLE_SPD.encode("utf-8")

    # 1. Direct filesystem .spd (uppercase extension too)
    (root / "direct.SPD").write_bytes(spd_bytes)
    (root / "notes.txt").write_text("plain", encoding="utf-8")

    # 2. .spd inside nested zip -> tar.gz -> 7z
    inner_zip_buf = io.BytesIO()
    with zipfile.ZipFile(inner_zip_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("pkg/in_zip.spd", spd_bytes)
    inner_zip_bytes = inner_zip_buf.getvalue()

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
        ti_spd = tarfile.TarInfo("tar_sub/in_tar.spd")
        ti_spd.size = len(spd_bytes)
        tf.addfile(ti_spd, io.BytesIO(spd_bytes))

        ti_zip = tarfile.TarInfo("nested/inner.zip")
        ti_zip.size = len(inner_zip_bytes)
        tf.addfile(ti_zip, io.BytesIO(inner_zip_bytes))
    tar_bytes = tar_buf.getvalue()

    sevenz_path = root / "bundle.7z"
    with py7zr.SevenZipFile(sevenz_path, "w") as sz:
        sz.writestr(spd_bytes, "boards/in_7z.spd")
        sz.writestr(tar_bytes, "archives/mid.tar.gz")
        sz.writestr(b"hello", "readme.txt")

    result = ScanEngine(ScanOptions(max_workers=4)).scan([root])
    assert not result.warnings
    assert result.stats.spd_files == 4

    by_name = {e.name: e for e in result.entries}
    for spd_name in ("direct.SPD", "in_7z.spd", "in_tar.spd", "in_zip.spd"):
        entry = by_name[spd_name]
        assert entry.spd_active_nets == 5, spd_name
        assert entry.spd_component_types == 4, spd_name
        assert entry.spd_refdes_count == 4, spd_name

    assert by_name["notes.txt"].spd_active_nets is None
    assert by_name["notes.txt"].spd_component_types is None
    assert by_name["notes.txt"].spd_refdes_count is None

    # Verify Excel output
    xlsx_path = tmp_path / "out.xlsx"
    export_to_excel(result, xlsx_path)
    wb = load_workbook(xlsx_path)
    ws = wb["파일 목록"]
    headers = [ws.cell(1, c).value for c in range(1, ws.max_column + 1)]
    assert headers[-3:] == ["활성 NET 수", "Component Type 수", "RefDes 수"]

    row_by_name = {ws.cell(r, 3).value: r for r in range(2, ws.max_row + 1)}
    for spd_name in ("direct.SPD", "in_7z.spd", "in_tar.spd", "in_zip.spd"):
        r = row_by_name[spd_name]
        assert (ws.cell(r, 8).value, ws.cell(r, 9).value, ws.cell(r, 10).value) == (5, 4, 4)

    notes_row = row_by_name["notes.txt"]
    assert (ws.cell(notes_row, 8).value, ws.cell(notes_row, 9).value, ws.cell(notes_row, 10).value) == (
        None,
        None,
        None,
    )

    summary = {
        row[0]: row[1] for row in wb["요약"].iter_rows(values_only=True) if row[0] is not None
    }
    assert summary["SPD 분석 파일 수"] == "4 개"
    wb.close()


def test_spd_direct_file_empty_7z_member_and_gui_columns(tmp_path: Path) -> None:
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from deeplister.ui import FileEntryTableModel

    direct = tmp_path / "single.spd"
    direct.write_text(SAMPLE_SPD, encoding="utf-8")

    empty_7z = tmp_path / "empty_spd.7z"
    with py7zr.SevenZipFile(empty_7z, "w") as sz:
        sz.writestr(b"", "empty.spd")

    result = ScanEngine(ScanOptions(max_workers=2)).scan([direct, empty_7z])
    assert not result.warnings
    by_name = {e.name: e for e in result.entries}
    assert (
        by_name["single.spd"].spd_active_nets,
        by_name["single.spd"].spd_component_types,
        by_name["single.spd"].spd_refdes_count,
    ) == (5, 4, 4)
    assert (
        by_name["empty.spd"].spd_active_nets,
        by_name["empty.spd"].spd_component_types,
        by_name["empty.spd"].spd_refdes_count,
    ) == (0, 0, 0)

    _ = QApplication.instance() or QApplication([])
    model = FileEntryTableModel()
    model.set_entries(result.entries)
    row = next(r for r in range(model.rowCount()) if model.entry_at(r).name == "single.spd")
    assert [model.data(model.index(row, c)) for c in (7, 8, 9)] == ["5", "4", "4"]
    arc_row = next(r for r in range(model.rowCount()) if model.entry_at(r).name == "empty_spd.7z")
    assert [model.data(model.index(arc_row, c)) for c in (7, 8, 9)] == ["", "", ""]
