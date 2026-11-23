"""Tests for Excel (.xlsx) export functionality."""

from __future__ import annotations

import zipfile
from pathlib import Path

from openpyxl import load_workbook

from deeplister.exporter import export_to_excel
from deeplister.models import ScanOptions
from deeplister.scanner import ScanEngine


def test_export_to_excel_sheets_and_values(tmp_path: Path) -> None:
    data_dir = tmp_path / "sample_data"
    data_dir.mkdir()
    (data_dir / "alpha.txt").write_bytes(b"1234567890")
    (data_dir / "bad.zip").write_bytes(b"corrupt")

    good_zip = data_dir / "good.zip"
    with zipfile.ZipFile(good_zip, "w") as zf:
        zf.writestr("sub/inside.csv", b"a,b,c\n1,2,3\n")

    result = ScanEngine(ScanOptions(max_workers=2)).scan([data_dir])
    xlsx_path = tmp_path / "output" / "inventory.xlsx"
    saved = export_to_excel(result, xlsx_path)

    assert saved == xlsx_path
    assert xlsx_path.is_file()

    wb = load_workbook(xlsx_path)
    assert "파일 목록" in wb.sheetnames
    assert "요약" in wb.sheetnames
    assert "경고 및 오류" in wb.sheetnames

    ws = wb["파일 목록"]
    assert ws.max_column == 7
    headers = [ws.cell(1, c).value for c in range(1, 8)]
    assert headers == [
        "No.",
        "디렉토리 이름",
        "파일 이름",
        "생성 날짜",
        "수정된 날짜",
        "용량 (Bytes)",
        "구분",
    ]
    assert ws.max_row == len(result.entries) + 1
    assert ws.freeze_panes == "A2"
    assert ws.auto_filter.ref == f"A1:G{len(result.entries) + 1}"

    row_by_name = {ws.cell(r, 3).value: r for r in range(2, ws.max_row + 1)}
    alpha_row = row_by_name["alpha.txt"]
    assert ws.cell(alpha_row, 6).value == 10  # size stays a real number, in bytes
    assert ws.cell(alpha_row, 7).value == "일반 파일"

    names_in_excel = {ws.cell(r, 3).value for r in range(2, ws.max_row + 1)}
    assert {"alpha.txt", "good.zip", "inside.csv", "bad.zip"}.issubset(names_in_excel)

    ws_warn = wb["경고 및 오류"]
    assert ws_warn.max_row >= 2

    # Summary explains how many entries lack a created date and where they came from
    summary = {
        row[0]: row[1] for row in wb["요약"].iter_rows(values_only=True) if row[0] is not None
    }
    stats = result.stats
    assert summary["생성 날짜 기록 항목 수"] == f"{stats.created_present:,} 개"
    assert summary["생성 날짜 없는 항목 수"] == f"{stats.created_missing:,} 개"
    assert summary["생성 시각 미저장 압축파일 수"] == "1 개"
    assert summary["ZIP 내부"] == "0 / 1 개"
    assert stats.created_missing >= 1
    assert any(str(key).startswith("※ 생성 날짜가 빈 항목") for key in summary)
    wb.close()


def test_export_sanitizes_control_chars_and_blocks_formula_injection(tmp_path: Path) -> None:
    from deeplister.models import EntryKind, FileEntry, ScanResult, ScanStats, ScanWarning

    entries = [
        FileEntry(
            directory="C:\\Unsafe\x01Dir",
            name="=CMD|' /C calc'!A0.txt",
            created_at=None,
            modified_at=None,
            size=42,
            kind=EntryKind.ARCHIVE_MEMBER,
            archive_depth=1,
        ),
        FileEntry(
            directory="C:\\MacFolder",
            name="Icon\r",
            created_at=None,
            modified_at=None,
            size=0,
            kind=EntryKind.ARCHIVE_MEMBER,
            archive_depth=1,
        ),
    ]
    warnings = [ScanWarning(path="=bad\x00path", reason="ctrl\x0bchar")]
    stats = ScanStats(total_entries=2, archive_members=2, total_size=42, input_paths=["=root"])
    result = ScanResult(entries=entries, warnings=warnings, stats=stats)

    out = tmp_path / "safe.xlsx"
    export_to_excel(result, out)

    wb = load_workbook(out)
    ws = wb["파일 목록"]
    formula_cell = ws.cell(2, 3)
    assert formula_cell.value == "=CMD|' /C calc'!A0.txt"
    assert formula_cell.data_type == "s"
    assert formula_cell.quotePrefix is True

    dir_cell = ws.cell(2, 2)
    assert "\x01" not in dir_cell.value

    icon_cell = ws.cell(3, 3)
    assert icon_cell.value == "Icon"
    wb.close()
