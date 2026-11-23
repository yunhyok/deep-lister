"""Streaming, formula-safe, atomic Excel (.xlsx) exporter for DeepLister."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime
from pathlib import Path

from openpyxl import Workbook
from openpyxl.cell import WriteOnlyCell
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from .models import SOURCE_LABELS, FileEntry, ScanResult, format_datetime, format_size

# Excel allows 1,048,576 rows per sheet (1 header + 1,048,575 data rows)
MAX_DATA_ROWS_PER_SHEET = 1_048_575

# Characters that Excel may interpret as formula prefixes
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

HEADER_FILL = PatternFill(start_color="2B4C7E", end_color="2B4C7E", fill_type="solid")
SUBHEADER_FILL = PatternFill(start_color="386CB0", end_color="386CB0", fill_type="solid")
ZEBRA_FILL = PatternFill(start_color="F5F7FA", end_color="F5F7FA", fill_type="solid")
SUMMARY_KEY_FILL = PatternFill(start_color="EBF0F7", end_color="EBF0F7", fill_type="solid")
WARN_HEADER_FILL = PatternFill(start_color="8C3D2B", end_color="8C3D2B", fill_type="solid")

HEADER_FONT = Font(name="Segoe UI", size=10, bold=True, color="FFFFFF")
BODY_FONT = Font(name="Segoe UI", size=10, color="1E2229")
BOLD_FONT = Font(name="Segoe UI", size=10, bold=True, color="1E2229")
TITLE_FONT = Font(name="Segoe UI", size=13, bold=True, color="2B4C7E")

THIN_BORDER = Border(
    left=Side(style="thin", color="D5DCE6"),
    right=Side(style="thin", color="D5DCE6"),
    top=Side(style="thin", color="D5DCE6"),
    bottom=Side(style="thin", color="D5DCE6"),
)

ALIGN_LEFT = Alignment(horizontal="left", vertical="center")
ALIGN_CENTER = Alignment(horizontal="center", vertical="center")
ALIGN_RIGHT = Alignment(horizontal="right", vertical="center")
ALIGN_MAP = {"left": ALIGN_LEFT, "center": ALIGN_CENTER, "right": ALIGN_RIGHT}

COLUMNS = [
    ("No.", 7, 12, "right"),
    ("디렉토리 이름", 24, 78, "left"),
    ("파일 이름", 18, 52, "left"),
    ("생성 날짜", 21, 23, "center"),
    ("수정된 날짜", 21, 23, "center"),
    ("용량 (Bytes)", 15, 20, "right"),
    ("구분", 16, 26, "center"),
]


# Shown under the created-date table whenever some entries have no creation timestamp
CREATED_MISSING_NOTE = (
    "※ 생성 날짜가 빈 항목은 원본에 생성 시각이 저장되어 있지 않은 경우입니다.",
    "   7z는 압축할 때 생성 시각 저장 옵션(-mtc=on)을 켜야 생성 시각이 기록되며,",
    "   기본 설정으로 만든 7z에는 수정 시각만 들어 있습니다.",
)


def sanitize_excel_text(value: str) -> str:
    """Strip XML 1.0 illegal control characters and stray CR/LF so Excel rows stay valid."""
    if not value:
        return ""
    cleaned = ILLEGAL_CHARACTERS_RE.sub("", value)
    return cleaned.replace("\r", "").replace("\n", " ")


def _display_width(text: str) -> int:
    """Estimate Excel column character width accounting for CJK wide characters."""
    width = 0
    for ch in text:
        width += 2 if ord(ch) > 127 else 1
    return width


def _make_cell(
    ws,
    value: object,
    *,
    font: Font = BODY_FONT,
    alignment: Alignment = ALIGN_LEFT,
    fill: PatternFill | None = None,
    number_format: str | None = None,
    as_text: bool = False,
) -> WriteOnlyCell:
    """Create a styled WriteOnlyCell safely guarded against illegal chars and formula injection."""
    if isinstance(value, str):
        clean = sanitize_excel_text(value)
        cell = WriteOnlyCell(ws, value=clean)
        cell.data_type = "s"
        if clean.startswith(_FORMULA_PREFIXES):
            cell.quotePrefix = True
    else:
        cell = WriteOnlyCell(ws, value=value)
        if as_text:
            cell.data_type = "s"

    cell.font = font
    cell.alignment = alignment
    cell.border = THIN_BORDER
    if fill is not None:
        cell.fill = fill
    if number_format is not None:
        cell.number_format = number_format
    return cell


def _compute_column_widths(entries: list[FileEntry]) -> list[int]:
    """Pre-compute bounded column widths from headers and up to 2,000 sampled rows."""
    observed = [_display_width(title) + 4 for title, _, _, _ in COLUMNS]
    for idx, entry in enumerate(entries[:2000], start=1):
        row_samples = (
            str(idx),
            sanitize_excel_text(entry.directory),
            sanitize_excel_text(entry.name),
            format_datetime(entry.created_at),
            format_datetime(entry.modified_at),
            f"{entry.size:,}",
            entry.kind_label,
        )
        for col_idx, text in enumerate(row_samples):
            w = _display_width(text) + 3
            if w > observed[col_idx]:
                observed[col_idx] = w

    return [
        max(min_w, min(max_w, observed[col_idx]))
        for col_idx, (_, min_w, max_w, _) in enumerate(COLUMNS)
    ]


def _write_entries_sheets(wb: Workbook, entries: list[FileEntry]) -> None:
    """Stream entries into one or more '파일 목록' sheets respecting Excel's row limit."""
    widths = _compute_column_widths(entries)
    total = len(entries)
    sheet_count = max(1, (total + MAX_DATA_ROWS_PER_SHEET - 1) // MAX_DATA_ROWS_PER_SHEET)

    for sheet_idx in range(sheet_count):
        title = "파일 목록" if sheet_idx == 0 else f"파일 목록 ({sheet_idx + 1})"
        ws = wb.create_sheet(title=title)
        ws.views.sheetView[0].showGridLines = True

        # Column widths must be set before appending rows in write_only mode
        for col_idx, w in enumerate(widths, start=1):
            ws.column_dimensions[get_column_letter(col_idx)].width = w

        start = sheet_idx * MAX_DATA_ROWS_PER_SHEET
        end = min(total, start + MAX_DATA_ROWS_PER_SHEET)
        rows_in_sheet = end - start

        ws.freeze_panes = "A2"
        ws.auto_filter.ref = f"A1:{get_column_letter(len(COLUMNS))}{max(1, rows_in_sheet + 1)}"

        header_cells = [
            _make_cell(ws, col_title, font=HEADER_FONT, alignment=ALIGN_CENTER, fill=HEADER_FILL)
            for col_title, _, _, _ in COLUMNS
        ]
        ws.append(header_cells)

        for local_i, entry in enumerate(entries[start:end], start=1):
            global_no = start + local_i
            fill = ZEBRA_FILL if (local_i % 2 == 0) else None
            row_cells = [
                _make_cell(
                    ws,
                    global_no,
                    alignment=ALIGN_RIGHT,
                    fill=fill,
                    number_format="#,##0",
                ),
                _make_cell(ws, entry.directory, alignment=ALIGN_LEFT, fill=fill),
                _make_cell(ws, entry.name, alignment=ALIGN_LEFT, fill=fill),
                _make_cell(
                    ws,
                    format_datetime(entry.created_at),
                    alignment=ALIGN_CENTER,
                    fill=fill,
                ),
                _make_cell(
                    ws,
                    format_datetime(entry.modified_at),
                    alignment=ALIGN_CENTER,
                    fill=fill,
                ),
                _make_cell(
                    ws,
                    entry.size,
                    alignment=ALIGN_RIGHT,
                    fill=fill,
                    number_format="#,##0",
                ),
                _make_cell(ws, entry.kind_label, alignment=ALIGN_CENTER, fill=fill),
            ]
            ws.append(row_cells)


def _write_summary_sheet(wb: Workbook, result: ScanResult) -> None:
    ws_sum = wb.create_sheet(title="요약")
    ws_sum.column_dimensions["A"].width = 24
    ws_sum.column_dimensions["B"].width = 74

    title_cell = WriteOnlyCell(ws_sum, value="DeepLister 스캔 요약")
    title_cell.font = TITLE_FONT
    ws_sum.append([title_cell])
    ws_sum.append([])

    stats = result.stats
    summary_rows: list[tuple[str, object]] = [
        ("생성 일시", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("총 항목 수", f"{stats.total_entries:,} 개"),
        ("일반 파일 수", f"{stats.regular_files:,} 개"),
        ("목록 내 압축 파일 수", f"{stats.archive_files:,} 개"),
        ("탐색한 압축 파일 수", f"{stats.archives_scanned:,} 개"),
        ("압축 내부 파일 수", f"{stats.archive_members:,} 개"),
        ("빈 폴더 수", f"{stats.directories:,} 개"),
        ("생성 날짜 기록 항목 수", f"{stats.created_present:,} 개"),
        ("생성 날짜 없는 항목 수", f"{stats.created_missing:,} 개"),
        ("생성 시각 미저장 압축파일 수", f"{stats.archives_without_created:,} 개"),
        ("총 용량 (Bytes)", stats.total_size),
        ("총 용량 (표시)", format_size(stats.total_size)),
        ("최대 압축 중첩 깊이", f"{stats.max_depth_seen} 단계"),
        ("사용 워커 스레드 수", f"{stats.worker_count} 개"),
        (
            "임시 공간 사용 한도",
            format_size(stats.temp_limit_bytes)
            if stats.temp_limit_bytes is not None
            else "제한 없음",
        ),
        (
            "임시 공간 최대 사용량",
            f"{format_size(stats.temp_peak_bytes)} (공간 대기 {stats.temp_wait_count:,} 회)",
        ),
        ("스캔 소요 시간", f"{stats.elapsed_seconds:.2f} 초"),
        ("경고 / 오류 수", f"{len(result.warnings):,} 건"),
        ("완료 상태", "사용자 중지됨" if stats.cancelled else "정상 완료"),
    ]
    if stats.log_path:
        summary_rows.append(("로그 파일", stats.log_path))

    for label, val in summary_rows:
        c_key = _make_cell(ws_sum, label, font=BOLD_FONT, alignment=ALIGN_LEFT, fill=SUMMARY_KEY_FILL)
        if isinstance(val, int):
            c_val = _make_cell(ws_sum, val, alignment=ALIGN_RIGHT, number_format="#,##0")
        else:
            c_val = _make_cell(ws_sum, str(val), alignment=ALIGN_LEFT)
        ws_sum.append([c_key, c_val])

    if stats.created_by_source:
        ws_sum.append([])
        cov_cell = WriteOnlyCell(ws_sum, value="생성 날짜 기록 현황")
        cov_cell.font = BOLD_FONT
        ws_sum.append([cov_cell])
        ws_sum.append(
            [
                _make_cell(
                    ws_sum, "원본", font=HEADER_FONT, alignment=ALIGN_CENTER, fill=SUBHEADER_FILL
                ),
                _make_cell(
                    ws_sum,
                    "생성 날짜 기록됨 / 전체 항목",
                    font=HEADER_FONT,
                    alignment=ALIGN_CENTER,
                    fill=SUBHEADER_FILL,
                ),
            ]
        )
        for source, (present, total) in stats.created_by_source.items():
            ws_sum.append(
                [
                    _make_cell(ws_sum, SOURCE_LABELS.get(source, source), alignment=ALIGN_LEFT),
                    _make_cell(ws_sum, f"{present:,} / {total:,} 개", alignment=ALIGN_LEFT),
                ]
            )
        if stats.created_missing:
            for line in CREATED_MISSING_NOTE:
                note_cell = WriteOnlyCell(ws_sum, value=line)
                note_cell.font = BODY_FONT
                ws_sum.append([note_cell])

    ws_sum.append([])
    sec_cell = WriteOnlyCell(ws_sum, value="스캔 입력 대상")
    sec_cell.font = BOLD_FONT
    ws_sum.append([sec_cell])
    ws_sum.append(
        [
            _make_cell(ws_sum, "No.", font=HEADER_FONT, alignment=ALIGN_CENTER, fill=SUBHEADER_FILL),
            _make_cell(ws_sum, "경로", font=HEADER_FONT, alignment=ALIGN_CENTER, fill=SUBHEADER_FILL),
        ]
    )
    for i, path_str in enumerate(stats.input_paths, start=1):
        ws_sum.append(
            [
                _make_cell(ws_sum, i, alignment=ALIGN_CENTER),
                _make_cell(ws_sum, path_str, alignment=ALIGN_LEFT),
            ]
        )


def _write_warnings_sheet(wb: Workbook, result: ScanResult) -> None:
    if not result.warnings:
        return
    ws_warn = wb.create_sheet(title="경고 및 오류")
    ws_warn.column_dimensions["A"].width = 8
    ws_warn.column_dimensions["B"].width = 66
    ws_warn.column_dimensions["C"].width = 54
    ws_warn.freeze_panes = "A2"

    ws_warn.append(
        [
            _make_cell(ws_warn, "No.", font=HEADER_FONT, alignment=ALIGN_CENTER, fill=WARN_HEADER_FILL),
            _make_cell(ws_warn, "경로", font=HEADER_FONT, alignment=ALIGN_CENTER, fill=WARN_HEADER_FILL),
            _make_cell(ws_warn, "사유", font=HEADER_FONT, alignment=ALIGN_CENTER, fill=WARN_HEADER_FILL),
        ]
    )
    for i, w in enumerate(result.warnings, start=1):
        fill = ZEBRA_FILL if (i % 2 == 0) else None
        ws_warn.append(
            [
                _make_cell(ws_warn, i, alignment=ALIGN_CENTER, fill=fill),
                _make_cell(ws_warn, w.path, alignment=ALIGN_LEFT, fill=fill),
                _make_cell(ws_warn, w.reason, alignment=ALIGN_LEFT, fill=fill),
            ]
        )


def export_to_excel(result: ScanResult, output_path: str | Path) -> Path:
    """Write scan entries, summary, and optional warnings atomically to an .xlsx file."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    wb = Workbook(write_only=True)
    _write_entries_sheets(wb, result.entries)
    _write_summary_sheet(wb, result)
    _write_warnings_sheet(wb, result)

    # Atomic write: save to sibling temp file, then replace target path
    fd, tmp_name = tempfile.mkstemp(prefix=".deeplister_", suffix=".xlsx.tmp", dir=str(out.parent))
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        wb.save(tmp_path)
        os.replace(tmp_path, out)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    return out
