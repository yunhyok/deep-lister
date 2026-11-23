"""Entry point for DeepLister."""

from __future__ import annotations

import argparse
import sys

from deeplister import APP_NAME, __version__
from deeplister.ui import run_gui


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="폴더, 파일, 중첩 압축파일 재귀 탐색 및 Excel 내보내기 도구",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="초기 스캔 대상에 추가할 폴더/파일/압축파일 경로",
    )
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="GUI 초기화를 검증하고 즉시 종료합니다.",
    )
    parser.add_argument(
        "--log-dir",
        metavar="DIR",
        help="상세 로그 파일을 저장할 폴더 (기본: %%LOCALAPPDATA%%\\DeepLister\\logs)",
    )
    parser.add_argument(
        "--temp-dir",
        metavar="DIR",
        help="중첩 압축파일을 풀 임시 폴더 (이번 실행에만 적용, 기본: 저장된 설정 또는 시스템 임시 폴더)",
    )
    parser.add_argument(
        "--temp-limit-gb",
        metavar="GB",
        type=int,
        help="임시 폴더에서 동시에 사용할 최대 용량(GB, 0=자동). 이번 실행에만 적용",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{APP_NAME} {__version__}",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return run_gui(
        smoke_test=args.smoke_test,
        initial_paths=args.paths or None,
        log_dir=args.log_dir,
        temp_dir=args.temp_dir,
        temp_limit_gb=args.temp_limit_gb,
    )


if __name__ == "__main__":
    raise SystemExit(main())
