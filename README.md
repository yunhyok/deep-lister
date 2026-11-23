# DeepLister

폴더, 파일 및 **중첩 압축파일(`.zip`, `.7z`, `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz`)** 내부까지 재귀적으로 탐색하여 **디렉토리 이름, 파일 이름, 생성 날짜, 수정된 날짜, 용량**을 정리하고 **Excel(`.xlsx`)** 파일로 내보내는 Windows 데스크톱(GUI) 애플리케이션입니다.

## 주요 기능

- **재귀 탐색 (Recursive Scan)**
  - 폴더 및 모든 하위 폴더 탐색 (`os.scandir` 기반 고속 탐색)
  - 압축파일 내부 탐색 및 **압축파일 안의 압축파일(중첩 압축)**까지 설정된 깊이(기본 10단계)까지 재귀적으로 자동 탐색
  - 지원 압축 형식: `.zip`, `.7z`, `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tbz2`, `.tar.xz`, `.txz`
  - 구형 Windows ZIP의 CP949/EUC-KR 한글 파일명 자동 복원 및 NTFS Extra Field(`0x000A`) / 7z 원본 생성·수정 시각 추출
- **멀티스레딩 고속 처리**
  - 데드락 없는 작업 큐 + 멀티스레드 워커 풀(1~32 스레드 조절 가능)로 대량 폴더와 다수의 압축파일을 병렬 스캔
  - 스캔 중에도 UI 프리징 없이 실시간 통계 확인 및 즉시 중지(Cancel) 가능
- **임시 폴더 지정**
  - 압축파일 안의 압축파일은 임시 폴더에 풀어서 내부를 읽습니다. `임시 폴더` 줄의 `변경...`으로 여유 공간이 큰 드라이브의 폴더를 지정할 수 있습니다 (현재 여유 공간 표시, 다음 실행에도 유지, `기본값`으로 복원)
  - 임시 폴더 안에 `deeplister_...` 작업 폴더를 만들어 쓰고 스캔이 끝나면 지웁니다
  - 공간이 모자라면 추출 전에 확인하여 필요·여유 용량을 `경고 및 오류`에 표시합니다
  - 실행 인자 `--temp-dir <폴더>`로 이번 실행에만 적용할 수도 있습니다
- **드래그 앤 드롭 & 다크 테마 GUI**
  - 폴더·파일·압축파일을 창 어디든 드래그 앤 드롭으로 다중 추가
  - Spectrum 스타일 다크 테마 + Windows 네이티브 다크 타이틀바
  - 가상 테이블 모델(`QTableView` + `QAbstractTableModel`)로 대량 항목도 부드럽게 정렬·실시간 검색
- **Excel(`.xlsx`) 내보내기**
  - `파일 목록` 시트: 틀 고정, 자동 필터, 열 너비 자동 조정, 용량은 Bytes 숫자 서식(`#,##0`) 한 열로 기록
  - `요약` 시트: 총 항목 수, 압축 깊이, 총 용량, 소요 시간, 입력 경로 목록, **생성 날짜 기록 현황**(원본별 기록됨 / 전체)
  - `경고 및 오류` 시트: 암호화·손상·접근 제한 항목 자동 기록
- **상세 로그 파일**
  - 실행할 때마다 `%LOCALAPPDATA%\DeepLister\logs`에 로그를 자동 기록 (최근 30개 보관)
  - 압축파일별 생성/수정 시각 기록 현황, 경고·오류의 상세 원인(traceback), 임시 폴더 여유 공간 기록
  - `로그 열기` / `로그 폴더` 버튼으로 바로 확인, `로그(.log)도 함께 저장`을 켜면 Excel 옆에 같은 이름의 `.log` 저장

## 생성 날짜가 비어 있는 경우

생성 날짜는 **원본에 저장되어 있을 때만** 표시합니다. 값이 없는 항목을 수정 날짜 등으로 대신 채우지 않습니다.

| 원본 | 생성 시각이 기록되는 조건 |
| --- | --- |
| 일반 파일·폴더 | Windows 파일 시스템이 항상 제공 |
| `.7z` 내부 | 압축할 때 생성 시각 저장을 켠 경우에만 (`7z a -mtc=on ...`, 7-Zip 22.00 이상은 압축 창의 `옵션`에서 선택). **7-Zip 기본 설정은 수정 시각만 저장** |
| `.zip` 내부 | 압축 프로그램이 NTFS(`0x000A`) 또는 UT(`0x5455`) 확장 필드에 생성 시각을 넣은 경우 |
| `.tar` 계열 내부 | 형식 자체에 생성 시각이 없음 (pax 확장 헤더 `LIBARCHIVE.creationtime`이 있을 때만) |

어떤 압축파일에 생성 시각이 없는지는 Excel `요약` 시트의 **생성 날짜 기록 현황**과 로그 파일의 압축파일별 기록(`생성 시각 0/1234` 등)에서 확인할 수 있습니다.

## 설치 (Windows x64)

[Releases](https://github.com/yunhyok/deep-lister/releases) 페이지에서 최신 `DeepListerSetup-x.y.z.exe` Windows 인스톨러를 내려받아 설치하세요.

## 개발 및 로컬 빌드

```powershell
# 1. 가상환경 생성 및 의존성 설치
uv venv --python 3.12 .venv
uv pip install --python .venv\Scripts\python.exe -r requirements.txt pytest pyinstaller

# 2. 실행
.\.venv\Scripts\python.exe main.py

# 3. 테스트
$env:QT_QPA_PLATFORM = "offscreen"
.\.venv\Scripts\python.exe -m pytest -v

# 4. Windows 실행파일 + Inno Setup 인스톨러 빌드
.\packaging\build.ps1
```

## 릴리즈

1. `deeplister/__init__.py`와 `pyproject.toml`의 버전을 올리고 `CHANGELOG.md`에 `## [x.y.z]` 항목을 추가합니다.
2. `main`에 병합한 뒤 `vX.Y.Z` 태그를 push하거나, GitHub Actions의 **Build Windows Installer** 워크플로를 `publish_release` 옵션을 켜서 수동 실행합니다.
3. 워크플로가 테스트 → 인스톨러 빌드 → GitHub Release 게시(인스톨러 첨부, SHA-256 기재)까지 수행합니다.

## 라이선스

MIT License — 자세한 내용은 [LICENSE](LICENSE)를 참고하세요.
