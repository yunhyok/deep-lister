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
- **드래그 앤 드롭 & 다크 테마 GUI**
  - 폴더·파일·압축파일을 창 어디든 드래그 앤 드롭으로 다중 추가
  - Spectrum 스타일 다크 테마 + Windows 네이티브 다크 타이틀바
  - 가상 테이블 모델(`QTableView` + `QAbstractTableModel`)로 대량 항목도 부드럽게 정렬·실시간 검색
- **Excel(`.xlsx`) 내보내기**
  - `파일 목록` 시트: 틀 고정, 자동 필터, 열 너비 자동 조정, Bytes 숫자 서식(`#,##0`) + 가독성 단위(`KB/MB/GB`) 병기
  - `요약` 시트: 총 항목 수, 압축 깊이, 총 용량, 소요 시간, 입력 경로 목록
  - `경고 및 오류` 시트: 암호화·손상·접근 제한 항목 자동 기록

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

## 라이선스

MIT License — 자세한 내용은 [LICENSE](LICENSE)를 참고하세요.
