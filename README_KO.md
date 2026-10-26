# Argus

Argus는 웹사이트의 JavaScript를 수집하고, 정적 source→sink taint 분석과 규칙 분류를 통해 혼합추적자를 탐지하는 연구 도구입니다.

이 배포본은 통합 RC3에 기반한 **v4 연구용 소스 패키지**입니다. Docker 이미지가 아니라 Linux 또는 WSL2에서 빌드하여 사용합니다. 크롤러·분석기·분류기, 10만 개 대상 목록, 연구 집계 스크립트를 포함합니다.

[English README](README.md)

## Pipeline Overview

```text
[1] 크롤링  →  [2] Taint 분석  →  [3] 규칙 분류
crawler.cjs     analyzer/run.py     classifier/run.py
               mixed-hermes         Argus 규칙
```

일반 실행은 세 단계입니다. 과거 논문 표의 집계는 보존된 결과 데이터를 사용하는 별도 작업입니다.

## 의존성과 설치

| 구성 요소 | 요구 환경 |
|---|---|
| 실행 환경 | Linux 또는 WSL2 |
| 크롤러 | Node.js 20, npm, Puppeteer/Chromium 및 브라우저의 Linux 시스템 라이브러리 |
| 네이티브 분석기 | C++17 컴파일러, CMake, Ninja, ICU 개발 라이브러리 |
| 파이프라인·분류기 | Python 3.10+; 분석에는 루트 npm 의존성도 필요 |
| 과거 집계 스크립트 | Python 표준 라이브러리 및 해당 시점의 입력 자료 |

Node.js 20을 설치한 후 저장소 루트에서 실행합니다.

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build libicu-dev python3
npm ci --ignore-scripts
bash scripts/build.sh
npm ci --prefix crawler
```

빌드는 기본 2개 작업으로 실행하며 `build/bin/mixed-hermes`를 생성합니다. 마지막 명령은 크롤러 의존성과 Chromium을 설치합니다. Chromium 실행에 필요한 Linux 시스템 라이브러리도 준비되어 있어야 합니다. 기존 수집본만 분석하면 크롤러 설치를 생략할 수 있습니다.

## 1. Crawling

**실행 파일:** `crawler/crawler.cjs`

### What it does

- 도메인/URL 목록을 읽고 Chromium으로 방문합니다. 포함된 `crawler/20261005-top-100k-urls.txt`는 한 줄에 하나씩 100,000개 고유 대상을 담고 있습니다.
- JavaScript, 응답 근거, 요청 관측 정보와 해시를 저장합니다.
- 기본 `preserve` 정책은 JavaScript를 변경하지 않습니다. 선택 사항인 `--transform babel`은 변환·건너뛰기·실패를 기록합니다.
- `SUCCESS`, `PARTIAL`, `NO_SCRIPTS`, `FAILED`, `NOT_STARTED`를 구분합니다.

### Usage

브라우저 실행 없이 목록만 검사합니다.

```bash
node crawler/crawler.cjs crawler/20261005-top-100k-urls.txt --check-input
```

새 폴더에 수집합니다.

```bash
node crawler/crawler.cjs crawler/20261005-top-100k-urls.txt \
  --out runs/crawl-01 --transform preserve --concurrency 2
```

### Output

```text
runs/crawl-01/
├── run.json
├── progress.json
├── outcomes.json
└── visits/
    └── <방문별 폴더>/
        ├── visit.json
        ├── network_logs.json
        ├── wholepage.js
        └── ... 개별 스크립트와 응답 근거
```

`wholepage.js`는 수집·결합이 성공한 경우 생성됩니다. `NO_SCRIPTS`는 사용 가능한 스크립트를 저장하지 못했다는 뜻이며 사이트에 JavaScript가 없다는 증거는 아닙니다. 결합 순서가 프레임·모듈의 실행 순서를 확정하지는 않습니다.

## 2. Taint Analysis

**진입점:** `analyzer/run.py`  
**네이티브 엔진:** `build/bin/mixed-hermes`

### What it does

- 입력·해시를 확인하고 자원 제한 내에서 AST 사전검사를 수행합니다.
- 허용된 입력을 컴파일하고 IR에서 source→sink 흐름을 분석합니다.
- 출력 완결성과 실행 근거를 확인하여 완료 보고서 목록을 만듭니다.

이 단계는 저장된 웹사이트 JavaScript를 실행하지 않으며 최종 규칙 분류도 별도로 진행합니다.

### Usage

```bash
python3 analyzer/run.py --crawl-dir runs/crawl-01 \
  --out runs/analysis-01 --workers 2
```

이미 수집한 파일 하나를 분석할 때는 다음과 같이 실행합니다.

```bash
python3 analyzer/run.py --input /path/to/example.com/wholepage.js \
  --domain example.com --network-log /path/to/example.com/visit.json \
  --out runs/analysis-saved-01
```

여러 파일은 `--manifest inputs.json`으로 지정합니다. 형식은 영문 README에 있습니다. 네트워크 근거는 `visit.json` 또는 URL 문자열 배열 JSON을 사용합니다. 요청 객체 배열인 크롤러의 `network_logs.json`을 이 인자에 직접 넣으면 안 됩니다. 네트워크 근거가 없으면 관련 규칙에 영향을 주며, 중복 도메인 키는 거부합니다.

### Output

```text
runs/analysis-01/
├── results.json
├── progress.json
├── final_summary.json
├── classification_manifest.json
└── visits/
    └── ... 도메인별 분석 산출물
```

`classification_manifest.json`에는 검증된 완료 보고서와 네트워크 정보만 들어갑니다. 실패·보류는 별도 기록합니다. 종료 코드 2는 다른 입력 처리 후에도 미완료 입력이 있다는 뜻이므로 요약을 확인하고 완료된 부분을 분류합니다.

## 3. Classification

**진입점:** `classifier/run.py`  
**규칙 구현:** `classifier.py`

### What it does

- 완료 보고서를 읽고 제공된 해시를 검증합니다.
- R1/R2/R4/R5의 탐지 그룹과 도메인 단위 R3를 구분하여 기록합니다.
- 네이티브 분석을 반복하지 않고 CSV와 통합 JSON을 생성합니다.

### Usage

```bash
python3 classifier/run.py \
  --manifest runs/analysis-01/classification_manifest.json \
  --out runs/classification-01
```

### Output

```text
runs/classification-01/
├── argus_findings.csv
├── argus_domain_summary.csv
├── argus_final_report.json
└── chunks/
    └── ... 분류기 세부 출력과 실행 기록
```

탐지 CSV는 기존 9개 컬럼을 유지합니다.

```text
Domain, Threat_Type, Trigger_Context, Leaked_Data (Source),
Leak_Method (Sink), Destination, Observed_Trackers, Party_Check, Confidence_Score
```

한 도메인에서 여러 탐지 그룹과 여러 규칙이 나올 수 있으므로 도메인 수·탐지 그룹 수·route 수를 구분합니다. R3 단독 구조 관측은 혼합추적자 분류와 별도로 유지합니다. 분석 결과를 옮길 때는 manifest가 참조하는 경로도 보존하거나 갱신합니다.

## Directory Structure

```text
Argus/
├── crawler/
│   ├── crawler.cjs
│   ├── 20261005-top-100k-urls.txt
│   ├── package.json
│   ├── package-lock.json
│   └── LICENSE
├── analyzer/run.py
├── classifier/run.py
├── classifier.py
├── argus/, argus_pipeline/, argus_semantics/, argus_conditional/
├── lib/, include/, public/, external/, cmake/, tools/
├── scripts/
│   ├── build.sh
│   ├── export_csv_and_tracker_counts.py
│   ├── count_rule_overlap.py
│   ├── compare_archived_easyprivacy.py
│   └── recompute_appendix.py
├── RELEASE.json
├── REPRODUCTION_INPUTS.json
├── LICENSE
└── build/bin/mixed-hermes                 (빌드 후 생성)
```

내부 Python 패키지와 네이티브 소스 폴더는 실행에 필요합니다. 수집 데이터·기존 결과·설치된 의존성·컴파일 산출물·테스트·스모크 실행기는 포함하지 않습니다. 과거 저장소의 Docker 및 그래프 생성 명령은 이 패키지에 적용하지 않습니다.

## Running the Full Pipeline

설치 후 저장소 루트에서 아래 명령을 순서대로 실행합니다. 매번 새 출력 폴더를 사용하고, 오류가 있으면 해당 단계의 결과를 확인한 뒤 진행합니다.

```bash
node crawler/crawler.cjs crawler/20261005-top-100k-urls.txt \
  --out runs/crawl-01 --transform preserve --concurrency 2

python3 analyzer/run.py --crawl-dir runs/crawl-01 \
  --out runs/analysis-01 --workers 2

python3 classifier/run.py \
  --manifest runs/analysis-01/classification_manifest.json \
  --out runs/classification-01
```

다른 터미널에서 해당 단계의 진행 상황을 확인합니다.

```bash
watch -n 10 cat runs/crawl-01/progress.json
```

```bash
watch -n 10 cat runs/analysis-01/progress.json
```

## 선택 기능과 제한

분석기에 `--semantics`를 지정하면 정확한 Date→cookie route의 의미 라벨을, `--conditional`을 지정하면 별도 pbjs 조건부 관측을 추가합니다. 두 결과는 주 규칙 집계와 구분합니다.

최대 worker 4개, 프로세스 주소 공간 8GiB, 사전검사·native 단계별 최대 60초, 파일 256MiB, 항목 1GiB 제한을 유지합니다. 압축 전체 IR의 논리 크기 한도는 1GiB입니다. 시작 시 worker당 8GiB에 여유 2GiB를 더한 가용 RAM과 디스크 여유 22GiB를 확인합니다.

불명확한 모듈·전역 환경, 부족한 호출 근거, 자원 초과는 보류 또는 UNKNOWN으로 남깁니다. native 완료와 의미 확정은 다르며, 미탐지가 무해함을 입증하지 않습니다. `DYNAMIC_URL`과 `{VAR}`는 미복원 목적지를 나타냅니다. 의미 라벨은 해당 Date source→sink route에만 부여하며 주변의 다른 Date 흐름을 합산하지 않습니다.

기존 44,882개 완료 수치는 여러 엔진 버전의 결과를 합친 과거 측정이며, v4를 새로 전수 실행한 결과가 아닙니다. 일반 설명 주석은 제거했지만 라이선스 고지·실행 지시문·런타임 문자열은 보존했습니다.

## 검증

Linux/WSL2 빌드, 크롤러 19개·native 예제 61개·TDZ 예제 11개, Date→cookie 양성·음성 및 모듈 보류 검사를 통과했습니다. Python/JavaScript AST와 주석을 제외한 네이티브 소스 비교도 통과했습니다. 실제 저장 입력 3개(adblockplus.org, ampproject.org, bis.org)는 경로 표기를 정규화한 route 필드와 규칙 분류 결과가 RC3와 같았습니다. 대상 목록 100,000행과 원본 해시도 확인했습니다.

검증 자료는 패키지 외부에 보존되어 있으며 요약은 `RELEASE.json`에 있습니다. 패키지 정리 과정에서 실제 사이트를 다시 크롤링하거나 전체 corpus를 재분석하지는 않았습니다.

## 연구 집계 스크립트

다음 스크립트는 보존된 과거 측정 자료를 읽습니다. 일반 크롤러→분석기→분류기 실행과 별개이며 원자료는 포함하지 않습니다.

| 스크립트 | 용도 |
|---|---|
| `scripts/export_csv_and_tracker_counts.py` | 전체 CSV·규칙별 수·목적지 집계 |
| `scripts/count_rule_overlap.py` | 규칙별 단독·동시 탐지 도메인 집계 |
| `scripts/compare_archived_easyprivacy.py` | 보존 호스트 목록과 대상·요청 호스트 대조 |
| `scripts/recompute_appendix.py` | 논문 부록 표 재계산 |

전체 실행 명령과 입력 형식은 영문 README에 있습니다. 예를 들어 부록 집계는 다음과 같이 실행합니다.

```bash
python3 scripts/recompute_appendix.py \
  --classification /path/to/final_classification.json.gz \
  --comparison /path/to/all_11124_domain_comparison.csv \
  --comparison-summary /path/to/comparison_summary.json \
  --output /path/to/new_appendix_metrics.json
```

출력 부모 폴더는 미리 만들고 새 파일명을 지정합니다. 과거 분류 JSON의 `rows` 구조를 사용하므로 현재 출력인 `argus_final_report.json`을 그대로 넣을 수 없습니다. 부록 스크립트는 당시 11,124개 혼합추적자 도메인·93,902개 그룹을 검사하는 고정 집계이며, 임의의 새 데이터용 범용 집계기가 아닙니다. 검증을 끄는 `python -O`는 사용하지 않습니다. 대조 요약 JSON은 해시 기록에만 사용합니다. `Unresolved URL`과 `All three`는 모두 `DYNAMIC_URL` 또는 `{VAR}` 포함 조건입니다.

당시 CSV·집계 결과와 목록 대조 9,957/1,166/1은 재계산 결과가 일치했습니다. 과거 별도 실험 대조용 `--old-csv`는 이번에 다시 검증하지 않았습니다. 호스트 대조는 보존된 EasyPrivacy 파생 목록의 정확한 호스트·하위 도메인 매칭이며 전체 Adblock 필터 평가가 아닙니다. 목록의 공식 버전 날짜·추출 과정은 확정되지 않았으므로 전 세계적 최초 발견을 입증하는 수치로 해석하지 않습니다.

필요한 과거 입력의 파일명·해시는 `REPRODUCTION_INPUTS.json`에 기록했습니다. 데이터와 공개 다운로드 주소는 포함하지 않았으며, 이 소스 패키지만으로 논문 결과 전체를 재현할 수 있다고 주장하지 않습니다.

## License

직접 작성한 크롤러는 **MIT** 라이선스로 공개하며 `crawler/LICENSE`와 패키지 메타데이터에 반영했습니다. 루트 LICENSE와 외부 코드의 기존 저작권·라이선스 고지는 유지합니다. 네이티브 엔진에 포함된 Hermes·LLVH·dtoa·zip·ICU와 npm 의존성에는 각 구성 요소의 라이선스가 적용됩니다.
