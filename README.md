# Argus

**Argus** is an automated pipeline for large-scale web tracking analysis.
It crawls JavaScript from real-world websites, performs static taint analysis on the compiled IR, classifies behavioral patterns, and visualizes data-flow graphs.

---

## Pipeline Overview

```
[1] Crawling  →  [2] Taint Analysis  →  [3] Classification  →  [4] Graph Generation
  crawler.cjs      Argus LLVM Pass        classifier.py         viz_taint.py
```

---

## 1. Crawling

**Script:** `crawler/crawler.cjs`

Collects JavaScript from websites using a headless Puppeteer cluster.

### What it does
- Reads a domain list (e.g., Tranco Top 100K) from a CSV or plain-text file
- Launches a headless Chromium instance per domain
- Intercepts all network responses and extracts `*.js` resources
- Decodes non-UTF-8 encoded scripts (EUC-KR, CP949) and repairs mojibake
- Deobfuscates collected scripts using **Restringer** and transpiles to ES5 via **Babel**
- Saves per-site scripts and a merged `wholepage.js` under `collected_scripts/<domain>/`
- Records failed domains in `fail_scripts/failed_urls.txt` for retry

### Usage
```bash
node crawler/crawler.cjs <url_list.txt>
```

### Output
```
collected_scripts/
  <domain>/
    wholepage.js          # merged, transpiled scripts
    <script>_<ts>.js      # individual script files
    network_logs.json     # intercepted URLs
fail_scripts/
  failed_urls.txt
```

---

## 2. Taint Analysis

**Pass:** `lib/Optimizer/Taint/`
**Entry:** `MixedTaintAnalysis.cpp` → `TaintAnalysis.cpp`

Performs static taint analysis on JavaScript compiled to **Hermes IR** via the Argus LLVM-style optimization pass.

### What it does
- Compiles `wholepage.js` to Hermes bytecode IR
- Registers **sources** (fingerprinting APIs: `navigator.*`, `document.URL`, `screen.*`, WebGL, etc.) and **sinks** (data exfiltration: `fetch`, `sendBeacon`, `XMLHttpRequest`, `img.src`, `innerHTML`, etc.)
- Propagates taint through the def-use chain using a worklist algorithm
- Tracks inter-procedural flows via **CallGraphAnalyzer** and closure variables via **DefUseAnalyzer**
- Applies four detection rules:
  | Rule | Description |
  |------|-------------|
  | Rule 1 | Direct source-to-sink taint flow |
  | Rule 2 | Fingerprinting data stored in localStorage / cookies |
  | Rule 3 | Event-driven function identification (`addEventListener`, `onclick`, …) |
  | Rule 4 | DOM evasion mapping (`img.src`, `script.src` forced to `SINK_NETWORK`) |
- Outputs a structured JSON report per domain

### Output
```
report/
  <domain>_report.json      # full taint report (s2s_routes, source, sink, path)
  <domain>_report.txt       # human-readable log
```

### JSON Report Format
```json
{
  "target_url": "<domain>",
  "s2s_routes": [
    {
      "route_id": 1,
      "source_name": "navigator.userAgent",
      "sink_name": "fetch",
      "sink_type": "Network",
      "trigger_context": "EVENT_DRIVEN",
      "destination_url": "https://tracker.example.com/collect",
      "path_length": 7,
      "path_nodes": ["LoadPropertyInst", "CallInst", "..."]
    }
  ]
}
```

---

## 3. Classification

**Script:** `classifier.py`

Classifies each taint report into behavioral tracking categories using the JSON output from Phase 2.

### What it does
- Reads all `*_report.json` files from `pipeline_results/` (Stage 2 output)
- Extracts features per S2S route: source API, sink type, trigger context, destination URL, path length
- Classifies routes into categories:
  - `Fingerprinting` — device/browser attribute collection
  - `Data Exfiltration` — network transmission of collected data
  - `Cookie Tracking` — persistent identifier storage/retrieval
  - `Event-Driven Tracking` — user interaction monitoring
  - `Code Injection` — dynamic script execution risk
- Writes a timestamped CSV summary to `csv_reports/`

### Usage
```bash
python3 classifier.py                 # classify only
python3 classifier.py --draw-graphs   # also render GTG/CTG PNGs for malicious domains
python3 classifier.py --summary       # also emit a per-domain summary CSV for paper use
```

### Output
```
csv_reports/
  malicious_domains_<YYYYMMDD>.csv
pipeline_results/graphs/              # if --draw-graphs is passed
  <domain>_<gtg|ctg>.png
```

---

## 4. Graph Generation

**Script:** `viz_taint.py`

Generates two types of data-flow graphs from a single taint report JSON, rendered as Graphviz DOT files (and PNGs when `dot` is available).

### Graph Types

| Graph | Description |
|-------|-------------|
| **GTG** (Global Threat Graph) | All S2S routes for a domain, including dynamic sources |
| **CTG** (Core Threat Graph) | Filtered high-confidence paths only; used for publication figures |

### What it does
- Parses `s2s_routes` from the JSON report
- Emits Graphviz DOT with color-coded nodes by sink type:
  - 🔴 `Network` — data exfiltration
  - 🟠 `Storage` — fingerprinting / storage
  - 🟡 `XSS` — DOM manipulation
  - 🟣 `CodeInjection` — code injection
  - 🔵 `Navigation` — page redirection
- Dynamic/unresolved sources are rendered as dashed grey nodes (`Dynamic_Source`)
- Includes a legend for hybrid (static + dynamic) view

### Usage
```bash
python3 viz_taint.py <report.json>
```

### Output
```
<domain>_gtg.dot / <domain>_gtg.png
<domain>_ctg.dot / <domain>_ctg.png
```

---

## Directory Structure

```
Argus/
├── crawler/
│   ├── crawler.cjs                       # Puppeteer crawler
│   └── collected_scripts/
│       ├── run_pipeline.py               # Stage 2 batch runner
│       └── <domain>/                     # Crawled JS per domain (runtime)
├── lib/
│   └── Optimizer/Taint/
│       ├── TaintAnalysis.cpp             # Core taint analysis logic
│       ├── MixedTaintAnalysis.cpp
│       ├── DefUseAnalyzer.cpp            # Def-use chain propagation
│       ├── CallGraphAnalyzer.cpp         # Inter-procedural call graph
│       └── ...
├── report/                               # Per-domain JSON/TXT reports
├── pipeline_results/                     # Aggregated taint reports (Stage 2 output)
├── csv_reports/                          # Classification CSVs (Stage 3 output)
├── classifier.py                         # Behavioral classifier
├── viz_taint.py                          # GTG / CTG graph generator
├── pipeline.sh                           # End-to-end pipeline wrapper
├── Dockerfile                            # Self-contained build environment
└── build/bin/mixed-hermes                # Argus taint analysis binary (after build)
```

---

## Running the Full Pipeline

`crawler/collected_scripts/run_pipeline.py` walks `collected_scripts/<domain>/` directories, runs `mixed-hermes` on each `wholepage.js`, and collects the resulting JSON reports under `pipeline_results/`.

> **Path convention:** `run_pipeline.py` and `classifier.py` reference paths via hard-coded `~/argus/...` and `~/mixed-hermes/...` prefixes. Inside the Docker image both names are symlinked to the project root, so the scripts run unmodified. For local use outside Docker, clone the repo as `~/mixed-hermes/` (or create the equivalent symlinks) — all output directories shown below resolve to the project root.

Manual three-stage invocation:

```bash
# [1] Crawl
cd ~/Argus/crawler && node crawler.cjs <url_list.txt>

# [2] Taint analysis (batch)
cd ~/Argus/crawler/collected_scripts && python3 run_pipeline.py

# [3] Classification
cd ~/Argus && python3 classifier.py
```

Or use the wrapper that chains all three:

```bash
./pipeline.sh                          # default: crawler/urls_test.txt (smoke test, 2 domains)
./pipeline.sh crawler/tranco-100K.txt    # full Tranco list
./pipeline.sh /path/to/your_urls.txt   # custom URL list
```

---

## Docker

A `Dockerfile` is provided to build a self-contained image with all dependencies pre-installed (Hermes/Argus build, Node.js 22, Puppeteer/Chromium runtime, Python tooling, Graphviz, `nlohmann-json`).

The build process:
1. Installs system packages (build toolchain, Chromium runtime libs, `nlohmann-json3-dev`, Graphviz, etc.)
2. Compiles the Argus/Hermes taint analysis binary via CMake + Ninja → `build/bin/mixed-hermes`
3. Runs `npm install` in `crawler/` (downloads Chromium for Puppeteer into `~/.cache/puppeteer`)
4. Creates a non-root user `user` and prepares the runtime environment

### Build

```bash
# 기본 빌드
docker build -t argus:base .

# 전체 로그 보면서 빌드 (권장)
docker build --progress=plain -t argus:base .

# 완전히 새로 빌드 (캐시 무시)
docker build --progress=plain --no-cache -t argus:base .
```

> **Apple Silicon (M-series):** Puppeteer's bundled Chrome is x86_64-only on Linux as of writing. On arm64 hosts add `--platform=linux/amd64` to both `docker build` and `docker run` so the entire image (and Chrome) runs under Rosetta:
> ```bash
> docker build --platform=linux/amd64 -t argus:base .
> docker run --platform=linux/amd64 --rm -it argus:base bash
> ```

### Run the pipeline

```bash
# Interactive shell
docker run --rm -it argus:base bash

# Inside the container:
./pipeline.sh                          # 테스트 URL 2개로 스모크 테스트
./pipeline.sh crawler/tranco-100K.txt    # 풀 데이터셋
```

### Run individual stages

Each stage can be invoked with its own `docker run`, mounting only the directories it needs. Outputs land on the host so subsequent stages can pick them up.

```bash
# Stage 1 — Crawl a URL list
docker run --rm -it \
  -v $(pwd)/urls.txt:/home/user/Argus/urls.txt \
  -v $(pwd)/collected_scripts:/home/user/Argus/crawler/collected_scripts \
  argus:base \
  bash -c "cd crawler && node crawler.cjs /home/user/Argus/urls.txt"

# Stage 2 — Taint analysis on a single script
docker run --rm -it \
  -v $(pwd)/collected_scripts:/home/user/Argus/crawler/collected_scripts \
  -v $(pwd)/report:/home/user/Argus/report \
  argus:base \
  /home/user/Argus/build/bin/mixed-hermes \
    crawler/collected_scripts/<domain>/wholepage.js

# Stage 3 — Classification
#   reads:  pipeline_results/  (Stage 2 batch output)
#   writes: csv_reports/       (timestamped CSV)
docker run --rm -it \
  -v $(pwd)/pipeline_results:/home/user/Argus/pipeline_results \
  -v $(pwd)/csv_reports:/home/user/Argus/csv_reports \
  argus:base \
  python3 /home/user/Argus/classifier.py

# Stage 4 — Graph generation for a specific report
docker run --rm -it \
  -v $(pwd)/report:/home/user/Argus/report \
  argus:base \
  python3 /home/user/Argus/viz_taint.py report/<domain>_report.json
```

### Run the full pipeline

```bash
docker run --rm -it \
  -v $(pwd)/collected_scripts:/home/user/Argus/crawler/collected_scripts \
  -v $(pwd)/pipeline_results:/home/user/Argus/pipeline_results \
  argus:base \
  bash -c "cd /home/user/Argus/crawler/collected_scripts && python3 run_pipeline.py"
```

> Puppeteer requires `--no-sandbox` (already configured in `crawler.cjs`).
> If Chromium still fails to launch, try `--cap-add=SYS_ADMIN` on `docker run`.

---

## Dependencies

| Component | Dependency |
|-----------|-----------|
| Crawler | Node.js 22+, `puppeteer-cluster`, `puppeteer-extra`, `restringer`, `@babel/core`, `iconv-lite`, `js-beautify` |
| Taint Analysis | C++14 toolchain (gcc / clang), CMake, Ninja, `libicu-dev`, `nlohmann-json3-dev`, `libreadline-dev` |
| Classifier | Python 3.10+ (standard library only — no external packages) |
| Graph Generation | Python 3.10+, Graphviz (`dot` CLI) |
