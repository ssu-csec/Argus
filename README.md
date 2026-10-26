# Argus

Argus is a research pipeline for identifying mixed web trackers. It collects JavaScript from websites, performs static source-to-sink taint analysis, and applies the Argus classification rules to the resulting reports.

This is the **v4 research source package**, based on the integrated RC3. It is built locally on Linux or WSL2; a Docker image is not included. The package contains the crawler, analyzer, classifier, the 100,000-target list, and research aggregation scripts.

[한국어 안내](README_KO.md)

## Pipeline Overview

```text
[1] Crawling  →  [2] Taint Analysis  →  [3] Classification
 crawler.cjs       analyzer/run.py       classifier/run.py
                   mixed-hermes         Argus rules
```

The normal workflow has three stages. Historical table aggregation is a separate operation on archived results.

## Dependencies and Installation

| Component | Requirements |
|---|---|
| Environment | Linux or WSL2 |
| Crawler | Node.js 20, npm, Puppeteer/Chromium and its Linux runtime libraries |
| Native analyzer | C++17 toolchain, CMake, Ninja, ICU development libraries |
| Pipeline and classifier | Python 3.10+; analysis also uses the root npm dependencies |
| Historical aggregation | Python standard library and the corresponding archived input files |

After installing Node.js 20, run the following from the repository root:

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build libicu-dev python3
npm ci --ignore-scripts
bash scripts/build.sh
npm ci --prefix crawler
```

The build creates `build/bin/mixed-hermes` and uses two build jobs by default. The last command installs the crawler dependencies and downloads Chromium; the browser's Linux system libraries must also be available. Skip the crawler installation when analyzing already collected files. The supported native build is the configuration in `scripts/build.sh`.

## 1. Crawling

**Script:** `crawler/crawler.cjs`

Collects JavaScript and request observations with Puppeteer/Chromium.

### What it does

- Reads targets from a domain/URL list. The included `crawler/20261005-top-100k-urls.txt` contains 100,000 unique entries, one per line.
- Visits each target and saves captured scripts, response evidence, request observations, and hashes.
- Preserves collected JavaScript by default. Optional `--transform babel` records transformations, skips, and failures.
- Records `SUCCESS`, `PARTIAL`, `NO_SCRIPTS`, `FAILED`, and `NOT_STARTED` outcomes.

### Usage

Check the target list without starting a browser:

```bash
node crawler/crawler.cjs crawler/20261005-top-100k-urls.txt --check-input
```

Start collection in a new output directory:

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
    └── <visit-directory>/
        ├── visit.json
        ├── network_logs.json
        ├── wholepage.js
        └── ... saved scripts and response evidence
```

`wholepage.js` is created when collection and assembly succeed. `NO_SCRIPTS` means no usable script was saved; it does not prove that the website has no JavaScript. Script concatenation order does not establish frame or module execution order.

## 2. Taint Analysis

**Entry point:** `analyzer/run.py`  
**Native engine:** `build/bin/mixed-hermes`

Analyzes saved JavaScript using the Argus native engine and validates the resulting evidence.

### What it does

- Validates input paths and hashes and performs bounded AST checks.
- Compiles admitted inputs and tracks source-to-sink flows in the native IR.
- Verifies complete reports and retains execution diagnostics and provenance.
- Produces a manifest of verified complete reports for the classifier.

This stage does not execute collected website JavaScript and does not run the final rule classifier.

### Usage

Analyze the crawler output:

```bash
python3 analyzer/run.py --crawl-dir runs/crawl-01 \
  --out runs/analysis-01 --workers 2
```

Analyze one saved file without crawling again:

```bash
python3 analyzer/run.py --input /path/to/example.com/wholepage.js \
  --domain example.com --network-log /path/to/example.com/visit.json \
  --out runs/analysis-saved-01
```

For multiple saved files, use `--manifest inputs.json` instead of `--crawl-dir`. Paths are relative to the input manifest:

```json
[
  {"domain":"example.com","input":"example.com/wholepage.js","network_log":"example.com/visit.json"},
  {"domain":"example.org","input":"example.org/wholepage.js","network_log":"example.org/visit.json"}
]
```

Pass `visit.json` or a JSON array of URL strings as network evidence. The crawler's `network_logs.json` is an array of request objects and is not accepted as this argument. Missing network evidence affects network-dependent rules. Duplicate normalized domain keys are rejected.

### Output

```text
runs/analysis-01/
├── results.json
├── progress.json
├── final_summary.json
├── classification_manifest.json
└── visits/
    └── ... per-domain analysis artifacts
```

The classification manifest includes only verified complete reports and their network snapshots. Failures and holds remain recorded separately. Exit code 2 indicates incomplete inputs after processing the other inputs; inspect the summary before classifying the completed subset.

## 3. Classification

**Entry point:** `classifier/run.py`  
**Rule implementation:** `classifier.py`

Applies the Argus rules to completed native reports without repeating native analysis.

### What it does

- Loads the completed-report manifest and checks report hashes when supplied.
- Applies the R1/R2/R4/R5 finding rules and records R3 separately at the domain level.
- Exports finding groups, domain-level rule combinations, and a combined JSON report.

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
    └── ... underlying classifier outputs and execution records
```

`argus_findings.csv` retains the original nine columns:

```text
Domain, Threat_Type, Trigger_Context, Leaked_Data (Source),
Leak_Method (Sink), Destination, Observed_Trackers, Party_Check, Confidence_Score
```

A domain can have multiple finding groups and match multiple rules. Domain counts, finding-group counts, and source-to-sink route counts are different units. R3-only structural observations are kept separate from qualifying mixed-tracker classifications.

Use the wrapper above for the packaged workflow. When relocating analysis outputs, preserve or update all referenced paths. A manually prepared classification manifest must contain `domain`, `report`, and optionally `report_sha256` and `network_log`; completion and provenance must be established before including a report.

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
├── argus/
├── argus_pipeline/
├── argus_semantics/
├── argus_conditional/
├── lib/Optimizer/Taint/
├── include/, public/, external/, cmake/, tools/
├── scripts/
│   ├── build.sh
│   ├── export_csv_and_tracker_counts.py
│   ├── count_rule_overlap.py
│   ├── compare_archived_easyprivacy.py
│   └── recompute_appendix.py
├── RELEASE.json
├── REPRODUCTION_INPUTS.json
├── LICENSE
└── build/bin/mixed-hermes                 (created by the build)
```

The supporting Python packages and native source directories are required by the three entry points. Collected website code, historical results, installed dependencies, compiled binaries, test suites, and smoke runners are not included. The earlier repository's Docker and graph-generation instructions do not apply to this package.

## Running the Full Pipeline

Run these commands in order from the repository root after installation. Always choose new output directories. If a stage reports an error, inspect its results before continuing.

```bash
node crawler/crawler.cjs crawler/20261005-top-100k-urls.txt \
  --out runs/crawl-01 --transform preserve --concurrency 2

python3 analyzer/run.py --crawl-dir runs/crawl-01 \
  --out runs/analysis-01 --workers 2

python3 classifier/run.py \
  --manifest runs/analysis-01/classification_manifest.json \
  --out runs/classification-01
```

Monitor the relevant stage from another terminal:

```bash
watch -n 10 cat runs/crawl-01/progress.json
```

```bash
watch -n 10 cat runs/analysis-01/progress.json
```

## Optional Analysis and Limits

`--semantics` on the analyzer adds exact Date-source-to-cookie-route semantic labels. `--conditional` adds separate pbjs conditional observations. These outputs are distinct from the main R1–R5 rule classification. `python3 -m argus analyze` also supports the combined analysis/classification workflow.

- Resource bounds remain in place: at most four workers, 8 GiB address space per process, up to 60 seconds per preflight/native stage, 256 MiB per output file and 1 GiB per item. The compressed full-IR logical limit is 1 GiB. Startup checks require workers × 8 GiB plus 2 GiB available RAM and 22 GiB free disk. Resource exhaustion is not a negative result.
- Missing module dependencies or uncertain entry/frame/global context may result in a hold or `UNKNOWN`. Concatenating scripts cannot resolve those uncertainties.
- Native completion is distinct from semantic certainty. Absence of findings does not establish benign behavior. `DYNAMIC_URL` and `{VAR}` indicate unresolved destination information.
- Semantic labels concern the exact emitted Date source-to-sink route; surrounding Date flows are not merged into that route's label.
- The historical 44,882 completed domains were obtained with multiple engine versions. They are not a new full-corpus evaluation of this reduced distribution.

The source cleanup preserves license notices, interpreter/encoding directives, and runtime strings. Ordinary explanatory comments are removed. Validation records and tests are maintained separately from this runtime distribution. See `RELEASE.json` for this package's validation summary and target-list hash.

## Validation

The reduced sources build successfully on Linux/WSL2. Validation passed 19 crawler checks, 61 authored native cases and 11 TDZ cases, plus positive/negative Date-to-cookie pipeline checks and a missing-module hold check. Python and JavaScript AST comparisons and a comment-excluded native-source comparison passed. Three saved site inputs (adblockplus.org, ampproject.org, bis.org) completed; source-to-sink route fields and rule findings matched RC3 after normalizing source-file paths. The included target list contains 100,000 unique entries and retains the supplied file hash.

These checks use external validation files; the runtime archive contains no smoke or test suite. No new full-corpus run or live crawl was performed during packaging. See `RELEASE.json` for the machine-readable summary.

## Research Aggregation Scripts

These scripts operate on archived measurement results and are separate from the three-stage workflow. Input datasets are not bundled; their filenames and hashes are listed in `REPRODUCTION_INPUTS.json`. Publishing this source package does not claim that all paper results can be reproduced from its contents alone.

### Appendix tables

`scripts/recompute_appendix.py` reproduces the appendix aggregates from the archived measurement inputs. It is a research-reproduction script, not a smoke test or another stage of the normal crawler/analyzer/classifier workflow.

```bash
python3 scripts/recompute_appendix.py \
  --classification /path/to/final_classification.json.gz \
  --comparison /path/to/all_11124_domain_comparison.csv \
  --comparison-summary /path/to/comparison_summary.json \
  --output /path/to/new_appendix_metrics.json
```

The script uses only the Python standard library. Supply an existing output parent directory and a new output filename. Historical input data are not bundled in this source package. The required inputs are:

- The archived gzip JSON classification dataset, with a top-level `rows` array and per-domain findings, domain findings and input hashes. This is **not** the same schema as the current CLI's `argus_final_report.json`.
- The archived domain/list-comparison CSV, including `Domain`, `Status`, `Wholepage_SHA256`, `Network_URLs_SHA256` and `Finding_Groups`.
- The archived comparison summary JSON. This file's hash is recorded for provenance; it is not used to derive the aggregates.

The script intentionally checks the historical cohort (11,124 mixed-tracker domains and 93,902 finding groups); it is not a generic aggregator for arbitrary future runs. Do not use Python's `-O` option, which disables its assertions. `Unresolved URL` includes exact `DYNAMIC_URL` and destinations containing `{VAR}`; `All three` uses that same condition. R1/R2/R4/R5 counts use finding groups, while the maximum evidence score is computed per domain. Reproduction input filenames and hashes are recorded in `RELEASE.json`.

### CSV tables, rule overlaps, and list coverage

The historical measurement schema is required by these scripts. They read saved results without crawling or rerunning the native analyzer. Python assertions are part of their validation; do not use `python -O`.

```bash
mkdir -p runs
python3 scripts/export_csv_and_tracker_counts.py \
  --input /archive/final_classification.json.gz --output runs/csv-export
python3 scripts/count_rule_overlap.py \
  --input /archive/final_classification.json.gz --output runs/rule-overlap.json
python3 scripts/compare_archived_easyprivacy.py \
  --classification /archive/final_classification.json.gz \
  --network-dir /archive/networks \
  --list /archive/easyprivacy_tracker_domains.txt \
  --output runs/list-comparison
```

Use new output paths. The network directory must contain `local_network.json.gz`, `argus1_network.json.gz`, `argus2_network.json.gz` and `argus3_network.json.gz` from the same archived measurement. `--old-csv` is optional and is needed only for comparison with the earlier study. CSV export reads `TRACKER_KEYWORDS` from the packaged classifier using Python AST parsing, without executing that classifier; `--classifier` can specify an archived classifier explicitly.

`REPRODUCTION_INPUTS.json` identifies required archived inputs by filename and SHA-256. These data are **not included** and no public download URL has been configured. The source ZIP alone therefore does not reproduce the paper's numerical results. Recomputed comparison JSON contains new timestamps and paths; compare its metrics and CSV hashes rather than expecting that entire JSON file to have the archived hash.

The list comparison checks literal hostnames and dot-boundary subdomains against the archived EasyPrivacy-derived host list. It is not full Adblock rule evaluation. The original upstream date and extraction procedure of that list have not been established. The reproduced categories contain 9,957 list-matched, 1,166 list-unmatched and one indeterminate mixed-tracker domain. These counts concern the archived observation and matching method, not proof of global novelty.

## License

The author-written crawler is released under the MIT License; see `crawler/LICENSE`. Its package metadata uses MIT. Third-party dependencies retain their own licenses.

Keep `LICENSE` and third-party notices with redistributed source. The native engine includes Hermes, LLVH, dtoa, zip, and ICU declarations; their applicable notices remain in the relevant files and directories. npm dependencies retain their own licenses when installed.
