#!/usr/bin/env bash
# Argus end-to-end pipeline: crawl -> analyze (mixed-hermes) -> classify.
# Usage:
#   pipeline.sh                       # uses crawler/urls_test.txt
#   pipeline.sh path/to/urls.txt      # custom URL list
set -euo pipefail

ARGUS_ROOT="${ARGUS_ROOT:-/home/csec/Argus}"
URL_FILE="${1:-${ARGUS_ROOT}/crawler/urls_test.txt}"

if [[ ! -f "$URL_FILE" ]]; then
    echo "URL list not found: $URL_FILE" >&2
    exit 1
fi

echo "==> [1/3] Crawling URLs from $URL_FILE"
cd "${ARGUS_ROOT}/crawler"
node crawler.cjs "$URL_FILE"

echo "==> [2/3] Analyzing collected scripts with mixed-hermes"
cd "${ARGUS_ROOT}/crawler/collected_scripts"
python3 run_pipeline.py

echo "==> [3/3] Classifying results"
cd "${ARGUS_ROOT}"
python3 classifier.py

echo "==> Pipeline complete. CSV reports: ${ARGUS_ROOT}/csv_reports/"
