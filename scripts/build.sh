#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
JOBS=${ARGUS_BUILD_JOBS:-2}
case "$JOBS" in 1|2|3|4) ;; *) echo 'ARGUS_BUILD_JOBS must be 1..4' >&2; exit 2;; esac
cmake -S "$ROOT" -B "$ROOT/build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DHERMES_ENABLE_TEST_SUITE=OFF \
  '-DCMAKE_CXX_FLAGS_RELEASE=-O2 -DNDEBUG' '-DCMAKE_C_FLAGS_RELEASE=-O2 -DNDEBUG'
cmake --build "$ROOT/build" --target mixed-hermes -j "$JOBS"
