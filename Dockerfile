# Argus v4 — crawler -> analyzer (mixed-hermes) -> classifier
#
# Build:   docker build -t argus:v4 .
# Run:     docker run --rm -it argus:v4 bash

FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH
# Must match .nvmrc
ARG NODE_VERSION=20.19.6
# scripts/build.sh accepts 1..4 (default 2)
ARG ARGUS_BUILD_JOBS=2

ENV TZ=Asia/Seoul \
    PYTHONIOENCODING=UTF-8 \
    LC_CTYPE=C.UTF-8 \
    LANG=C.UTF-8

# ---------------------------------------------------------------------------
# System packages
#   build-essential / cmake / ninja-build : C++17 toolchain for scripts/build.sh
#   libicu-dev                            : Hermes ICU dependency
#   nlohmann-json3-dev                    : <nlohmann/json.hpp> used by
#                                           lib/Optimizer/Taint/*
#   libreadline-dev                       : optional mixed-hermes REPL support
#   python3                               : analyzer / classifier (stdlib only)
#   util-linux                            : prlimit, used by argus_pipeline
#   curl / xz-utils / ca-certificates     : Node.js tarball download
#   libnss3 ... fonts-liberation          : Chromium runtime libs for
#                                           puppeteer (crawler/)
# Install BEFORE creating the user user so sudo's postinst owns /etc/sudoers.
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        curl \
        libicu-dev \
        libreadline-dev \
        ninja-build \
        nlohmann-json3-dev \
        pkg-config \
        python3 \
        sudo \
        tzdata \
        util-linux \
        xz-utils \
        fonts-liberation \
        libasound2 \
        libatk-bridge2.0-0 \
        libatk1.0-0 \
        libatspi2.0-0 \
        libcairo2 \
        libcups2 \
        libdbus-1-3 \
        libdrm2 \
        libgbm1 \
        libgtk-3-0 \
        libnspr4 \
        libnss3 \
        libpango-1.0-0 \
        libx11-6 \
        libxcomposite1 \
        libxdamage1 \
        libxext6 \
        libxfixes3 \
        libxkbcommon0 \
        libxrandr2 \
        libxshmfence1 \
        libxss1 \
        xdg-utils \
 && rm -rf /var/lib/apt/lists/*

# Node.js pinned to .nvmrc from the official release tarball.
RUN case "${TARGETARCH:-amd64}" in \
        amd64) NODE_ARCH=x64 ;; \
        arm64) NODE_ARCH=arm64 ;; \
        *) echo "unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz" \
    | tar -xJ -C /usr/local --strip-components=1 --no-same-owner \
 && node --version && npm --version

# Non-root user (mirrors the legacy CustomHermes image convention).
# Use /etc/sudoers.d drop-in instead of editing /etc/sudoers directly so
# sudo's package-managed config stays untouched.
RUN groupadd -r user \
 && useradd -r -g user -m user \
 && echo "user:user" | chpasswd \
 && echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/user \
 && chmod 0440 /etc/sudoers.d/user

WORKDIR /home/user/Argus

# ---------------------------------------------------------------------------
# npm dependencies (copied first so source edits don't invalidate this layer)
#   root    : @babel/* used by argus_conditional / argus_pipeline (.cjs)
#   crawler : puppeteer etc. puppeteer's postinstall downloads Chrome into
#             $PUPPETEER_CACHE_DIR; pin it to user's home so the runtime
#             user can launch the browser.
# ---------------------------------------------------------------------------
ENV PUPPETEER_CACHE_DIR=/home/user/.cache/puppeteer
COPY package.json package-lock.json ./
COPY crawler/package.json crawler/package-lock.json crawler/
RUN npm ci --ignore-scripts --no-audit --no-fund \
 && mkdir -p "$PUPPETEER_CACHE_DIR" \
 && npm ci --prefix crawler --no-audit --no-fund \
 && chown -R user:user /home/user/.cache

# ---------------------------------------------------------------------------
# Source + native build (supported configuration: scripts/build.sh)
# Output: build/bin/mixed-hermes
# ---------------------------------------------------------------------------
COPY . /home/user/Argus
RUN ARGUS_BUILD_JOBS="${ARGUS_BUILD_JOBS}" bash scripts/build.sh \
 && test -x build/bin/mixed-hermes \
 && chown -R user:user /home/user/Argus

USER user
WORKDIR /home/user/Argus

# ---------------------------------------------------------------------------
# Three-stage workflow (run inside the container; use new output dirs):
#
#   node crawler/crawler.cjs crawler/20261005-top-100k-urls.txt \
#     --out runs/crawl-01 --transform preserve --concurrency 2
#
#   python3 analyzer/run.py --crawl-dir runs/crawl-01 \
#     --out runs/analysis-01 --workers 2
#
#   python3 classifier/run.py \
#     --manifest runs/analysis-01/classification_manifest.json \
#     --out runs/classification-01
#
# The analyzer refuses to start unless workers x 8 GiB + 2 GiB RAM and
# 22 GiB free disk are available for --out; mount runs/ from the host:
#   docker run --rm -it -v "$(pwd)/runs:/home/user/Argus/runs" argus:v4 bash
# ---------------------------------------------------------------------------
