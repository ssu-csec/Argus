# Argus base image — Hermes-based taint analysis (mixed-hermes)
#
# Build:   docker build -t argus:base .
# Run:     docker run --rm -it argus:base bash

FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

ENV TZ=Asia/Seoul \
    PYTHONIOENCODING=UTF-8 \
    LC_CTYPE=C.UTF-8 \
    LANG=C.UTF-8

# ---------------------------------------------------------------------------
# System packages
#   build-essential / clang / cmake / ninja-build : Hermes C++14 toolchain
#   libicu-dev / libreadline-dev / python3 / zip  : Hermes required deps
#   graphviz                                      : dot, used by classifier.py
#   curl / wget / gnupg / ca-certificates         : Node.js + LLVM apt repos
#   nlohmann-json3-dev                            : <nlohmann/json.hpp> used
#                                                   by lib/Optimizer/Taint/*
#   libnss3 ... fonts-liberation                  : Chromium runtime libs for
#                                                   puppeteer (crawler/)
# Install BEFORE creating the csec user so sudo's postinst owns /etc/sudoers.
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        curl \
        git \
        gnupg \
        graphviz \
        libicu-dev \
        libreadline-dev \
        lsb-release \
        ninja-build \
        nlohmann-json3-dev \
        pkg-config \
        python3 \
        python3-pip \
        software-properties-common \
        sudo \
        tzdata \
        unzip \
        wget \
        zip \
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

# Non-root user (mirrors the legacy CustomHermes image convention).
# Use /etc/sudoers.d drop-in instead of editing /etc/sudoers directly so
# sudo's package-managed config stays untouched.
RUN groupadd -r csec \
 && useradd -r -g csec -m csec \
 && echo "csec:csec" | chpasswd \
 && echo "csec ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/csec \
 && chmod 0440 /etc/sudoers.d/csec

# Python helper for pulling datasets from Google Drive (legacy pipeline)
RUN pip3 install --no-cache-dir gdown

# Node.js 22 — required by crawler/ deps. restringer pulls in isolated-vm,
# which needs Node >=22 (uses v8::SourceLocation introduced in V8 12.x).
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/*

# Note: system LLVM is intentionally NOT installed. Hermes/Argus vendors the
# parts of LLVM it needs under external/llvh/ and the build does not call
# find_package(LLVM) or llvm-config. The default gcc (build-essential) and
# clang packages are sufficient.

# ---------------------------------------------------------------------------
# Source + build
# ---------------------------------------------------------------------------
WORKDIR /home/csec/Argus
COPY . /home/csec/Argus

# Build Hermes + mixed-hermes (taint analysis). Outputs land in build/bin/.
RUN cmake -S /home/csec/Argus -B /home/csec/Argus/build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /home/csec/Argus/build

# Crawler npm deps. puppeteer's postinstall downloads Chrome into
# $PUPPETEER_CACHE_DIR (or ~/.cache/puppeteer). Pin it to csec's home so the
# binary is reachable when the runtime user (csec) launches the browser.
ENV PUPPETEER_CACHE_DIR=/home/csec/.cache/puppeteer
RUN mkdir -p "$PUPPETEER_CACHE_DIR" \
 && cd /home/csec/Argus/crawler && npm install --no-audit --no-fund \
 && chown -R csec:csec /home/csec/.cache

# classifier.py hard-codes ~/mixed-hermes/... and run_pipeline.py hard-codes
# ~/argus/... — symlink both names to the real source tree so the scripts
# work without modification.
RUN ln -s /home/csec/Argus /home/csec/mixed-hermes \
 && ln -s /home/csec/Argus /home/csec/argus \
 && chown -h csec:csec /home/csec/mixed-hermes /home/csec/argus \
 && chmod +x /home/csec/Argus/pipeline.sh \
 && chown -R csec:csec /home/csec/Argus

USER csec
WORKDIR /home/csec/Argus

# ---------------------------------------------------------------------------
# End-to-end pipeline: crawl -> mixed-hermes analysis -> classify.
# Run inside the container:
#
#   ./pipeline.sh                              # uses crawler/urls_test.txt
#   ./pipeline.sh crawler/tranco-1M.txt        # full Tranco list
#   ./pipeline.sh path/to/your_urls.txt        # custom list
#
# Or invoke each stage manually:
#   cd crawler && node crawler.cjs urls_test.txt
#   cd crawler/collected_scripts && python3 run_pipeline.py
#   python3 classifier.py
# ---------------------------------------------------------------------------
