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

# Node.js 18 — required by crawler/ (puppeteer, restringer)
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
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

# Crawler npm deps (puppeteer downloads Chromium during install).
# Comment out if the crawler is not needed inside the image.
RUN cd /home/csec/Argus/crawler && npm install --no-audit --no-fund

# classifier.py hard-codes paths under ~/mixed-hermes/... — symlink so those
# paths resolve to the actual source tree without modifying the script.
RUN ln -s /home/csec/Argus /home/csec/mixed-hermes \
 && chown -h csec:csec /home/csec/mixed-hermes \
 && chown -R csec:csec /home/csec/Argus

USER csec
WORKDIR /home/csec/Argus

# ---------------------------------------------------------------------------
# Runtime examples (uncomment / override at `docker run` time)
# ---------------------------------------------------------------------------
# RUN /home/csec/Argus/build/bin/mixed-hermes path/to/script.js
# RUN cd /home/csec/Argus/crawler && node crawler.cjs urls.txt
# RUN python3 /home/csec/Argus/classifier.py
