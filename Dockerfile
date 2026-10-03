FROM rust:1.98.1-bookworm

# System packages & C++ tooling for native witness generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    m4 \
    nasm \
    curl \
    git \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Add clippy
RUN rustup component add clippy rustfmt

# Node.js & SnarkJS
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && npm install -g snarkjs \
 && rm -rf /var/lib/apt/lists/*

# Pinned Circom compiler (Guarantees deterministic R1CS output)
ARG CIRCOM_VERSION=v2.2.3
RUN git clone --depth 1 --branch ${CIRCOM_VERSION} https://github.com/iden3/circom.git /tmp/circom \
 && cd /tmp/circom \
 && cargo build --release \
 && cp target/release/circom /usr/local/bin/circom \
 && rm -rf /tmp/circom

# NPM must use a writable cache
ENV npm_config_cache=/tmp/npm-cache

# Cache Directories
RUN mkdir -p /tmp/cargo-target /tmp/cargo-home \
 && chmod -R 777 /tmp/cargo-target /tmp/cargo-home

RUN curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to /usr/local/bin

WORKDIR /workspace