# syntax=docker/dockerfile:1
#
# Multi-stage build on Debian Bullseye (glibc 2.31)
# Compatible with most Linux distros released after 2020.
#
# Usage:
#   docker buildx build -t trojan-rs .
#   docker buildx build --output type=local,dest=out .   # extract binary to ./out/

# ── Stage 1: Build (Debian Bullseye, glibc 2.31) ───────────────
FROM rust:1-bullseye AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev perl make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cargo build --release --features cert

# ── Stage 2: Runtime ────────────────────────────────────────────
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/trojan /usr/local/bin/trojan

ENTRYPOINT ["trojan"]
