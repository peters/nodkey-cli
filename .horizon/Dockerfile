# syntax=docker/dockerfile:1.7
FROM ghcr.io/peters/horizon-worker-base@sha256:5d831ab73cc11575080ededaca851480fc9539c13916fd9c19e36903962526d8

USER root
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# ci.yml relies on hosted-runner native tools. Cargo.lock includes aws-lc-sys,
# which needs a C/C++ compiler and CMake. TLS uses rustls, not system OpenSSL.
ARG BUILD_ESSENTIAL_VERSION=12.10ubuntu1
ARG CMAKE_VERSION=3.28.3-1build7
ARG PKG_CONFIG_VERSION=1.8.1-2build1
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential="${BUILD_ESSENTIAL_VERSION}" cmake="${CMAKE_VERSION}" \
        pkg-config="${PKG_CONFIG_VERSION}" \
        ca-certificates curl xz-utils

# Cargo.toml and README require Rust >=1.85; CI uses the runner's Rust.
# Pin stable as resolved on 2026-10-11. Direct tools need no writable rustup home.
ARG RUST_VERSION=1.99.0
ARG RUST_SHA256=891c6366d7100feda0bca4c03ce63f3c9ac827cbebbc283e7433061d42c6a376
ARG WASM_STD_SHA256=b760b0c9b08a6843c05de0098bd6802e23178ff473c4715ae57c1d679125bf22
RUN set -eu; mkdir -p /tmp/nodkey-cli-rust; cd /tmp/nodkey-cli-rust; \
    archive="rust-${RUST_VERSION}-x86_64-unknown-linux-gnu"; \
    curl -fsSL "https://static.rust-lang.org/dist/${archive}.tar.xz" -o "${archive}.tar.xz"; \
    printf '%s  %s\n' "$RUST_SHA256" "${archive}.tar.xz" | sha256sum -c -; \
    tar -xf "${archive}.tar.xz"; \
    "./${archive}/install.sh" --prefix=/opt/nodkey-cli-rust \
        --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu,rustfmt-preview,clippy-preview \
        --disable-ldconfig; \
    archive="rust-std-${RUST_VERSION}-wasm32-unknown-unknown"; \
    curl -fsSL "https://static.rust-lang.org/dist/${archive}.tar.xz" -o "${archive}.tar.xz"; \
    printf '%s  %s\n' "$WASM_STD_SHA256" "${archive}.tar.xz" | sha256sum -c -; \
    tar -xf "${archive}.tar.xz"; \
    "./${archive}/install.sh" --prefix=/opt/nodkey-cli-rust --disable-ldconfig; \
    rm -rf /tmp/nodkey-cli-rust

# Newest published localci release. Verify the selected asset against SHA256SUMS
# and pin its checksum so replacing a release asset cannot change this image.
ARG LOCALCI_VERSION=0.1.0
ARG LOCALCI_SHA256=215096651a2af9b1a8d64825d6453b7e090049078ac30525074e9e1f43fdc893
RUN set -eu; mkdir -p /tmp/nodkey-cli-localci; cd /tmp/nodkey-cli-localci; \
    url="https://github.com/peters/localci/releases/download/v${LOCALCI_VERSION}"; \
    curl -fsSLO "${url}/localci-x86_64-unknown-linux-musl.tar.gz"; \
    curl -fsSLO "${url}/SHA256SUMS"; \
    awk '$2 == "localci-x86_64-unknown-linux-musl.tar.gz" { print; found=1 } END { if (!found) exit 1 }' \
        SHA256SUMS > selected.sha256; \
    sha256sum -c selected.sha256; \
    printf '%s  %s\n' "$LOCALCI_SHA256" localci-x86_64-unknown-linux-musl.tar.gz | sha256sum -c -; \
    tar -xzf localci-x86_64-unknown-linux-musl.tar.gz; \
    install -m 0755 localci /usr/local/bin/localci; \
    rm -rf /tmp/nodkey-cli-localci

# SSH sessions receive this environment. Cargo uses the persistent user's HOME
# for writable caches; toolchains are shared read-only outside all user homes.
RUN mkdir -p /etc/horizon-worker/session-env.d && printf '%s\n' \
    'PATH_PREPEND=/opt/nodkey-cli-rust/bin' \
    'PATH_PREPEND=/usr/local/bin' \
    > /etc/horizon-worker/session-env.d/20-nodkey-cli.env

# The proof checks committed source before these setup files are committed.
# Include only nonsecret image configuration and Horizon's generated verifier.
COPY --chmod=0444 Dockerfile pins.json verify-pins.py /opt/nodkey-cli-horizon/
# COPY's mode also applies to the created directory; sessions need traversal.
RUN chmod 0755 /opt/nodkey-cli-horizon

# Keep the base's SSH entrypoint and unprivileged session runtime.
