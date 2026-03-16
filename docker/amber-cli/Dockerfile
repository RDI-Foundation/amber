# syntax=docker/dockerfile:1.12

FROM rust:1.93.1-slim-trixie AS base-builder

WORKDIR /app

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    g++ \
    musl-tools \
    pkg-config

COPY rust-toolchain.toml .
RUN rustup show
ARG TARGETARCH
RUN case "${TARGETARCH}" in \
        amd64) target="x86_64-unknown-linux-musl" ;; \
        arm64) target="aarch64-unknown-linux-musl" ;; \
        *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    echo "${target}" > /tmp/rust-target && \
    rustup target add "${target}"

FROM base-builder AS builder

# Prefetch Rust dependencies for better Docker layer caching.
COPY Cargo.toml Cargo.lock ./
COPY README.md ./
COPY cli/Cargo.toml cli/
COPY compiler/config/Cargo.toml compiler/config/
COPY compiler/Cargo.toml compiler/
COPY runtime/docker-gateway/Cargo.toml runtime/docker-gateway/
COPY runtime/helper/Cargo.toml runtime/helper/
COPY images/Cargo.toml images/
COPY compiler/json5/Cargo.toml compiler/json5/
COPY compiler/manifest/Cargo.toml compiler/manifest/
COPY runtime/mesh/Cargo.toml runtime/mesh/
COPY runtime/proxy/Cargo.toml runtime/proxy/
COPY runtime/router/Cargo.toml runtime/router/
COPY compiler/resolver/Cargo.toml compiler/resolver/
COPY compiler/scenario/Cargo.toml compiler/scenario/
COPY compiler/template/Cargo.toml compiler/template/
COPY node/Cargo.toml node/
COPY runtime/provisioner/Cargo.toml runtime/provisioner/

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    mkdir -p cli/src compiler/config/src compiler/src runtime/docker-gateway/src runtime/helper/src images/src compiler/json5/src compiler/manifest/src runtime/mesh/src runtime/proxy/src runtime/router/src compiler/resolver/src compiler/scenario/src compiler/template/src node/src runtime/provisioner/src && \
    touch cli/src/main.rs compiler/config/src/lib.rs compiler/src/lib.rs runtime/docker-gateway/src/main.rs runtime/helper/src/main.rs images/src/lib.rs compiler/json5/src/lib.rs compiler/manifest/src/lib.rs runtime/mesh/src/lib.rs runtime/proxy/src/lib.rs runtime/router/src/main.rs compiler/resolver/src/lib.rs compiler/scenario/src/lib.rs compiler/template/src/lib.rs node/src/main.rs runtime/provisioner/src/main.rs && \
    cargo fetch --locked

COPY cli ./cli
COPY compiler ./compiler
COPY examples ./examples
COPY images ./images
COPY runtime/mesh ./runtime/mesh
COPY runtime/proxy ./runtime/proxy
COPY runtime/router ./runtime/router
COPY docker/images.json docker/images.json

ARG BUILD_MODE=release
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    target=$(cat /tmp/rust-target) && \
    if [ "$BUILD_MODE" = "release" ]; then \
      cargo build --locked --release -p amber-cli --target "${target}"; \
      build_dir=release; \
    else \
      cargo build --locked -p amber-cli --target "${target}"; \
      build_dir=debug; \
    fi && \
    install -D -m 0755 /app/target/"${target}"/"${build_dir}"/amber /out/amber && \
    install -d -m 0755 /out/workdir

FROM gcr.io/distroless/static-debian13 AS runtime

COPY --from=builder --chown=65532:65532 /out/workdir /app
COPY --from=builder --chown=65532:65532 /out/amber /amber

USER 65532:65532
WORKDIR /app
ENTRYPOINT ["/amber"]
