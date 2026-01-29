FROM rust:1.91-slim-trixie AS base-builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    g++ \
    musl-tools \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

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
COPY cli/Cargo.toml cli/
COPY config/Cargo.toml config/
COPY compiler/Cargo.toml compiler/
COPY helper/Cargo.toml helper/
COPY json5/Cargo.toml json5/
COPY manifest/Cargo.toml manifest/
COPY resolver/Cargo.toml resolver/
COPY scenario/Cargo.toml scenario/
COPY template/Cargo.toml template/
COPY node/Cargo.toml node/

RUN mkdir -p cli/src config/src compiler/src helper/src json5/src manifest/src resolver/src scenario/src template/src node/src && \
    touch cli/src/main.rs config/src/lib.rs compiler/src/lib.rs helper/src/main.rs json5/src/lib.rs manifest/src/lib.rs resolver/src/lib.rs scenario/src/lib.rs template/src/lib.rs node/src/main.rs
RUN cargo fetch --locked
RUN rm -rf cli/src config/src compiler/src helper/src json5/src manifest/src resolver/src scenario/src template/src node/src

COPY cli ./cli
COPY config ./config
COPY compiler ./compiler
COPY helper ./helper
COPY json5 ./json5
COPY manifest ./manifest
COPY resolver ./resolver
COPY scenario ./scenario
COPY template ./template
COPY node ./node

ARG BUILD_MODE=release
RUN target=$(cat /tmp/rust-target) && \
    if [ "$BUILD_MODE" = "release" ]; then \
      cargo build --locked --release -p amber-cli --target "${target}"; \
      build_dir=release; \
    else \
      cargo build -p amber-cli --target "${target}"; \
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
