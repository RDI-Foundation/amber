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
COPY images/Cargo.toml images/
COPY json5/Cargo.toml json5/
COPY manifest/Cargo.toml manifest/
COPY mesh/Cargo.toml mesh/
COPY router/Cargo.toml router/
COPY resolver/Cargo.toml resolver/
COPY scenario/Cargo.toml scenario/
COPY template/Cargo.toml template/
COPY node/Cargo.toml node/

RUN mkdir -p cli/src config/src compiler/src helper/src images/src json5/src manifest/src mesh/src router/src resolver/src scenario/src template/src node/src && \
    touch cli/src/main.rs config/src/lib.rs compiler/src/lib.rs helper/src/main.rs images/src/lib.rs json5/src/lib.rs manifest/src/lib.rs mesh/src/lib.rs router/src/main.rs resolver/src/lib.rs scenario/src/lib.rs template/src/lib.rs node/src/main.rs
RUN cargo fetch --locked
RUN rm -rf cli/src config/src compiler/src helper/src images/src json5/src manifest/src router/src resolver/src scenario/src template/src node/src

COPY cli ./cli
COPY config ./config
COPY compiler ./compiler
COPY helper ./helper
COPY images ./images
COPY json5 ./json5
COPY manifest ./manifest
COPY mesh ./mesh
COPY router ./router
COPY resolver ./resolver
COPY scenario ./scenario
COPY template ./template
COPY node ./node
COPY docker/images.json docker/images.json

RUN target=$(cat /tmp/rust-target) && \
    cargo build -p amber-router --release --locked --target "${target}" && \
    install -D -m 0755 /app/target/"${target}"/release/amber-router /out/amber-router

FROM gcr.io/distroless/static-debian13 AS runtime

COPY --from=builder /out/amber-router /amber-router

USER 65532:65532
ENTRYPOINT ["/amber-router"]
