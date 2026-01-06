FROM rust:1.91-slim-trixie AS base-builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    g++ \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY rust-toolchain.toml .
RUN rustup show

FROM base-builder AS builder

# Prefetch Rust dependencies for better Docker layer caching.
COPY Cargo.toml Cargo.lock ./
COPY cli/Cargo.toml cli/
COPY compiler/Cargo.toml compiler/
COPY json5/Cargo.toml json5/
COPY manifest/Cargo.toml manifest/
COPY resolver/Cargo.toml resolver/
COPY scenario/Cargo.toml scenario/
COPY node/Cargo.toml node/

RUN mkdir -p cli/src compiler/src json5/src manifest/src resolver/src scenario/src node/src && \
    touch cli/src/main.rs compiler/src/lib.rs json5/src/lib.rs manifest/src/lib.rs resolver/src/lib.rs scenario/src/lib.rs node/src/main.rs
RUN cargo fetch --locked
RUN rm -rf cli/src compiler/src json5/src manifest/src resolver/src scenario/src node/src

COPY cli ./cli
COPY compiler ./compiler
COPY json5 ./json5
COPY manifest ./manifest
COPY resolver ./resolver
COPY scenario ./scenario
COPY node ./node

ARG BUILD_MODE=release
RUN if [ "$BUILD_MODE" = "release" ]; then \
      cargo build --locked --release -p amber-node; \
    else \
      cargo build -p amber-node; \
    fi

FROM debian:13-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tini \
    && rm -rf /var/lib/apt/lists/*

ARG USERNAME=amber
ARG USER_UID=1001
ARG USER_GID=${USER_UID}
RUN groupadd --gid ${USER_GID} ${USERNAME} && \
    useradd --uid ${USER_UID} --gid ${USER_GID} --shell /bin/false --create-home ${USERNAME}

WORKDIR /home/${USERNAME}/app

ARG BUILD_MODE=release
COPY --from=builder --chown=${USERNAME}:${USERNAME} /app/target/${BUILD_MODE}/amber-node /usr/local/bin/node

USER ${USERNAME}
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/node"]
