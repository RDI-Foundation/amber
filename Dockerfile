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
COPY manifest/Cargo.toml manifest/
COPY node/Cargo.toml node/

RUN mkdir -p manifest/src node/src && \
    touch manifest/src/lib.rs manifest/src/main.rs node/src/main.rs
RUN cargo fetch --locked
RUN rm -rf manifest/src node/src

COPY manifest ./manifest
COPY node ./node

ARG BUILD_MODE=release
RUN if [ "$BUILD_MODE" = "release" ]; then \
      cargo build --locked --release -p node; \
    else \
      cargo build -p node; \
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
COPY --from=builder --chown=${USERNAME}:${USERNAME} /app/target/${BUILD_MODE}/node /usr/local/bin/node

USER ${USERNAME}
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/node"]
