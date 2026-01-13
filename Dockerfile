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
COPY compose-helper/Cargo.toml compose-helper/
COPY json5/Cargo.toml json5/
COPY manifest/Cargo.toml manifest/
COPY resolver/Cargo.toml resolver/
COPY scenario/Cargo.toml scenario/
COPY template/Cargo.toml template/
COPY node/Cargo.toml node/

RUN mkdir -p cli/src compiler/src compose-helper/src json5/src manifest/src resolver/src scenario/src template/src node/src && \
    touch cli/src/main.rs compiler/src/lib.rs compose-helper/src/main.rs json5/src/lib.rs manifest/src/lib.rs resolver/src/lib.rs scenario/src/lib.rs template/src/lib.rs node/src/main.rs
RUN cargo fetch --locked
RUN rm -rf cli/src compiler/src compose-helper/src json5/src manifest/src resolver/src scenario/src template/src node/src

COPY cli ./cli
COPY compiler ./compiler
COPY compose-helper ./compose-helper
COPY json5 ./json5
COPY manifest ./manifest
COPY resolver ./resolver
COPY scenario ./scenario
COPY template ./template
COPY node ./node

ARG BUILD_MODE=release
RUN if [ "$BUILD_MODE" = "release" ]; then \
      cargo build --locked --release -p amber-cli; \
    else \
      cargo build -p amber-cli; \
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
COPY --from=builder --chown=${USERNAME}:${USERNAME} /app/target/${BUILD_MODE}/amber /usr/local/bin/amber

USER ${USERNAME}
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/amber"]
