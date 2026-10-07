# syntax=docker/dockerfile:1

# ---- Stage 1: builder -------------------------------------------------------
FROM ubuntu:24.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    pkg-config \
    libssl-dev \
    libsodium-dev \
    librocksdb-dev \
    nlohmann-json3-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

# FINALIS_BUILD_FUZZ/NGINX default ON upstream -- both irrelevant to a node
# runtime image (fuzz harnesses, a from-source nginx build) and meaningfully
# slow the image build. secp256k1-zkp is fetched via FetchContent+git at
# configure time (no vendored third_party/ copy in this tree), so this stage
# needs network access during `docker build`, same as a bare-metal
# `cmake -S .` would from a fresh checkout.
RUN cmake -S . -B build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DFINALIS_BUILD_FUZZ=OFF \
      -DFINALIS_BUILD_NGINX=OFF \
      -DFINALIS_GENERATE_NGINX_CONFIG=OFF \
    && cmake --build build --target finalis-node finalis-lightserver finalis-cli -j"$(nproc)"

# ---- Stage 2: runtime --------------------------------------------------------
FROM ubuntu:24.04 AS runtime
ENV DEBIAN_FRONTEND=noninteractive

# Runtime-only packages (no -dev headers, no compiler toolchain). apt resolves
# librocksdb's own transitive deps (gflags/snappy/zlib/bz2/lz4/zstd) automatically.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libsodium23 \
    librocksdb8.9 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /var/lib/finalis \
       --shell /usr/sbin/nologin finalis

COPY --from=builder /src/build/finalis-node /opt/finalis-core/bin/finalis-node
COPY --from=builder /src/build/finalis-cli  /opt/finalis-core/bin/finalis-cli
# --with-lightserver execs this as a sibling of finalis-node.
COPY --from=builder /src/build/finalis-lightserver /opt/finalis-core/bin/finalis-lightserver
COPY --from=builder /src/mainnet/genesis.bin /opt/finalis-core/mainnet/genesis.bin
COPY --from=builder /src/mainnet/SEEDS.json  /opt/finalis-core/mainnet/SEEDS.json

ENV PATH="/opt/finalis-core/bin:${PATH}"
# Steps 1-3 RocksDB tuning env vars are read directly from the process
# environment by src/storage/db.cpp's env_u64_or_default() calls -- nothing
# Dockerfile-side needed beyond letting docker-compose's `environment:` block
# set them per container. Documented defaults here for a single-container run:
ENV FINALIS_DB_PARALLELISM=4 \
    FINALIS_DB_MEMTABLE_BUDGET_MB=256 \
    FINALIS_DB_RATE_LIMITER_BYTES_S=67108864 \
    FINALIS_DB_DELAYED_WRITE_RATE_BYTES_S=33554432

# /run/finalis holds the lightserver admin socket (default /var/run/finalis/admin.sock, and
# /var/run -> /run); the non-root runtime user cannot create it itself.
RUN mkdir -p /var/lib/finalis/keystore /var/lib/finalis/logs /run/finalis \
    && chown -R finalis:finalis /var/lib/finalis /opt/finalis-core /run/finalis \
    && chmod 0700 /run/finalis

USER finalis
WORKDIR /var/lib/finalis
VOLUME ["/var/lib/finalis"]
EXPOSE 19440 19444

# The validator keystore is created/unlocked with the passphrase in FINALIS_VALIDATOR_PASSPHRASE
# (docker run -e FINALIS_VALIDATOR_PASSPHRASE=...); the node refuses to create an unencrypted one.
ENTRYPOINT ["finalis-node"]
CMD ["--db", "/var/lib/finalis/db", "--genesis", "/opt/finalis-core/mainnet/genesis.bin", \
     "--allow-unsafe-genesis-override", \
     "--validator-key-file", "/var/lib/finalis/keystore/validator.json", \
     "--validator-passphrase-env", "FINALIS_VALIDATOR_PASSPHRASE", \
     "--listen", "--bind", "0.0.0.0", "--port", "19440", \
     "--with-lightserver", "--lightserver-bind", "0.0.0.0", "--lightserver-port", "19444", \
     "--no-dns-seeds"]
