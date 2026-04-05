FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    pkg-config \
    libssl-dev \
    libsodium-dev \
    librocksdb-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

RUN cmake -S . -B build && cmake --build build -j"$(nproc)"

ENV SC_DB=/data/node
VOLUME ["/data"]

ENTRYPOINT ["/src/build/finalis-node"]
