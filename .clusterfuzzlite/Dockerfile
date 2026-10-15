# ClusterFuzzLite build image for the libFuzzer targets in fuzz/ (see build.sh).
FROM gcr.io/oss-fuzz-base/base-builder:v1
RUN apt-get update && apt-get install -y --no-install-recommends \
      ninja-build pkg-config libssl-dev libsodium-dev \
    && pip3 install --no-cache-dir cmake==3.31.6
# The base image's Ubuntu 20.04 nlohmann-json (3.7) predates ordered_json: use the 3.11.3 release header.
RUN mkdir -p /usr/local/include/nlohmann \
    && curl -fsSL -o /usr/local/include/nlohmann/json.hpp \
         https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp \
    && echo "9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6  /usr/local/include/nlohmann/json.hpp" \
         | sha256sum -c -
COPY . $SRC/finalis-core
WORKDIR $SRC/finalis-core
COPY .clusterfuzzlite/build.sh $SRC/
