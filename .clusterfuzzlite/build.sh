#!/bin/bash -eu
# SPDX-License-Identifier: MIT
# ClusterFuzzLite / OSS-Fuzz build. CC, CXX, CFLAGS, CXXFLAGS (sanitizer and coverage flags) and
# LIB_FUZZING_ENGINE come from the base-builder image. libsodium and OpenSSL are linked statically:
# the runner image does not ship them. RocksDB is left out (storage falls back to its file backend).

cmake -S . -B build-fuzz -G Ninja \
  -DCMAKE_BUILD_TYPE= \
  -DFINALIS_LIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE" \
  -DFINALIS_BUILD_NGINX=OFF \
  -DFINALIS_GENERATE_NGINX_CONFIG=OFF \
  -DOPENSSL_USE_STATIC_LIBS=TRUE \
  -DSODIUM_LIB=/usr/lib/x86_64-linux-gnu/libsodium.a

targets="fuzz_p2p_frame fuzz_tx_parse fuzz_consensus_msgs fuzz_consensus_node fuzz_smt fuzz_confidential
  fuzz_wire_codecs fuzz_sync"
cmake --build build-fuzz -j"$(nproc)" --target $targets
for target in $targets; do
  cp "build-fuzz/$target" "$OUT/"
  if [[ -f "fuzz/$target.dict" ]]; then cp "fuzz/$target.dict" "$OUT/"; fi
  # Minimized corpora (libFuzzer -merge=1 of earlier runs); the engine starts from them.
  if [[ -f "fuzz/seed_corpus/$target.zip" ]]; then cp "fuzz/seed_corpus/$target.zip" "$OUT/${target}_seed_corpus.zip"; fi
done
