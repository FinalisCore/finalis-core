#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-./wallet-release-key}"

mkdir -p "$OUT_DIR"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$OUT_DIR/release-private.pem"
openssl rsa -pubout -in "$OUT_DIR/release-private.pem" -out "$OUT_DIR/release-public.pem"

echo "generated:"
echo "  private: $OUT_DIR/release-private.pem"
echo "  public:  $OUT_DIR/release-public.pem"
