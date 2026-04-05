#!/usr/bin/env bash
set -euo pipefail

RELEASE_DIR="${1:-./build/release}"
PUBKEY="${2:-}"

have() {
  command -v "$1" >/dev/null 2>&1
}

sha256_file() {
  local path="$1"
  if have sha256sum; then
    sha256sum "${path}" | awk '{print $1}'
  elif have shasum; then
    shasum -a 256 "${path}" | awk '{print $1}'
  elif have openssl; then
    openssl dgst -sha256 "${path}" | awk '{print $NF}'
  else
    echo "sha256-unavailable"
  fi
}

test -d "$RELEASE_DIR"
test -f "$RELEASE_DIR/SHA256SUMS.txt"
test -f "$RELEASE_DIR/manifest.txt"

while read -r checksum filename; do
  [[ -z "${checksum}" ]] && continue
  actual="$(sha256_file "$RELEASE_DIR/$filename")"
  if [[ "$checksum" != "$actual" ]]; then
    echo "checksum mismatch: $filename" >&2
    exit 1
  fi
done < "$RELEASE_DIR/SHA256SUMS.txt"

if [[ -n "$PUBKEY" ]]; then
  test -f "$PUBKEY"
  test -f "$RELEASE_DIR/SHA256SUMS.txt.sig"
  test -f "$RELEASE_DIR/manifest.txt.sig"
  openssl dgst -sha256 -verify "$PUBKEY" -signature "$RELEASE_DIR/SHA256SUMS.txt.sig" "$RELEASE_DIR/SHA256SUMS.txt"
  openssl dgst -sha256 -verify "$PUBKEY" -signature "$RELEASE_DIR/manifest.txt.sig" "$RELEASE_DIR/manifest.txt"
fi

echo "release verified: $RELEASE_DIR"
