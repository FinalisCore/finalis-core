#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
STAGE_DIR="${STAGE_DIR:-/tmp/finalis-wallet-stage}"
RELEASE_DIR="${RELEASE_DIR:-$BUILD_DIR/release}"
PACKAGE_VERSION="${PACKAGE_VERSION:-0.1.0}"
RELEASE_SIGNING_KEY="${RELEASE_SIGNING_KEY:-}"
RELEASE_SIGNING_PUBKEY="${RELEASE_SIGNING_PUBKEY:-}"

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

sign_file() {
  local path="$1"
  local out="$2"
  openssl dgst -sha256 -sign "$RELEASE_SIGNING_KEY" -out "$out" "$path"
}

cmake -S "$ROOT" -B "$BUILD_DIR"
build_targets=(
  finalis-node
  finalis-cli
  finalis-lightserver
  finalis-explorer
  finalis-wallet
)
cmake --build "$BUILD_DIR" --target "${build_targets[@]}" -j1
cmake --install "$BUILD_DIR" --prefix "$STAGE_DIR"

(
  cd "$BUILD_DIR"
  cpack -G TGZ
  cpack -G ZIP
)

mkdir -p "$RELEASE_DIR"

TGZ_PATH="$BUILD_DIR/finalis-wallet-${PACKAGE_VERSION}-Linux.tar.gz"
ZIP_PATH="$BUILD_DIR/finalis-wallet-${PACKAGE_VERSION}-Linux.zip"

cp "$TGZ_PATH" "$RELEASE_DIR/"
cp "$ZIP_PATH" "$RELEASE_DIR/"
if [[ -f "$ROOT/docs/REFERENCE_WALLET_RELEASE_NOTES_TEMPLATE.md" ]]; then
  cp "$ROOT/docs/REFERENCE_WALLET_RELEASE_NOTES_TEMPLATE.md" "$RELEASE_DIR/RELEASE_NOTES.md"
else
  cat >"$RELEASE_DIR/RELEASE_NOTES.md" <<EOF
# finalis-wallet ${PACKAGE_VERSION}

Artifacts:

- $(basename "$TGZ_PATH")
- $(basename "$ZIP_PATH")

Installed docs:

- README.md
- FINALIS_WALLET_API_V1.md
- PROTOCOL-SPEC.md
EOF
fi

TGZ_BASENAME="$(basename "$TGZ_PATH")"
ZIP_BASENAME="$(basename "$ZIP_PATH")"
TGZ_SHA="$(sha256_file "$TGZ_PATH")"
ZIP_SHA="$(sha256_file "$ZIP_PATH")"

cat >"$RELEASE_DIR/SHA256SUMS.txt" <<EOF
${TGZ_SHA}  ${TGZ_BASENAME}
${ZIP_SHA}  ${ZIP_BASENAME}
EOF

cat >"$RELEASE_DIR/manifest.txt" <<EOF
finalis-wallet release
version: ${PACKAGE_VERSION}
generated_from: ${ROOT}
stage_dir: ${STAGE_DIR}
artifacts:
- ${TGZ_BASENAME}
  sha256: ${TGZ_SHA}
- ${ZIP_BASENAME}
  sha256: ${ZIP_SHA}
EOF

if [[ -n "$RELEASE_SIGNING_KEY" ]]; then
  if [[ ! -f "$RELEASE_SIGNING_KEY" ]]; then
    echo "release signing key not found: $RELEASE_SIGNING_KEY" >&2
    exit 1
  fi
  if ! have openssl; then
    echo "openssl is required for release signing" >&2
    exit 1
  fi
  sign_file "$RELEASE_DIR/SHA256SUMS.txt" "$RELEASE_DIR/SHA256SUMS.txt.sig"
  sign_file "$RELEASE_DIR/manifest.txt" "$RELEASE_DIR/manifest.txt.sig"
  if [[ -n "$RELEASE_SIGNING_PUBKEY" && -f "$RELEASE_SIGNING_PUBKEY" ]]; then
    cp "$RELEASE_SIGNING_PUBKEY" "$RELEASE_DIR/"
  fi
fi

echo "staged wallet install: $STAGE_DIR"
echo "release artifacts: $RELEASE_DIR"
