#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Install a Finalis testnet node from the prebuilt Linux tarball and run it under systemd.
#
#   curl -fsSL https://raw.githubusercontent.com/FinalisCore/finalis-core/main/scripts/install.sh | bash
#
# Needs: x86_64 or aarch64 Linux with systemd and glibc >= 2.39 (Ubuntu 24.04+, Debian 13+,
# Fedora 40+, Arch). Older systems: use the Docker image (testnet/JOIN.md).
#
# Environment:
#   FINALIS_RELEASE    release tag to install (default: newest tagged release with Linux
#                      packages, else the main-latest-linux pre-release)
#   FINALIS_TARBALL    install from this local tarball instead of downloading
#   FINALIS_NO_START=1 install without enabling and starting the service
#
# Re-running upgrades the binaries in place; chain data and keys are kept.

set -euo pipefail

REPO="FinalisCore/finalis-core"
OPT_DIR=/opt/finalis-core
DATA_DIR=/var/lib/finalis
SERVICE=finalis-testnet
UNIT_PATH="/etc/systemd/system/${SERVICE}.service"

log() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Linux" ]] || die "Linux only. On Windows use the installer from the releases page."
command -v systemctl >/dev/null || die "systemd not found. Use the Docker image instead (testnet/JOIN.md)."
command -v curl >/dev/null || die "curl is required."
command -v sha256sum >/dev/null || die "sha256sum is required."

case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) die "unsupported CPU architecture $(uname -m) (need x86_64 or aarch64)." ;;
esac

glibc="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')"
if [[ -z "${glibc}" ]] || [[ "$(printf '%s\n2.39\n' "${glibc}" | sort -V | head -n1)" != "2.39" ]]; then
  die "glibc ${glibc:-unknown} is older than 2.39. Use the Docker image instead (testnet/JOIN.md)."
fi

# scripts/start.sh installs a unit of the same name that runs from a source checkout with its data
# in the user's home. Replacing it would silently start a new chain copy with a new validator key.
if [[ -f "${UNIT_PATH}" ]] && ! grep -q "^Description=Finalis testnet node$" "${UNIT_PATH}"; then
  die "${UNIT_PATH} was installed by scripts/start.sh. Keep updating that node with start.sh, or
remove it first (sudo systemctl disable --now ${SERVICE}; sudo rm ${UNIT_PATH})."
fi

SUDO=""
if [[ ${EUID} -ne 0 ]]; then
  command -v sudo >/dev/null || die "run as root or install sudo."
  SUDO="sudo"
fi

ASSET="finalis-core-linux-${ARCH}.tar.gz"
SUMS="SHA256SUMS-linux.txt"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }

if [[ -n "${FINALIS_TARBALL:-}" ]]; then
  log "Using local tarball ${FINALIS_TARBALL}"
  cp "${FINALIS_TARBALL}" "${WORK}/${ASSET}"
else
  if [[ -n "${FINALIS_RELEASE:-}" ]]; then
    bases=("https://github.com/${REPO}/releases/download/${FINALIS_RELEASE}")
  else
    bases=("https://github.com/${REPO}/releases/latest/download"
           "https://github.com/${REPO}/releases/download/main-latest-linux")
  fi
  got=""
  for base in "${bases[@]}"; do
    if fetch "${base}/${SUMS}" "${WORK}/${SUMS}" 2>/dev/null; then
      log "Downloading ${base}/${ASSET}"
      fetch "${base}/${ASSET}" "${WORK}/${ASSET}"
      got=1
      break
    fi
  done
  [[ -n "${got}" ]] || die "no Linux release found on github.com/${REPO}/releases."
  log "Verifying checksum"
  (cd "${WORK}" && grep " ${ASSET}\$" "${SUMS}" | sha256sum -c --quiet -) || die "checksum mismatch for ${ASSET}."
fi

tar -C "${WORK}" -xzf "${WORK}/${ASSET}"
PKG="${WORK}/finalis-core"
[[ -x "${PKG}/bin/finalis-node" ]] || die "tarball does not contain bin/finalis-node."
"${PKG}/bin/finalis-cli" --testnet genesis_print_embedded >/dev/null \
  || die "the binaries do not run on this system. Use the Docker image instead (testnet/JOIN.md)."
[[ -f "${PKG}/VERSION" ]] && log "Version: $(cat "${PKG}/VERSION")"

if ! id -u finalis >/dev/null 2>&1; then
  log "Creating system user 'finalis' (home ${DATA_DIR})"
  ${SUDO} useradd --system --home-dir "${DATA_DIR}" --shell /usr/sbin/nologin finalis
fi
${SUDO} install -d -o finalis -g finalis -m 0700 "${DATA_DIR}"

was_active=""
if ${SUDO} systemctl is-active --quiet "${SERVICE}"; then
  was_active=1
  log "Stopping ${SERVICE} for the upgrade"
  ${SUDO} systemctl stop "${SERVICE}"
fi

log "Installing to ${OPT_DIR}"
${SUDO} rm -rf "${OPT_DIR}.new"
${SUDO} cp -a "${PKG}" "${OPT_DIR}.new"
${SUDO} chown -R root:root "${OPT_DIR}.new"
${SUDO} rm -rf "${OPT_DIR}.old"
[[ -d "${OPT_DIR}" ]] && ${SUDO} mv "${OPT_DIR}" "${OPT_DIR}.old"
${SUDO} mv "${OPT_DIR}.new" "${OPT_DIR}"
${SUDO} rm -rf "${OPT_DIR}.old"
for b in finalis-node finalis-lightserver finalis-cli finalis-explorer; do
  ${SUDO} ln -sf "${OPT_DIR}/bin/${b}" "/usr/local/bin/${b}"
done

# Testnet unit from the packaged mainnet unit: same hardening, testnet network, ports and paths.
# The data directory is the default ~/.finalis/testnet of the finalis user, so
# `sudo -u finalis -H finalis-cli --testnet ...` finds the node's state and key without --db.
log "Writing ${UNIT_PATH}"
sed -e "s|^Description=.*|Description=Finalis testnet node|" \
    -e "s|^Environment=\"FINALIS_HOME=.*|Environment=\"HOME=${DATA_DIR}\"|" \
    -e "s|--db \${FINALIS_HOME}/mainnet|--testnet|" \
    -e "/--genesis \/opt\/finalis-core\/mainnet\/genesis.bin/d" \
    -e "s|--port 19440|--port 19540|" \
    -e "s|--lightserver-port 19444|--lightserver-port 19544|" \
    -e "s|^RuntimeDirectory=finalis/mainnet|RuntimeDirectory=finalis/testnet|" \
    -e "s|/run/finalis/mainnet/|/run/finalis/testnet/|" \
    -e "s|^ReadWritePaths=.*|ReadWritePaths=${DATA_DIR}|" \
    -e "s|^WorkingDirectory=.*|WorkingDirectory=${DATA_DIR}|" \
    "${PKG}/packaging/finalis-node.service" > "${WORK}/unit"
for want in "--testnet" "--port 19540" "--lightserver-port 19544" "RuntimeDirectory=finalis/testnet" "HOME=${DATA_DIR}"; do
  grep -q -- "${want}" "${WORK}/unit" || die "generated unit is missing '${want}'; please report this."
done
! grep -qE "mainnet|19440|19444" "${WORK}/unit" || die "generated unit still references mainnet; please report this."
${SUDO} install -m 0644 "${WORK}/unit" "${UNIT_PATH}"
${SUDO} systemctl daemon-reload

if [[ "${FINALIS_NO_START:-0}" == "1" ]]; then
  log "Installed. Start with: sudo systemctl enable --now ${SERVICE}"
  exit 0
fi

if [[ -n "${was_active}" ]]; then
  ${SUDO} systemctl start "${SERVICE}"
else
  ${SUDO} systemctl enable --now "${SERVICE}"
fi

cat <<EOF

Finalis testnet node is running (service: ${SERVICE}).

  Logs:        journalctl -u ${SERVICE} -f
  Status:      curl -s http://127.0.0.1:19544/rpc -d '{"jsonrpc":"2.0","id":1,"method":"get_status","params":{}}'
  CLI:         sudo -u finalis -H finalis-cli --testnet getBalance
  Upgrade:     re-run this installer

Help the network: open TCP port 19540 in your firewall so other nodes can connect.
Become a validator: https://github.com/${REPO}/blob/main/testnet/JOIN.md#4-become-a-validator
EOF
