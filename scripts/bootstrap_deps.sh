#!/usr/bin/env bash
set -euo pipefail

WITH_WALLET=1

usage() {
  cat <<'EOF'
usage: ./scripts/bootstrap_deps.sh [--no-wallet]

Installs the build dependencies required by Finalis Core on supported
package-managed systems. By default this includes Qt5 packages so the
`finalis-wallet` target can be built as well.

Options:
  --no-wallet   Skip Qt5 wallet dependencies and install only node/CLI deps.
  -h, --help    Show this help text.
EOF
}

log() {
  printf '[bootstrap-deps] %s\n' "$*"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

need_sudo() {
  if [[ "${EUID}" -eq 0 ]]; then
    return 0
  fi
  if ! have sudo; then
    log "sudo is required to install packages."
    exit 1
  fi
}

pkg_missing_deb() {
  local pkg
  for pkg in "$@"; do
    if ! dpkg-query -W -f='${Status}\n' "${pkg}" 2>/dev/null | grep -q "install ok installed"; then
      printf '%s\n' "${pkg}"
    fi
  done
}

pkg_missing_rpm() {
  local pkg
  for pkg in "$@"; do
    if ! rpm -q "${pkg}" >/dev/null 2>&1; then
      printf '%s\n' "${pkg}"
    fi
  done
}

pkg_missing_pacman() {
  local pkg
  for pkg in "$@"; do
    if ! pacman -Q "${pkg}" >/dev/null 2>&1; then
      printf '%s\n' "${pkg}"
    fi
  done
}

install_apt() {
  local packages=(
    build-essential
    cmake
    pkg-config
    ninja-build
    python3
    libssl-dev
    libsodium-dev
    librocksdb-dev
  )
  if [[ "${WITH_WALLET}" == "1" ]]; then
    packages+=(qtbase5-dev qtbase5-dev-tools)
  fi

  mapfile -t missing < <(pkg_missing_deb "${packages[@]}")
  if [[ "${#missing[@]}" -eq 0 ]]; then
    log "APT dependencies already installed."
    return 0
  fi

  need_sudo
  log "Installing missing APT packages: ${missing[*]}"
  sudo apt-get update
  sudo apt-get install -y "${missing[@]}"
}

install_dnf() {
  local packages=(
    gcc-c++
    make
    cmake
    pkgconf-pkg-config
    ninja-build
    python3
    openssl-devel
    libsodium-devel
    rocksdb-devel
  )
  if [[ "${WITH_WALLET}" == "1" ]]; then
    packages+=(qt5-qtbase-devel)
  fi

  mapfile -t missing < <(pkg_missing_rpm "${packages[@]}")
  if [[ "${#missing[@]}" -eq 0 ]]; then
    log "DNF dependencies already installed."
    return 0
  fi

  need_sudo
  log "Installing missing DNF packages: ${missing[*]}"
  sudo dnf install -y "${missing[@]}"
}

install_pacman() {
  local packages=(
    base-devel
    cmake
    pkgconf
    ninja
    python
    openssl
    libsodium
    rocksdb
  )
  if [[ "${WITH_WALLET}" == "1" ]]; then
    packages+=(qt5-base)
  fi

  mapfile -t missing < <(pkg_missing_pacman "${packages[@]}")
  if [[ "${#missing[@]}" -eq 0 ]]; then
    log "Pacman dependencies already installed."
    return 0
  fi

  need_sudo
  log "Installing missing pacman packages: ${missing[*]}"
  sudo pacman -Sy --noconfirm "${missing[@]}"
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --no-wallet)
        WITH_WALLET=0
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        log "Unknown argument: $1"
        usage
        exit 1
        ;;
    esac
  done

  local os
  os="$(uname -s)"
  case "${os}" in
    Linux)
      if have apt-get; then
        install_apt
      elif have dnf; then
        install_dnf
      elif have pacman; then
        install_pacman
      else
        log "Unsupported Linux package manager."
        log "Install a C++20 toolchain, CMake >= 3.20, pkg-config, OpenSSL dev, libsodium dev, RocksDB dev, and Qt5 Widgets dev."
        exit 1
      fi
      ;;
    *)
      log "Unsupported OS: ${os}"
      log "Install a C++20 toolchain, CMake >= 3.20, pkg-config, OpenSSL dev, libsodium dev, RocksDB dev, and Qt5 Widgets dev."
      exit 1
      ;;
  esac

  if [[ "${WITH_WALLET}" == "1" ]]; then
    log "Dependency bootstrap complete. Wallet-capable build deps are installed."
  else
    log "Dependency bootstrap complete. Node/CLI/lightserver build deps are installed."
  fi
}

main "$@"
