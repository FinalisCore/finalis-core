#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-build}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
GENERATOR="${GENERATOR:-}"
BUILD_JOBS="${BUILD_JOBS:-}"
RUN_TESTS="${RUN_TESTS:-0}"
CLEAN_ON_GENERATOR_MISMATCH="${CLEAN_ON_GENERATOR_MISMATCH:-1}"
INSTALL_DEPS="${INSTALL_DEPS:-1}"
RESET_CHAIN_DATA="${RESET_CHAIN_DATA:-0}"
SETUP_NODE_SERVICE="${SETUP_NODE_SERVICE:-1}"
OPEN_FIREWALL_PORTS="${OPEN_FIREWALL_PORTS:-1}"
SERVICE_NAME="${SERVICE_NAME:-finalis}"
SERVICE_USER="${SERVICE_USER:-${SUDO_USER:-$USER}}"
DB_DIR="${DB_DIR:-$HOME/.finalis/mainnet}"
P2P_PORT="${P2P_PORT:-19440}"
LIGHTSERVER_PORT="${LIGHTSERVER_PORT:-19444}"
LIGHTSERVER_BIND="${LIGHTSERVER_BIND:-0.0.0.0}"
WITH_LIGHTSERVER="${WITH_LIGHTSERVER:-1}"
WITH_EXPLORER="${WITH_EXPLORER:-1}"
EXPLORER_PORT="${EXPLORER_PORT:-18080}"
EXPLORER_BIND="${EXPLORER_BIND:-0.0.0.0}"
EXPLORER_RPC_URL="${EXPLORER_RPC_URL:-http://127.0.0.1:${LIGHTSERVER_PORT}/rpc}"
PUBLIC_NODE="${PUBLIC_NODE:-1}"
OUTBOUND_TARGET="${OUTBOUND_TARGET:-8}"
HANDSHAKE_TIMEOUT_MS="${HANDSHAKE_TIMEOUT_MS:-30000}"
FRAME_TIMEOUT_MS="${FRAME_TIMEOUT_MS:-30000}"
IDLE_TIMEOUT_MS="${IDLE_TIMEOUT_MS:-600000}"
NODE_EXTRA_ARGS="${NODE_EXTRA_ARGS:-}"
USE_SEEDS_JSON="${USE_SEEDS_JSON:-1}"
GENESIS_BIN="${GENESIS_BIN:-}"
GENESIS_PATH="${GENESIS_PATH:-${GENESIS_BIN}}"
ALLOW_UNSAFE_GENESIS_OVERRIDE="${ALLOW_UNSAFE_GENESIS_OVERRIDE:-1}"
NODE_ROLE="${NODE_ROLE:-auto}"
RECOVER_PEER_DISCOVERY="${RECOVER_PEER_DISCOVERY:-0}"
TRUSTED_BOOTSTRAP_PEER="${TRUSTED_BOOTSTRAP_PEER:-}"
FOLLOW_RECOVERY_LOGS="${FOLLOW_RECOVERY_LOGS:-1}"
AUTO_FAST_SYNC="${AUTO_FAST_SYNC:-1}"
SNAPSHOT_FILE="${SNAPSHOT_FILE:-${ROOT_DIR}/snapshot.bin}"
AUTO_FAST_SYNC_FORCE_OVERWRITE="${AUTO_FAST_SYNC_FORCE_OVERWRITE:-0}"
SYNC_TURBO_MODE="${SYNC_TURBO_MODE:-0}"
SYNC_TARGET_UTIL_PCT="${SYNC_TARGET_UTIL_PCT:-70}"
FAST_SYNC_PRELOAD_CACHE="${FAST_SYNC_PRELOAD_CACHE:-0}"
NO_REINDEX_ON_START="${NO_REINDEX_ON_START:-1}"
AUTO_DEFERRED_EXIT_ACTIVATION_EXTREME="${AUTO_DEFERRED_EXIT_ACTIVATION_EXTREME:-0}"

log() { printf '[start] %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

APT_BUILD_PACKAGES=(
  build-essential
  cmake
  ninja-build
  pkg-config
  libssl-dev
  qtbase5-dev
  qtchooser
  qt5-qmake
  qtbase5-dev-tools
  libsodium-dev
  librocksdb-dev
  curl
  jq
)

run_bootstrap_deps_helper() {
  local helper="${ROOT_DIR}/scripts/bootstrap_deps.sh"
  if [[ ! -f "${helper}" ]]; then
    return 1
  fi

  log "Installing build dependencies via scripts/bootstrap_deps.sh"
  bash "${helper}"
}

listener_pids_on_port() {
  local port="$1"
  if have ss; then
    ss -ltnp "sport = :${port}" 2>/dev/null | grep -o "pid=[0-9]\+" | cut -d= -f2 | awk '!seen[$0]++'
    return 0
  fi
  if have lsof; then
    lsof -tiTCP:"${port}" -sTCP:LISTEN 2>/dev/null | awk '!seen[$0]++'
    return 0
  fi
}

detect_build_jobs() {
  if [[ -n "${BUILD_JOBS}" ]]; then
    echo "${BUILD_JOBS}"
    return
  fi

  if [[ -r /proc/meminfo ]]; then
    local mem_kb
    mem_kb="$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"
    if [[ -n "${mem_kb}" ]] && (( mem_kb <= 2097152 )); then
      echo "1"
      return
    fi
  fi

  if have nproc; then
    nproc
    return
  fi
  if have sysctl; then
    sysctl -n hw.ncpu 2>/dev/null || echo "1"
    return
  fi
  echo "1"
}

clamp_percent() {
  local pct="$1"
  if [[ -z "${pct}" ]]; then
    echo "70"
    return
  fi
  if (( pct < 30 )); then
    echo "30"
    return
  fi
  if (( pct > 90 )); then
    echo "90"
    return
  fi
  echo "${pct}"
}

auto_tune_sync_profile_if_requested() {
  if [[ "${SYNC_TURBO_MODE}" != "1" && "${SYNC_TURBO_MODE}" != "extreme" ]]; then
    return 0
  fi

  local cpu_cores
  cpu_cores="$(detect_build_jobs)"
  if [[ -z "${cpu_cores}" ]] || (( cpu_cores < 1 )); then
    cpu_cores=1
  fi
  local target_pct
  if [[ "${SYNC_TURBO_MODE}" == "extreme" ]]; then
    target_pct=100
  else
    target_pct="$(clamp_percent "${SYNC_TARGET_UTIL_PCT}")"
  fi

  if [[ -z "${BUILD_JOBS}" ]]; then
    BUILD_JOBS="$(( (cpu_cores * target_pct) / 100 ))"
    if (( BUILD_JOBS < 1 )); then BUILD_JOBS=1; fi
    if (( BUILD_JOBS > cpu_cores )); then BUILD_JOBS="${cpu_cores}"; fi
  fi

  if [[ "${OUTBOUND_TARGET}" == "8" ]]; then
    local tuned_outbound="$(( BUILD_JOBS * 2 ))"
    local outbound_cap=32
    if [[ "${SYNC_TURBO_MODE}" == "extreme" ]]; then
      outbound_cap=96
    fi
    if (( tuned_outbound < 8 )); then tuned_outbound=8; fi
    if (( tuned_outbound > outbound_cap )); then tuned_outbound=outbound_cap; fi
    OUTBOUND_TARGET="${tuned_outbound}"
  fi

  if [[ "${FAST_SYNC_PRELOAD_CACHE}" == "0" ]]; then
    FAST_SYNC_PRELOAD_CACHE="1"
  fi

  local mem_kb=0
  if [[ -r /proc/meminfo ]]; then
    mem_kb="$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"
  fi
  if [[ -z "${mem_kb}" || "${mem_kb}" == "0" ]]; then
    mem_kb=$((8 * 1024 * 1024))
  fi
  local mem_mb=$((mem_kb / 1024))
  local write_buffer_mb=$((mem_mb / 24))
  if (( write_buffer_mb < 128 )); then write_buffer_mb=128; fi
  if (( write_buffer_mb > 1024 )); then write_buffer_mb=1024; fi
  local max_write_buffers=$((cpu_cores / 2))
  if (( max_write_buffers < 4 )); then max_write_buffers=4; fi
  if (( max_write_buffers > 16 )); then max_write_buffers=16; fi
  local background_jobs="$cpu_cores"
  if (( background_jobs < 8 )); then background_jobs=8; fi
  if (( background_jobs > 64 )); then background_jobs=64; fi
  local target_file_mb=$((write_buffer_mb / 2))
  if (( target_file_mb < 64 )); then target_file_mb=64; fi
  if (( target_file_mb > 512 )); then target_file_mb=512; fi
  local import_batch_size=$((cpu_cores * 2048))
  if (( import_batch_size < 4096 )); then import_batch_size=4096; fi
  if (( import_batch_size > 65536 )); then import_batch_size=65536; fi

  export FINALIS_INGEST_MAX_BACKGROUND_JOBS="${background_jobs}"
  export FINALIS_INGEST_BYTES_PER_SYNC="1048576"
  export FINALIS_INGEST_WRITE_BUFFER_MB="${write_buffer_mb}"
  export FINALIS_INGEST_MAX_WRITE_BUFFERS="${max_write_buffers}"
  export FINALIS_INGEST_MIN_WRITE_BUFFERS_TO_MERGE="2"
  export FINALIS_INGEST_L0_COMPACTION_TRIGGER="8"
  export FINALIS_INGEST_TARGET_FILE_SIZE_MB="${target_file_mb}"
  export FINALIS_SNAPSHOT_IMPORT_BATCH_SIZE="${import_batch_size}"

  log "sync_telemetry cpu_cores=${cpu_cores} target_util_pct=${target_pct} chosen_build_jobs=${BUILD_JOBS} outbound_target=${OUTBOUND_TARGET}"
  log "sync_telemetry mem_mb=${mem_mb} ingest_bg_jobs=${FINALIS_INGEST_MAX_BACKGROUND_JOBS} ingest_write_buffer_mb=${FINALIS_INGEST_WRITE_BUFFER_MB} ingest_max_write_buffers=${FINALIS_INGEST_MAX_WRITE_BUFFERS} import_batch_size=${FINALIS_SNAPSHOT_IMPORT_BATCH_SIZE}"
  log "SYNC_TURBO_MODE=${SYNC_TURBO_MODE} active (target=${target_pct}%): BUILD_JOBS=${BUILD_JOBS}, OUTBOUND_TARGET=${OUTBOUND_TARGET}, FAST_SYNC_PRELOAD_CACHE=${FAST_SYNC_PRELOAD_CACHE}"
}

clear_build_dir() {
  local dir="$1"
  rm -rf "${dir}/CMakeCache.txt" "${dir}/CMakeFiles"
}

configure_cmake() {
  local args=("$@")
  local output
  if output="$(cmake "${args[@]}" 2>&1)"; then
    printf '%s\n' "${output}"
    return 0
  fi
  printf '%s\n' "${output}" >&2

  if [[ "${CLEAN_ON_GENERATOR_MISMATCH}" == "1" ]] && grep -q "Does not match the generator used previously" <<<"${output}"; then
    log "Detected CMake generator mismatch in ${BUILD_DIR}. Cleaning cache and retrying..."
    clear_build_dir "${BUILD_DIR}"
    cmake "${args[@]}"
    return $?
  fi
  return 1
}

need_sudo() {
  if [[ "${EUID}" -ne 0 ]]; then
    if have sudo; then
      echo "sudo"
    else
      log "Need root privileges but 'sudo' is not installed."
      exit 1
    fi
  else
    echo ""
  fi
}

systemd_available() {
  have systemctl && [[ -d /run/systemd/system ]]
}

open_firewall_ports() {
  local mode="$1"
  if [[ "${OPEN_FIREWALL_PORTS}" != "1" ]]; then
    log "Skipping firewall changes (OPEN_FIREWALL_PORTS=0)."
    return 0
  fi
  if [[ "${mode}" != "bootstrap" ]]; then
    log "Skipping firewall changes for joiner mode."
    return 0
  fi

  local s; s="$(need_sudo)"
  if have ufw; then
    log "Opening firewall ports with ufw: ${P2P_PORT}/tcp and ${LIGHTSERVER_PORT}/tcp."
    ${s} ufw allow "${P2P_PORT}/tcp" >/dev/null || true
    ${s} ufw allow "${LIGHTSERVER_PORT}/tcp" >/dev/null || true
    return 0
  fi
  if have firewall-cmd; then
    log "Opening firewall ports with firewalld: ${P2P_PORT}/tcp and ${LIGHTSERVER_PORT}/tcp."
    ${s} firewall-cmd --permanent --add-port="${P2P_PORT}/tcp" >/dev/null || true
    ${s} firewall-cmd --permanent --add-port="${LIGHTSERVER_PORT}/tcp" >/dev/null || true
    ${s} firewall-cmd --reload >/dev/null || true
    return 0
  fi

  log "No managed firewall command found (ufw/firewalld). Skipping firewall changes."
}

install_apt() {
  local -a missing=()
  local pkg
  for pkg in "${APT_BUILD_PACKAGES[@]}"; do
    if ! dpkg-query -W -f='${Status}\n' "${pkg}" 2>/dev/null | grep -q "install ok installed"; then
      missing+=("${pkg}")
    fi
  done

  if (( ${#missing[@]} == 0 )); then
    log "APT build/runtime packages already installed."
    return 0
  fi

  local s; s="$(need_sudo)"
  log "Installing missing APT packages: ${missing[*]}"
  ${s} apt update
  ${s} apt install -y "${missing[@]}"
}

install_dnf() {
  local s; s="$(need_sudo)"
  ${s} dnf install -y \
    gcc-c++ make cmake pkgconf-pkg-config ninja-build \
    openssl-devel libsodium-devel rocksdb-devel python3
}

install_pacman() {
  local s; s="$(need_sudo)"
  ${s} pacman -Sy --noconfirm \
    base-devel cmake pkgconf ninja \
    openssl libsodium rocksdb python
}

install_brew() {
  if ! have brew; then
    log "Homebrew not found. Install Homebrew first: https://brew.sh"
    exit 1
  fi
  brew install cmake pkg-config ninja openssl libsodium rocksdb
}

install_deps() {
  if [[ "${INSTALL_DEPS}" != "1" ]]; then
    log "Skipping dependency installation (INSTALL_DEPS=0)."
    return 0
  fi

  local os
  os="$(uname -s)"
  case "$os" in
    Linux)
      if have apt-get; then
        install_apt
      elif have dnf; then
        run_bootstrap_deps_helper || true
        install_dnf
      elif have pacman; then
        run_bootstrap_deps_helper || true
        install_pacman
      else
        log "Unsupported Linux package manager. Install manually:"
        log "  C++20 compiler, cmake>=3.20, pkg-config, OpenSSL dev, libsodium dev, RocksDB dev (optional)"
        exit 1
      fi
      ;;
    Darwin)
      install_brew
      ;;
    *)
      log "Unsupported OS: $os"
      exit 1
      ;;
  esac
}

configure_and_build() {
  cd "${ROOT_DIR}"
  local args=(-S . -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE="${BUILD_TYPE}")
  local jobs
  jobs="$(detect_build_jobs)"
  if [[ -n "${GENERATOR}" ]]; then
    args+=(-G "${GENERATOR}")
  elif have ninja; then
    args+=(-G Ninja)
  fi
  log "Configure command: cmake ${args[*]}"
  configure_cmake "${args[@]}"

  local -a targets=(finalis-node finalis-lightserver finalis-explorer finalis-cli)
  log "Build command: cmake --build ${BUILD_DIR} -j${jobs} --target ${targets[*]}"
  if ! cmake --build "${BUILD_DIR}" -j"${jobs}" --target "${targets[@]}"; then
    log "Build failed."
    log "Hint: if this is an OOM failure (cc1plus killed), retry with BUILD_JOBS=1"
    exit 1
  fi

  if [[ "${RUN_TESTS}" == "1" ]]; then
    ctest --test-dir "${BUILD_DIR}" --output-on-failure
  fi
}

read_seed_list() {
  local seeds_file="${ROOT_DIR}/mainnet/SEEDS.json"
  if [[ ! -f "${seeds_file}" ]]; then
    return 0
  fi
  python3 - "${seeds_file}" <<'PY'
import json, sys
p = sys.argv[1]
try:
    data = json.load(open(p, "r", encoding="utf-8"))
    for seed in data.get("seeds_p2p", []):
        if isinstance(seed, str):
            seed = seed.strip()
            if seed:
                print(seed)
except Exception:
    pass
PY
}

set_single_seed_endpoint() {
  local endpoint="$1"
  local seeds_file="${ROOT_DIR}/mainnet/SEEDS.json"
  if [[ -z "${endpoint}" ]]; then
    log "TRUSTED_BOOTSTRAP_PEER is empty; cannot rewrite SEEDS.json"
    return 1
  fi
  if [[ ! -f "${seeds_file}" ]]; then
    log "SEEDS.json not found at ${seeds_file}; cannot pin bootstrap peer"
    return 1
  fi

  python3 - "${seeds_file}" "${endpoint}" <<'PY'
import json
import sys

path = sys.argv[1]
endpoint = sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
data["seeds_p2p"] = [endpoint]
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
  log "Pinned mainnet/SEEDS.json to trusted bootstrap peer: ${endpoint}"
}

recover_peer_discovery_state_if_requested() {
  if [[ "${RECOVER_PEER_DISCOVERY}" != "1" ]]; then
    return 0
  fi

  log "RECOVER_PEER_DISCOVERY=1: stopping finalis services, clearing peer cache, and restarting"
  local s; s="$(need_sudo)"

  if systemd_available; then
    ${s} systemctl stop "${SERVICE_NAME}" "${SERVICE_NAME}-explorer" 2>/dev/null || true
  fi

  rm -f "${DB_DIR}/addrman.dat" "${DB_DIR}/peers.dat"
  log "Cleared peer discovery cache: ${DB_DIR}/addrman.dat and ${DB_DIR}/peers.dat"

  if [[ -n "${TRUSTED_BOOTSTRAP_PEER}" ]]; then
    set_single_seed_endpoint "${TRUSTED_BOOTSTRAP_PEER}"
  else
    log "TRUSTED_BOOTSTRAP_PEER not set; leaving mainnet/SEEDS.json unchanged"
  fi

  if systemd_available; then
    ${s} systemctl start "${SERVICE_NAME}"
    log "Restarted ${SERVICE_NAME}.service"
    if [[ "${FOLLOW_RECOVERY_LOGS}" == "1" ]]; then
      log "Following ${SERVICE_NAME} logs (Ctrl+C to stop)..."
      ${s} journalctl -u "${SERVICE_NAME}" -f
      exit 0
    fi
  else
    log "systemd not available; continuing with regular start flow"
  fi
}

seed_count() {
  local -a seeds=()
  if [[ "${USE_SEEDS_JSON}" == "1" ]]; then
    mapfile -t seeds < <(read_seed_list || true)
  fi
  echo "${#seeds[@]}"
}

seed_csv() {
  local -a seeds=()
  if [[ "${USE_SEEDS_JSON}" == "1" ]]; then
    mapfile -t seeds < <(read_seed_list || true)
  fi
  if (( ${#seeds[@]} == 0 )); then
    return 0
  fi
  local IFS=,
  printf '%s' "${seeds[*]}"
}

seed_args() {
  local -a seeds=()
  if [[ "${USE_SEEDS_JSON}" == "1" ]]; then
    mapfile -t seeds < <(read_seed_list || true)
  fi
  if (( ${#seeds[@]} == 0 )); then
    return 0
  fi
  local seed
  for seed in "${seeds[@]}"; do
    printf '%q %q ' "--peers" "${seed}"
  done
}

requested_mode() {
  case "${NODE_ROLE}" in
    auto|"")
      echo "auto"
      ;;
    bootstrap)
      echo "bootstrap"
      ;;
    joiner|follower)
      echo "joiner"
      ;;
    *)
      log "Unsupported NODE_ROLE=${NODE_ROLE}. Use auto, bootstrap, or joiner."
      exit 1
      ;;
  esac
}

detect_mode() {
  local requested
  requested="$(requested_mode)"
  if [[ "${requested}" != "auto" ]]; then
    echo "${requested}"
    return
  fi

  if [[ "${USE_SEEDS_JSON}" == "1" ]] && [[ "$(seed_count)" -gt 0 ]]; then
    echo "joiner"
  else
    echo "bootstrap"
  fi
}

resolve_genesis_source() {
  local default_genesis_bin="${ROOT_DIR}/mainnet/genesis.bin"
  local default_genesis_json="${ROOT_DIR}/mainnet/genesis.json"
  if [[ -n "${GENESIS_PATH}" ]]; then
    echo "${GENESIS_PATH}"
  elif [[ -f "${default_genesis_bin}" ]]; then
    echo "${default_genesis_bin}"
  elif [[ -f "${default_genesis_json}" ]]; then
    echo "${default_genesis_json}"
  else
    log "No genesis artifact found. Set GENESIS_PATH or provide mainnet/genesis.bin."
    exit 1
  fi
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

reset_chain_data_if_requested() {
  if [[ "${RESET_CHAIN_DATA}" != "1" ]]; then
    return 0
  fi

  local -a pids=()
  mapfile -t pids < <(listener_pids_on_port "${P2P_PORT}" || true)
  if (( ${#pids[@]} > 0 )); then
    local pid
    for pid in "${pids[@]}"; do
      local comm
      comm="$(ps -p "${pid}" -o comm= 2>/dev/null | tr -d '[:space:]')"
      if [[ "${comm}" != "finalis-node" ]]; then
        log "Port ${P2P_PORT} is already in use by pid=${pid} (${comm:-unknown})."
        log "Stop that process manually, then retry."
        exit 1
      fi
      log "Stopping existing finalis-node pid=${pid} on port ${P2P_PORT}."
      kill "${pid}" 2>/dev/null || true
    done

    sleep 1
    local -a stubborn_pids=()
    mapfile -t stubborn_pids < <(listener_pids_on_port "${P2P_PORT}" || true)
    if (( ${#stubborn_pids[@]} > 0 )); then
      for pid in "${stubborn_pids[@]}"; do
        local comm
        comm="$(ps -p "${pid}" -o comm= 2>/dev/null | tr -d '[:space:]')"
        if [[ "${comm}" == "finalis-node" ]]; then
          log "Force stopping finalis-node pid=${pid} on port ${P2P_PORT}."
          kill -9 "${pid}" 2>/dev/null || true
        fi
      done
      sleep 1
    fi

    if listener_pids_on_port "${P2P_PORT}" | grep -q .; then
      log "Port ${P2P_PORT} is still busy after cleanup."
      log "Run: ss -ltnp | rg ${P2P_PORT}"
      exit 1
    fi
  fi

  local data_root
  data_root="$(dirname "${DB_DIR}")"
  if [[ -z "${data_root}" || "${data_root}" == "/" ]]; then
    log "RESET_CHAIN_DATA=1 refused: unsafe data root '${data_root}'"
    exit 1
  fi

  log "RESET_CHAIN_DATA=1: resetting ${data_root} (keeping validator.json files if present)."
  mkdir -p "${data_root}"

  local tmp_keep_root="/tmp/finalis.keep-keys.$$"
  rm -rf "${tmp_keep_root}"
  mkdir -p "${tmp_keep_root}"

  local -a kept_keys=()
  mapfile -t kept_keys < <(find "${data_root}" -type f -name "validator.json" 2>/dev/null || true)
  if (( ${#kept_keys[@]} > 0 )); then
    local key_path rel_path keep_path
    for key_path in "${kept_keys[@]}"; do
      rel_path="${key_path#${data_root}/}"
      keep_path="${tmp_keep_root}/${rel_path}"
      mkdir -p "$(dirname "${keep_path}")"
      cp -f "${key_path}" "${keep_path}"
    done
    log "Preserved ${#kept_keys[@]} validator.json key file(s)"
  fi

  find "${data_root}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +

  if (( ${#kept_keys[@]} > 0 )); then
    local restored
    restored=0
    while IFS= read -r key_path; do
      rel_path="${key_path#${tmp_keep_root}/}"
      keep_path="${data_root}/${rel_path}"
      mkdir -p "$(dirname "${keep_path}")"
      cp -f "${key_path}" "${keep_path}"
      chmod 600 "${keep_path}" || true
      restored=$((restored + 1))
    done < <(find "${tmp_keep_root}" -type f -name "validator.json" 2>/dev/null || true)
    log "Restored ${restored} validator.json key file(s)"
  fi

  rm -rf "${tmp_keep_root}"
  mkdir -p "${DB_DIR}/keystore"
  chmod 700 "${DB_DIR}/keystore" || true
}

auto_fast_sync_if_requested() {
  if [[ "${AUTO_FAST_SYNC}" != "1" ]]; then
    log "Skipping automatic fast sync (AUTO_FAST_SYNC=0)."
    return 0
  fi

  local cli_bin="${ROOT_DIR}/${BUILD_DIR}/finalis-cli"
  if [[ ! -x "${cli_bin}" ]]; then
    log "Automatic fast sync skipped: finalis-cli not found at ${cli_bin}"
    return 0
  fi
  if [[ ! -f "${SNAPSHOT_FILE}" ]]; then
    log "Automatic fast sync skipped: snapshot file not found at ${SNAPSHOT_FILE}"
    return 0
  fi

  if [[ "${FAST_SYNC_PRELOAD_CACHE}" == "1" ]]; then
    if have dd; then
      local snapshot_size_bytes=0
      if [[ -f "${SNAPSHOT_FILE}" ]]; then
        snapshot_size_bytes="$(wc -c < "${SNAPSHOT_FILE}" 2>/dev/null || echo 0)"
      fi
      local preload_start preload_end preload_ms
      preload_start="$(date +%s%3N 2>/dev/null || true)"
      log "Preloading snapshot into page cache: ${SNAPSHOT_FILE}"
      dd if="${SNAPSHOT_FILE}" of=/dev/null bs=8M iflag=fullblock status=none || true
      preload_end="$(date +%s%3N 2>/dev/null || true)"
      preload_ms=0
      if [[ -n "${preload_start}" && -n "${preload_end}" && "${preload_start}" =~ ^[0-9]+$ && "${preload_end}" =~ ^[0-9]+$ ]]; then
        preload_ms="$((preload_end - preload_start))"
      fi
      log "sync_telemetry snapshot_path=${SNAPSHOT_FILE} snapshot_size_bytes=${snapshot_size_bytes} preload_ms=${preload_ms}"
    fi
  fi

  local has_chain_state=0
  if [[ -d "${DB_DIR}" ]]; then
    local entry name
    while IFS= read -r entry; do
      name="$(basename "${entry}" | tr '[:upper:]' '[:lower:]')"
      if [[ "${name}" == "keystore" || "${name}" == "logs" ]]; then
        continue
      fi
      has_chain_state=1
      break
    done < <(find "${DB_DIR}" -mindepth 1 -maxdepth 1 2>/dev/null || true)
  fi

  preserve_validator_keys_for_destructive_sync() {
    local source_root="$1"
    local dest_root="$2"
    local tmp_keep_root="$3"
    local -a key_files=()
    mapfile -t key_files < <(find "${source_root}" -type f -name "validator.json" 2>/dev/null || true)
    if (( ${#key_files[@]} == 0 )); then
      return 0
    fi

    rm -rf "${tmp_keep_root}"
    mkdir -p "${tmp_keep_root}"

    local key_path rel_path keep_path
    for key_path in "${key_files[@]}"; do
      rel_path="${key_path#${source_root}/}"
      keep_path="${tmp_keep_root}/${rel_path}"
      mkdir -p "$(dirname "${keep_path}")"
      cp -f "${key_path}" "${keep_path}"
    done

    local restored=0
    while IFS= read -r key_path; do
      rel_path="${key_path#${tmp_keep_root}/}"
      keep_path="${dest_root}/${rel_path}"
      mkdir -p "$(dirname "${keep_path}")"
      cp -f "${key_path}" "${keep_path}"
      chmod 600 "${keep_path}" || true
      restored=$((restored + 1))
    done < <(find "${tmp_keep_root}" -type f -name "validator.json" 2>/dev/null || true)

    rm -rf "${tmp_keep_root}"
    if (( restored > 0 )); then
      mkdir -p "${dest_root}/keystore"
      chmod 700 "${dest_root}/keystore" || true
      log "Preserved and restored ${restored} validator.json key file(s) for destructive fast_sync."
    fi
  }

  if (( has_chain_state == 1 )) && [[ "${AUTO_FAST_SYNC_FORCE_OVERWRITE}" != "1" ]] && [[ "${SYNC_TURBO_MODE}" == "extreme" ]]; then
    local backup_path="${DB_DIR}.pre_fast_sync.$(date +%s)"
    local tmp_keep_root="/tmp/finalis.fastsync.keep-keys.$$"
    log "SYNC_TURBO_MODE=extreme: existing chain state detected, auto-enabling destructive fast_sync."
    log "Creating safety backup: ${backup_path}"
    rm -rf "${backup_path}"
    mv "${DB_DIR}" "${backup_path}"
    mkdir -p "${DB_DIR}"
    preserve_validator_keys_for_destructive_sync "${backup_path}" "${DB_DIR}" "${tmp_keep_root}"
    has_chain_state=0
  fi

  if (( has_chain_state == 1 )) && [[ "${AUTO_FAST_SYNC_FORCE_OVERWRITE}" != "1" ]]; then
    log "Automatic fast sync skipped: existing chain state detected in ${DB_DIR}."
    log "Set AUTO_FAST_SYNC_FORCE_OVERWRITE=1 (or RESET_CHAIN_DATA=1) to allow destructive re-import."
    return 0
  fi

  if (( has_chain_state == 1 )); then
    log "AUTO_FAST_SYNC_FORCE_OVERWRITE=1: applying destructive fast_sync over existing chain state in ${DB_DIR}"
    "${cli_bin}" fast_sync --db "${DB_DIR}" --snapshot "${SNAPSHOT_FILE}" --force
  else
    log "AUTO_FAST_SYNC=1 and no existing chain state detected; running fast_sync"
    "${cli_bin}" fast_sync --db "${DB_DIR}" --snapshot "${SNAPSHOT_FILE}"
  fi
}

build_node_command() {
  local node_bin="${ROOT_DIR}/${BUILD_DIR}/finalis-node"
  local cli_bin="${ROOT_DIR}/${BUILD_DIR}/finalis-cli"
  local genesis_path="$1"
  local mode="$2"
  local -a args=(
    "${node_bin}"
    "--db" "${DB_DIR}"
    "--genesis" "${genesis_path}"
    "--port" "${P2P_PORT}"
    "--handshake-timeout-ms" "${HANDSHAKE_TIMEOUT_MS}"
    "--frame-timeout-ms" "${FRAME_TIMEOUT_MS}"
    "--idle-timeout-ms" "${IDLE_TIMEOUT_MS}"
  )

  if [[ "${NO_REINDEX_ON_START}" == "1" ]]; then
    args+=("--no-reindex")
  fi
  if [[ "${SYNC_TURBO_MODE}" == "extreme" ]]; then
    args+=("--fast-start")
  fi

  if [[ "${SYNC_TURBO_MODE}" == "extreme" && "${AUTO_DEFERRED_EXIT_ACTIVATION_EXTREME}" == "1" ]]; then
    local has_manual_activation=0
    if [[ -n "${NODE_EXTRA_ARGS}" ]]; then
      if grep -Eq -- '(^|[[:space:]])--deferred-exit-activation-(height|epoch-start)($|[[:space:]])' <<<"${NODE_EXTRA_ARGS}"; then
        has_manual_activation=1
      fi
    fi
    if (( has_manual_activation == 0 )) && [[ -x "${cli_bin}" ]]; then
      local height_line height next_epoch_start
      height_line="$("${cli_bin}" print_logs 2>/dev/null | awk -F= '/^height=/ {print $2; exit}')"
      if [[ -n "${height_line}" ]] && [[ "${height_line}" =~ ^[0-9]+$ ]] && (( height_line >= 1 )); then
        # committee_epoch_start(h) = floor((h-1)/32)*32 + 1; next epoch start adds 32
        next_epoch_start=$(( (((height_line - 1) / 32) + 1) * 32 + 1 ))
        args+=("--deferred-exit-activation-height" "${next_epoch_start}")
        log "SYNC_TURBO_MODE=extreme: auto-set deferred-exit activation to next epoch start ${next_epoch_start} (from height=${height_line})" >&2
      fi
    fi
  fi

  if [[ "${ALLOW_UNSAFE_GENESIS_OVERRIDE}" == "1" ]]; then
    log "WARNING: enabling --allow-unsafe-genesis-override (intended only for controlled recovery/testing)" >&2
    args+=("--allow-unsafe-genesis-override")
  fi

  if [[ "${PUBLIC_NODE}" == "1" ]]; then
    args+=("--public")
  fi

  if [[ "${WITH_LIGHTSERVER}" == "1" ]]; then
    args+=(
      "--with-lightserver"
      "--lightserver-bind" "${LIGHTSERVER_BIND}"
      "--lightserver-port" "${LIGHTSERVER_PORT}"
    )
  fi

  if [[ "${mode}" == "bootstrap" ]]; then
    args+=(
      "--listen"
      "--bind" "0.0.0.0"
      "--outbound-target" "${OUTBOUND_TARGET}"
    )
  else
    local peers
    peers="$(seed_csv)"
    if [[ -z "${peers}" ]]; then
      log "Joiner mode requires one or more peers in mainnet/SEEDS.json."
      exit 1
    fi
    args+=(
      "--outbound-target" "${OUTBOUND_TARGET}"
    )
    # Use one --peers flag per canonical endpoint to avoid persisting a single
    # comma-joined legacy peer string into peers.dat.
    while IFS= read -r seed; do
      [[ -n "${seed}" ]] || continue
      args+=("--peers" "${seed}")
    done < <(read_seed_list || true)
  fi

  if [[ -n "${NODE_EXTRA_ARGS}" ]]; then
    # shellcheck disable=SC2206
    local extra=( ${NODE_EXTRA_ARGS} )
    args+=("${extra[@]}")
  fi

  printf '%q ' "${args[@]}"
}

build_explorer_command() {
  local explorer_bin="${ROOT_DIR}/${BUILD_DIR}/finalis-explorer"
  local -a args=(
    "${explorer_bin}"
    "--bind" "${EXPLORER_BIND}"
    "--port" "${EXPLORER_PORT}"
    "--rpc-url" "${EXPLORER_RPC_URL}"
  )
  printf '%q ' "${args[@]}"
}

display_host() {
  local bind="$1"
  if [[ "${bind}" == "0.0.0.0" || "${bind}" == "::" ]]; then
    echo "127.0.0.1"
    return
  fi
  echo "${bind}"
}

print_runtime_urls() {
  local lightserver_host explorer_host
  lightserver_host="$(display_host "${LIGHTSERVER_BIND}")"
  explorer_host="$(display_host "${EXPLORER_BIND}")"
  if [[ "${WITH_LIGHTSERVER}" == "1" ]]; then
    log "Lightserver URL: http://${lightserver_host}:${LIGHTSERVER_PORT}/rpc"
  fi
  if [[ "${WITH_EXPLORER}" == "1" ]]; then
    log "Explorer URL: http://${explorer_host}:${EXPLORER_PORT}"
  fi
}

print_summary() {
  local mode="$1"
  local genesis_path="$2"
  local command_line="$3"
  local genesis_sha
  genesis_sha="$(sha256_file "${genesis_path}")"
  local peers
  peers="$(seed_csv)"

  log "Detected mode=${mode}"
  log "Seed count=$(seed_count)"
  log "DB_DIR=${DB_DIR}"
  log "Genesis=${genesis_path}"
  log "Genesis sha256=${genesis_sha}"
  log "All nodes must use this exact genesis artifact or VERSION handshake will be rejected."
  if [[ "${mode}" == "bootstrap" ]]; then
    log "Peers=<none; SEEDS.json is empty>"
  else
    log "Peers=${peers}"
  fi
  log "Command:"
  printf '%s\n' "${command_line}"
  if [[ "${mode}" == "bootstrap" ]]; then
    log "Bootstrap verification:"
    log "  ss -ltnp | rg ${P2P_PORT}"
    log "  nc -vz <this-public-ip> ${P2P_PORT}"
  else
    log "Joiner verification:"
    log "  rg 'peer-connected|recv VERSION|recv VERACK|request-finalized-tip|recv BLOCK|buffered-sync-applied'"
  fi
  log "If logs show 'genesis-fingerprint-mismatch', stop the node and reset ${DB_DIR} before retrying."
}

run_node() {
  local command_line="$1"
  if [[ "${WITH_LIGHTSERVER}" == "1" ]]; then
    log "Starting node with public lightserver on ${LIGHTSERVER_BIND}:${LIGHTSERVER_PORT}"
  fi
  log "Starting finalis-node..."
  # Intentional direct exec: this script is the one command operators run.
  eval "exec ${command_line}"
}

install_and_restart_service() {
  local command_line="$1"
  if [[ "${SETUP_NODE_SERVICE}" != "1" ]]; then
    return 1
  fi
  if ! systemd_available; then
    return 1
  fi

  local service_path="/etc/systemd/system/${SERVICE_NAME}.service"
  local s; s="$(need_sudo)"
  ${s} tee "${service_path}" >/dev/null <<EOF
[Unit]
Description=Finalis Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${ROOT_DIR}
ExecStart=${command_line}
StandardOutput=journal
StandardError=journal
SyslogIdentifier=finalis-node
Restart=on-failure
RestartSec=2
TimeoutStopSec=300
KillSignal=SIGINT
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
  ${s} systemctl daemon-reload
  ${s} systemctl enable "${SERVICE_NAME}" >/dev/null || true
  ${s} systemctl restart "${SERVICE_NAME}"
  log "Installed and restarted ${SERVICE_NAME}.service"
  ${s} systemctl status "${SERVICE_NAME}" --no-pager || true
  return 0
}

install_and_restart_explorer_service() {
  local command_line="$1"
  if [[ "${WITH_EXPLORER}" != "1" ]]; then
    return 1
  fi
  if [[ "${SETUP_NODE_SERVICE}" != "1" ]]; then
    return 1
  fi
  if ! systemd_available; then
    return 1
  fi

  local service_path="/etc/systemd/system/${SERVICE_NAME}-explorer.service"
  local s; s="$(need_sudo)"
  ${s} tee "${service_path}" >/dev/null <<EOF
[Unit]
Description=Finalis Explorer
After=network-online.target ${SERVICE_NAME}.service
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${ROOT_DIR}
ExecStart=${command_line}
StandardOutput=journal
StandardError=journal
SyslogIdentifier=finalis-explorer
Restart=on-failure
RestartSec=2
TimeoutStopSec=60
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target
EOF
  ${s} systemctl daemon-reload
  ${s} systemctl enable "${SERVICE_NAME}-explorer" >/dev/null || true
  if ! ${s} systemctl restart "${SERVICE_NAME}-explorer"; then
    log "Explorer service failed to start; continuing without explorer service."
    return 1
  fi
  log "Installed and restarted ${SERVICE_NAME}-explorer.service"
  ${s} systemctl status "${SERVICE_NAME}-explorer" --no-pager || true
  return 0
}

start_explorer_background() {
  local command_line="$1"
  if [[ "${WITH_EXPLORER}" != "1" ]]; then
    return 0
  fi
  local -a pids=()
  mapfile -t pids < <(listener_pids_on_port "${EXPLORER_PORT}" || true)
  if (( ${#pids[@]} > 0 )); then
    log "Explorer port ${EXPLORER_PORT} already has a listener; leaving it in place."
    return 0
  fi
  local log_path="${DB_DIR}/explorer.log"
  log "Starting finalis-explorer..."
  if ! nohup bash -lc "${command_line}" >"${log_path}" 2>&1 & then
    log "Explorer failed to start; continuing without explorer."
    return 1
  fi
  return 0
}

main() {
  recover_peer_discovery_state_if_requested
  auto_tune_sync_profile_if_requested

  log "Checking/installing build dependencies..."
  install_deps
  log "Running cmake -S . -B ${BUILD_DIR} -G ${GENERATOR:-Ninja if available} ..."
  log "Building project with cmake --build ${BUILD_DIR} -j..."
  configure_and_build
  reset_chain_data_if_requested
  auto_fast_sync_if_requested

  local mode
  mode="$(detect_mode)"
  mkdir -p "${DB_DIR}"
  local genesis_path
  genesis_path="$(resolve_genesis_source)"
  local command_line
  command_line="$(build_node_command "${genesis_path}" "${mode}")"
  local explorer_command_line=""
  if [[ "${WITH_EXPLORER}" == "1" ]]; then
    explorer_command_line="$(build_explorer_command)"
  fi

  print_summary "${mode}" "${genesis_path}" "${command_line}"
  open_firewall_ports "${mode}"
  if install_and_restart_service "${command_line}"; then
    if [[ -n "${explorer_command_line}" ]]; then
      install_and_restart_explorer_service "${explorer_command_line}" || true
    fi
    print_runtime_urls
    exit 0
  fi
  if [[ -n "${explorer_command_line}" ]]; then
    start_explorer_background "${explorer_command_line}" || true
  fi
  print_runtime_urls
  run_node "${command_line}"
}

main "$@"
