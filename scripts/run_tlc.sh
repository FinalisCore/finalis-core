#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORMAL_DIR="${ROOT_DIR}/formal"
DEFAULT_JAR="${HOME}/tools/tla/tla2tools.jar"
DEFAULT_SPEC="formal/checkpoint_availability.tla"
DEFAULT_OUT_DIR="formal/tlc_runs"
DEFAULT_CONFIGS=(
  "formal/checkpoint_availability.cfg"
  "formal/checkpoint_availability_sticky.cfg"
  "formal/checkpoint_availability_ordering.cfg"
  "formal/checkpoint_availability_long_horizon.cfg"
)

TLA_JAR="${TLA_JAR:-$DEFAULT_JAR}"
TLC_SEED="${TLC_SEED:-20260331}"
TLC_WORKERS="${TLC_WORKERS:-1}"
TLC_HEAP_MB="${TLC_HEAP_MB:-4096}"
TLC_OUT_DIR="${TLC_OUT_DIR:-$DEFAULT_OUT_DIR}"
TLC_KEEP_META="${TLC_KEEP_META:-0}"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/run_tlc.sh [options] [-- <extra TLC args>]

Options:
  --list                List the built-in TLC configs and exit
  --config <path>       Run only the given config (repeatable)
  --spec <path>         Override the spec path (default: formal/checkpoint_availability.tla)
  --out-dir <path>      Directory for logs and TLC metadirs (default: formal/tlc_runs)
  --keep-metadir        Keep TLC metadirs instead of passing -cleanup
  -h, --help            Show this help

Environment overrides:
  TLA_JAR               Path to tla2tools.jar
  TLC_SEED              Fixed TLC seed for reproducible runs
  TLC_WORKERS           TLC worker count (default: 1 for reproducibility)
  TLC_HEAP_MB           JVM heap in MB (default: 4096)
  TLC_OUT_DIR           Output directory for logs/metadirs
  TLC_KEEP_META         Set to 1 to keep TLC metadirs
EOF
}

list_configs() {
  printf '%s\n' "${DEFAULT_CONFIGS[@]}"
}

SPEC_REL="${DEFAULT_SPEC}"
OUT_DIR_REL="${TLC_OUT_DIR}"
declare -a CONFIGS=()
declare -a EXTRA_TLC_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list)
      list_configs
      exit 0
      ;;
    --config)
      [[ $# -ge 2 ]] || { echo "error: --config requires a path" >&2; exit 1; }
      CONFIGS+=("$2")
      shift 2
      ;;
    --spec)
      [[ $# -ge 2 ]] || { echo "error: --spec requires a path" >&2; exit 1; }
      SPEC_REL="$2"
      shift 2
      ;;
    --out-dir)
      [[ $# -ge 2 ]] || { echo "error: --out-dir requires a path" >&2; exit 1; }
      OUT_DIR_REL="$2"
      shift 2
      ;;
    --keep-metadir)
      TLC_KEEP_META=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      EXTRA_TLC_ARGS=("$@")
      break
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! command -v java >/dev/null 2>&1; then
  echo "error: java not found" >&2
  echo "install a JRE first, for example: sudo apt install -y default-jre" >&2
  exit 1
fi

if [[ ! -f "${TLA_JAR}" ]]; then
  cat >&2 <<EOF
error: tla2tools.jar not found at:
  ${TLA_JAR}

Set TLA_JAR to the jar path or install the default location:
  mkdir -p ${HOME}/tools/tla
  curl -L -o ${DEFAULT_JAR} https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
EOF
  exit 1
fi

if [[ ${#CONFIGS[@]} -eq 0 ]]; then
  CONFIGS=("${DEFAULT_CONFIGS[@]}")
fi

SPEC_PATH="${ROOT_DIR}/${SPEC_REL}"
OUT_DIR_PATH="${ROOT_DIR}/${OUT_DIR_REL}"

if [[ ! -f "${SPEC_PATH}" ]]; then
  echo "error: spec file not found: ${SPEC_PATH}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR_PATH}"

JVM_OPTS=("-XX:+UseParallelGC" "-Xmx${TLC_HEAP_MB}m")
TLC_BASE_ARGS=("-seed" "${TLC_SEED}" "-workers" "${TLC_WORKERS}")
if [[ "${TLC_KEEP_META}" != "1" ]]; then
  TLC_BASE_ARGS+=("-cleanup")
fi

for cfg_rel in "${CONFIGS[@]}"; do
  cfg_path="${ROOT_DIR}/${cfg_rel}"
  if [[ ! -f "${cfg_path}" ]]; then
    echo "error: config file not found: ${cfg_path}" >&2
    exit 1
  fi

  cfg_name="$(basename "${cfg_rel}" .cfg)"
  meta_dir="${OUT_DIR_PATH}/${cfg_name}.tlc"
  log_path="${OUT_DIR_PATH}/${cfg_name}.log"

  rm -rf "${meta_dir}"
  mkdir -p "${meta_dir}"

  echo "==> TLC ${cfg_name}"
  echo "    spec: ${SPEC_REL}"
  echo "    cfg : ${cfg_rel}"
  echo "    log : ${log_path}"

  java "${JVM_OPTS[@]}" -cp "${TLA_JAR}" tlc2.TLC \
    "${TLC_BASE_ARGS[@]}" \
    -metadir "${meta_dir}" \
    -config "${cfg_path}" \
    "${SPEC_PATH}" \
    "${EXTRA_TLC_ARGS[@]}" | tee "${log_path}"
done

echo "TLC suite completed successfully."
