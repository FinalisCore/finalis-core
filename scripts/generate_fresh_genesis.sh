#!/usr/bin/env bash
# Generate a fresh validator set and genesis for a devnet or launch ceremony.
#
# Output: devnet/<UTC timestamp>/ (git-ignored)
#   keys/validator-<i>.json      encrypted validator keystores (wallet_create)
#   secrets/validator-<i>.pass   keystore passphrases (production profile only)
#   genesis.json / genesis.bin   mainnet parameters, fresh validator set
#   manifest.env                 consumed by scripts/devnet_up.sh
#
# Network parameters (network_id, magic, protocol_version, committee params,
# monetary ref) are copied from mainnet/genesis.json; `genesis_build` validates
# them against the compiled-in mainnet NetworkConfig.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PROFILE="local"
VALIDATORS=3
CLI_BIN=""
USE_DOCKER=0
ALLOW_DIRTY=0
OUT_ROOT="$ROOT_DIR/devnet"
LOCAL_PASSPHRASE="localdevnet"

usage() {
  cat <<EOF
usage: $(basename "$0") [options]

  --profile local|production  local: shared passphrase "$LOCAL_PASSPHRASE" (default)
                              production: random per-validator passphrases, clean git tree required
  --validators N              number of genesis validators (default: 3)
  --cli PATH                  finalis-cli binary (default: build/finalis-cli if present)
  --docker                    run finalis-cli inside the compose-built image
  --out-root DIR              parent output directory (default: devnet/)
  --allow-dirty               production: allow uncommitted changes in the tree
  -h, --help                  show this help
EOF
}

die() { echo "error: $*" >&2; exit 1; }
log() { echo "[genesis] $*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)     PROFILE="${2:?--profile requires a value}"; shift 2 ;;
    --validators)  VALIDATORS="${2:?--validators requires a value}"; shift 2 ;;
    --cli)         CLI_BIN="${2:?--cli requires a value}"; shift 2 ;;
    --docker)      USE_DOCKER=1; shift ;;
    --out-root)    OUT_ROOT="${2:?--out-root requires a value}"; shift 2 ;;
    --allow-dirty) ALLOW_DIRTY=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             usage >&2; die "unknown argument: $1" ;;
  esac
done

case "$PROFILE" in
  local|production) ;;
  *) die "--profile must be local or production" ;;
esac
[[ "$VALIDATORS" =~ ^[1-9][0-9]*$ ]] || die "--validators must be a positive integer"
command -v python3 >/dev/null || die "python3 is required"

MAINNET_JSON="$ROOT_DIR/mainnet/genesis.json"
[[ -f "$MAINNET_JSON" ]] || die "missing $MAINNET_JSON"

# --- source provenance --------------------------------------------------------
GIT_COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_DIRTY=0
if [[ -n "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=no 2>/dev/null)" ]]; then
  GIT_DIRTY=1
fi
if [[ "$PROFILE" == "production" && "$GIT_DIRTY" == 1 && "$ALLOW_DIRTY" == 0 ]]; then
  die "production profile requires a clean git tree (commit or pass --allow-dirty)"
fi

# --- output directory ---------------------------------------------------------
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$OUT_ROOT/$STAMP"
[[ -e "$OUT_DIR" ]] && die "$OUT_DIR already exists"
umask 077
mkdir -p "$OUT_DIR/keys"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
if [[ "$PROFILE" == "production" ]]; then
  mkdir -p "$OUT_DIR/secrets"
fi

# --- finalis-cli runner -------------------------------------------------------
# run_cli <args...>; paths under $OUT_DIR must be passed as /work/<rel> and are
# rewritten for the local binary.
COMPOSE=()
if [[ "$USE_DOCKER" == 0 ]]; then
  if [[ -z "$CLI_BIN" && -x "$ROOT_DIR/build/finalis-cli" ]]; then
    CLI_BIN="$ROOT_DIR/build/finalis-cli"
  fi
  if [[ -z "$CLI_BIN" ]]; then
    log "no local finalis-cli found; falling back to the container image"
    USE_DOCKER=1
  fi
fi

if [[ "$USE_DOCKER" == 1 ]]; then
  if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
  elif command -v docker-compose >/dev/null; then
    COMPOSE=(docker-compose)
  else
    die "neither 'docker compose' nor 'docker-compose' is available"
  fi
  COMPOSE+=(-f "$ROOT_DIR/docker-compose.yml")
  log "building node image"
  "${COMPOSE[@]}" build node1
  CLI_SOURCE="docker"
else
  [[ -x "$CLI_BIN" ]] || die "finalis-cli not executable: $CLI_BIN"
  CLI_SOURCE="$CLI_BIN"
fi

run_cli() {
  if [[ "$USE_DOCKER" == 1 ]]; then
    "${COMPOSE[@]}" run --rm --no-deps -T \
      --user "$(id -u):$(id -g)" \
      -v "$OUT_DIR:/work" \
      --entrypoint finalis-cli node1 "$@"
  else
    local args=() a
    for a in "$@"; do args+=("${a//\/work/$OUT_DIR}"); done
    "$CLI_BIN" "${args[@]}"
  fi
}

kv() { sed -n "s/^$1=//p" <<<"$2" | head -n1; }

# --- validator keys -----------------------------------------------------------
declare -a PUBKEYS ADDRESSES
for ((i = 1; i <= VALIDATORS; i++)); do
  if [[ "$PROFILE" == "production" ]]; then
    pass="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    printf '%s\n' "$pass" > "$OUT_DIR/secrets/validator-$i.pass"
    chmod 600 "$OUT_DIR/secrets/validator-$i.pass"
  else
    pass="$LOCAL_PASSPHRASE"
  fi

  out="$(run_cli wallet_create --out "/work/keys/validator-$i.json" --pass "$pass" --network mainnet)" \
    || die "wallet_create failed for validator $i"
  PUBKEYS[i]="$(kv pubkey_hex "$out")"
  ADDRESSES[i]="$(kv address "$out")"
  [[ "${PUBKEYS[i]}" =~ ^[0-9a-f]{64}$ ]] || die "unexpected wallet_create output for validator $i:"$'\n'"$out"

  # Keystores are passphrase-encrypted; 0644 lets the container's non-root
  # user read the bind mount, while the 0700 parent keeps other host users out.
  chmod 644 "$OUT_DIR/keys/validator-$i.json"
  log "validator $i pubkey=${PUBKEYS[i]}"
done
chmod 700 "$OUT_DIR" "$OUT_DIR/keys"

# --- genesis.json -------------------------------------------------------------
GENESIS_TIME="$(date -u +%s)"
python3 - "$MAINNET_JSON" "$OUT_DIR/genesis.json" "$GENESIS_TIME" "$PROFILE" "$STAMP" "${PUBKEYS[@]}" <<'PY'
import json, sys

src, dst, gtime, profile, stamp, *validators = sys.argv[1:]
with open(src) as f:
    doc = json.load(f)

doc["genesis_time_unix"] = int(gtime)
doc["initial_height"] = 0
doc["initial_validators"] = validators
doc["initial_active_set_size"] = len(validators)
doc["seeds"] = []
doc["note"] = f"Fresh {profile} genesis {stamp} with {len(validators)} generated validators"

with open(dst, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY

# --- genesis.bin --------------------------------------------------------------
build_out="$(run_cli genesis_build --in /work/genesis.json --out /work/genesis.bin)" \
  || die "genesis_build failed"
run_cli genesis_verify --json /work/genesis.json --bin /work/genesis.bin >/dev/null \
  || die "genesis_verify failed"
chmod 644 "$OUT_DIR/genesis.json" "$OUT_DIR/genesis.bin"

GENESIS_HASH="$(kv genesis_hash "$build_out")"
GENESIS_TRANSITION_ID="$(kv genesis_transition_id "$build_out")"
NETWORK_ID="$(kv network_id "$build_out")"
MAGIC="$(kv magic "$build_out")"
[[ -n "$GENESIS_HASH" ]] || die "genesis_build printed no genesis_hash:"$'\n'"$build_out"

# --- manifest.env -------------------------------------------------------------
# Paths are relative to the manifest's directory. Plain KEY=VALUE lines only (no
# comments), so the file also works with `env $(xargs <manifest.env)` and --env-file.
{
  printf 'DEVNET_PROFILE=%q\n' "$PROFILE"
  printf 'DEVNET_CREATED_UTC=%q\n' "$STAMP"
  printf 'GIT_COMMIT=%q\n' "$GIT_COMMIT"
  printf 'GIT_DIRTY=%q\n' "$GIT_DIRTY"
  printf 'CLI_SOURCE=%q\n' "$CLI_SOURCE"
  printf 'NETWORK_ID=%q\n' "$NETWORK_ID"
  printf 'MAGIC=%q\n' "$MAGIC"
  printf 'GENESIS_TIME_UNIX=%q\n' "$GENESIS_TIME"
  printf 'GENESIS_JSON=%q\n' "genesis.json"
  printf 'GENESIS_BIN=%q\n' "genesis.bin"
  printf 'GENESIS_HASH=%q\n' "$GENESIS_HASH"
  printf 'GENESIS_TRANSITION_ID=%q\n' "$GENESIS_TRANSITION_ID"
  printf 'VALIDATOR_COUNT=%q\n' "$VALIDATORS"
  for ((i = 1; i <= VALIDATORS; i++)); do
    printf 'VALIDATOR_%d_KEY=%q\n' "$i" "keys/validator-$i.json"
    printf 'VALIDATOR_%d_PUBKEY=%q\n' "$i" "${PUBKEYS[i]}"
    printf 'VALIDATOR_%d_ADDRESS=%q\n' "$i" "${ADDRESSES[i]}"
    if [[ "$PROFILE" == "production" ]]; then
      printf 'VALIDATOR_%d_PASS_FILE=%q\n' "$i" "secrets/validator-$i.pass"
    else
      printf 'VALIDATOR_%d_PASSPHRASE=%q\n' "$i" "$LOCAL_PASSPHRASE"
    fi
  done
  # Names consumed by docker-compose.devnet.yml. Local profile only: production
  # passphrases stay in secrets/*.pass and reach <devnet>/.env via devnet_up.sh.
  if [[ "$PROFILE" != "production" ]]; then
    for ((i = 1; i <= VALIDATORS; i++)); do
      printf 'FINALIS_DEVNET_PASS_%d=%q\n' "$i" "$LOCAL_PASSPHRASE"
    done
  fi
} > "$OUT_DIR/manifest.env"
chmod 600 "$OUT_DIR/manifest.env"

log "profile=$PROFILE validators=$VALIDATORS"
log "genesis_hash=$GENESIS_HASH"
log "output=$OUT_DIR"
