#!/usr/bin/env bash
# SPDX-License-Identifier: MIT

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PORT="${PORT:-18080}"
STATE_FILE="$(mktemp /tmp/finalis-mint-state.XXXXXX.json)"
LOCK_FILE="$(mktemp /tmp/finalis-mint-worker.XXXXXX.lock)"
SECRETS_DIR="$(mktemp -d /tmp/finalis-mint-secrets.XXXXXX)"
ENV_FILE="$(mktemp /tmp/finalis-mint-env.XXXXXX)"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then kill "$SERVER_PID" >/dev/null 2>&1 || true; fi
  if [[ -n "${WORKER_PID:-}" ]]; then kill "$WORKER_PID" >/dev/null 2>&1 || true; fi
  wait "${SERVER_PID:-}" "${WORKER_PID:-}" 2>/dev/null || true
  rm -f "$STATE_FILE" "$LOCK_FILE" "$ENV_FILE"
  rm -rf "$SECRETS_DIR"
}
trap cleanup EXIT

cat >"$ENV_FILE" <<EOF
FINALIS_MINT_HOST=127.0.0.1
FINALIS_MINT_PORT=$PORT
FINALIS_MINT_STATE_FILE=$STATE_FILE
FINALIS_MINT_MINT_ID=
FINALIS_MINT_SIGNING_SEED=finalis-mint-smoke-seed
FINALIS_MINT_OPERATOR_KEY=dev-operator:1111111111111111111111111111111111111111111111111111111111111111
FINALIS_MINT_LIGHTSERVER_URL=
FINALIS_MINT_RESERVE_PRIVKEY=
FINALIS_MINT_RESERVE_ADDRESS=
FINALIS_MINT_RESERVE_FEE=1000
FINALIS_MINT_CLI_PATH=$ROOT/build/finalis-cli
FINALIS_MINT_NOTIFIER_RETRY_INTERVAL_SECONDS=1
FINALIS_MINT_SECRET_BACKEND=auto
FINALIS_MINT_NOTIFIER_SECRETS_FILE=
FINALIS_MINT_NOTIFIER_SECRET_DIR=$SECRETS_DIR
FINALIS_MINT_NOTIFIER_SECRET_ENV_PREFIX=FINALIS_MINT_SECRET_
FINALIS_MINT_NOTIFIER_SECRET_HELPER_CMD="$ROOT/services/finalis-mint/secret_helper.py --dir $SECRETS_DIR --env-prefix FINALIS_MINT_SECRET_"
FINALIS_MINT_WORKER_LOCK_FILE=$LOCK_FILE
FINALIS_MINT_WORKER_STALE_TIMEOUT_SECONDS=5
EOF

set -a
source "$ENV_FILE"
set +a

python3 "$ROOT/services/finalis-mint/server.py" \
  --mode server \
  --host "$FINALIS_MINT_HOST" \
  --port "$FINALIS_MINT_PORT" \
  --state-file "$FINALIS_MINT_STATE_FILE" \
  --signing-seed "$FINALIS_MINT_SIGNING_SEED" \
  --operator-key "$FINALIS_MINT_OPERATOR_KEY" \
  --notifier-secret-backend "$FINALIS_MINT_SECRET_BACKEND" \
  --notifier-secret-dir "$FINALIS_MINT_NOTIFIER_SECRET_DIR" \
  --notifier-secret-helper-cmd "$FINALIS_MINT_NOTIFIER_SECRET_HELPER_CMD" \
  --worker-lock-file "$FINALIS_MINT_WORKER_LOCK_FILE" \
  --worker-stale-timeout-seconds "$FINALIS_MINT_WORKER_STALE_TIMEOUT_SECONDS" \
  --notifier-retry-interval-seconds "$FINALIS_MINT_NOTIFIER_RETRY_INTERVAL_SECONDS" \
  >/tmp/finalis-mint-server-smoke.log 2>&1 &
SERVER_PID=$!

python3 "$ROOT/services/finalis-mint/server.py" \
  --mode worker \
  --state-file "$FINALIS_MINT_STATE_FILE" \
  --signing-seed "$FINALIS_MINT_SIGNING_SEED" \
  --operator-key "$FINALIS_MINT_OPERATOR_KEY" \
  --notifier-secret-backend "$FINALIS_MINT_SECRET_BACKEND" \
  --notifier-secret-dir "$FINALIS_MINT_NOTIFIER_SECRET_DIR" \
  --notifier-secret-helper-cmd "$FINALIS_MINT_NOTIFIER_SECRET_HELPER_CMD" \
  --worker-lock-file "$FINALIS_MINT_WORKER_LOCK_FILE" \
  --worker-stale-timeout-seconds "$FINALIS_MINT_WORKER_STALE_TIMEOUT_SECONDS" \
  --notifier-retry-interval-seconds "$FINALIS_MINT_NOTIFIER_RETRY_INTERVAL_SECONDS" \
  >/tmp/finalis-mint-worker-smoke.log 2>&1 &
WORKER_PID=$!

python3 - <<PY
import json, time, urllib.request
url = "http://127.0.0.1:${PORT}/healthz"
for _ in range(50):
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            data = json.loads(resp.read().decode())
            if data.get("ok"):
                break
    except Exception:
        time.sleep(0.1)
else:
    raise SystemExit("server did not become healthy")
with urllib.request.urlopen("http://127.0.0.1:${PORT}/monitoring/worker", timeout=2) as resp:
    worker = json.loads(resp.read().decode())
if worker.get("takeover_policy") != "allow-after-stale-timeout":
    raise SystemExit("unexpected worker status")
PY

echo "finalis-mint smoke deployment passed"
