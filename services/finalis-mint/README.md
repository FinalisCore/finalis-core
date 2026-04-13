# finalis-mint

Minimal standalone Chaumian mint boundary service for local development and integration work.

Current restarted mainnet identity reference:

- `network_name = mainnet`
- `network_id = 258038c123a1c9b08475216e5f53a503`
- `genesis_hash = fd5570810b163e43a90ef5e8203e8aef34c89072f5f261c4de74aa724a615211`

This service is intentionally outside consensus. It consumes the JSON contracts described in:

- the HTTP handlers implemented in [server.py](./server.py)
- the finalized-state lightserver surface documented in [../../docs/LIVE_PROTOCOL.md](../../docs/LIVE_PROTOCOL.md)

It is a narrow scaffold, not a production mint:

- file-backed state
- deterministic RSA blind-signing for development/testing
- persistent issuance ledger
- reserve and accounting summary endpoints
- reserve wallet inventory / fragmentation reporting
- max-input coin selection policy and reserve alerts
- automatic redemption settlement using a configured reserve wallet
- lightserver-backed redemption finalization (`pending -> broadcast -> finalized/rejected`)
- HMAC-signed operator admin requests
- persistent notifier delivery job queue
- optional single-worker leader lock for queue draining
- notifier secret refs resolved through a pluggable secret backend adapter
- signed reserve attestations / audit exports
- no federation
- no multi-operator quorum custody

Fresh-genesis boundary:

- if the configured lightserver reports a different `network_id` or
  `genesis_hash`, it is not the current restarted mainnet
- old-chain reserve assumptions or txids from the abandoned chain must not be
  reused as if they were current settlement facts

## Endpoints

- `POST /deposits/register`
- `POST /issuance/blind`
- `POST /redemptions/create`
- `POST /redemptions/approve_broadcast`
- `POST /reserves/consolidate`
- `POST /redemptions/status`
- `POST /redemptions/update`
- `POST /policy/redemptions`
- `GET /healthz`
- `GET /mint/key`
- `GET /reserves`
- `GET /reserves/consolidate_plan`
- `GET /policy/redemptions`
- `GET /monitoring/reserve_health`
- `GET /monitoring/alerts/history`
- `GET /monitoring/events/policy`
- `GET /monitoring/events/silences`
- `GET /monitoring/notifiers`
- `GET /monitoring/dead_letters`
- `GET /monitoring/incidents/export`
- `GET /monitoring/metrics`
- `GET /monitoring/worker`
- `GET /dashboard`
- `GET /dashboard/incidents`
- `POST /monitoring/dead_letters/replay`
- `GET /accounting/summary`
- `GET /operator/key`
- `GET /attestations/reserves`
- `GET /audit/export` (operator-signed request required)

## Run

```bash
python3 services/finalis-mint/server.py \
  --host 127.0.0.1 \
  --port 8080 \
  --state-file /tmp/finalis-mint-state.json \
  --confirmations-required 1 \
  --operator-key dev-operator:1111111111111111111111111111111111111111111111111111111111111111 \
  --lightserver-url http://127.0.0.1:19444/rpc \
  --reserve-privkey 5555555555555555555555555555555555555555555555555555555555555555 \
  --reserve-address sc1... \
  --reserve-fee 1000 \
  --cli-path ./build/finalis-cli \
  --notifier-retry-interval-seconds 5 \
  --notifier-secrets-file /etc/finalis-mint/notifier-secrets.json \
  --notifier-secret-dir /etc/finalis-mint/secrets.d \
  --notifier-secret-env-prefix FINALIS_MINT_SECRET_ \
  --notifier-secret-backend auto \
  --notifier-secret-helper-cmd "" \
  --worker-lock-file /var/lib/finalis-mint/worker.lock
```

`--confirmations-required` is a legacy flag name.
In the current code it acts as the required finalized-depth threshold reported
by lightserver `get_tx_status`.

Run a separate worker process:

```bash
python3 services/finalis-mint/server.py \
  --mode worker \
  --state-file /tmp/finalis-mint-state.json \
  --operator-key dev-operator:1111111111111111111111111111111111111111111111111111111111111111 \
  --lightserver-url http://127.0.0.1:19444/rpc \
  --reserve-privkey 5555555555555555555555555555555555555555555555555555555555555555 \
  --reserve-address sc1... \
  --cli-path ./build/finalis-cli \
  --notifier-retry-interval-seconds 5 \
  --notifier-secret-backend auto \
  --notifier-secret-dir /etc/finalis-mint/secrets.d \
  --worker-lock-file /var/lib/finalis-mint/worker.lock \
  --worker-stale-timeout-seconds 30
```

## Example with finalis-cli

```bash
./build/finalis-cli mint_deposit_register \
  --url http://127.0.0.1:8080/deposits/register \
  --deposit-txid 1111111111111111111111111111111111111111111111111111111111111111 \
  --deposit-vout 0 \
  --mint-id 2222222222222222222222222222222222222222222222222222222222222222 \
  --recipient-address sc1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaczjbkjy \
  --amount 100000
```

The response now reports `finalization_depth_required` as the primary
finalized-state threshold.
`confirmations_required` may still appear as a compatibility alias during migration.

```bash
./build/finalis-cli mint_redeem_status \
  --url http://127.0.0.1:8080/redemptions/status \
  --batch-id <opaque-id>
```

The redemption status response reports `finalization_depth` as the primary
progress field.
`confirmations` may still appear as a compatibility alias.

```bash
./build/finalis-cli mint_issue_blinds \
  --url http://127.0.0.1:8080/issuance/blind \
  --mint-deposit-ref <opaque-id> \
  --blind blind-msg-1 --note-amount 40000 \
  --blind blind-msg-2 --note-amount 60000
```

```bash
./build/finalis-cli mint_redeem_create \
  --url http://127.0.0.1:8080/redemptions/create \
  --redeem-address sc1... \
  --amount 100000 \
  --note <note-ref-1> \
  --note <note-ref-2>
```

```bash
./build/finalis-cli mint_redeem_approve_broadcast \
  --url http://127.0.0.1:8080/redemptions/approve_broadcast \
  --batch-id <opaque-id> \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111
```

```bash
./build/finalis-cli mint_reserve_consolidate \
  --url http://127.0.0.1:8080/reserves/consolidate \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111
```

```bash
./build/finalis-cli mint_reserve_consolidation_plan \
  --url http://127.0.0.1:8080/reserves/consolidate_plan \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111
```

```bash
./build/finalis-cli mint_reserve_health \
  --url http://127.0.0.1:8080/monitoring/reserve_health
```

```bash
./build/finalis-cli mint_reserve_metrics \
  --url http://127.0.0.1:8080/monitoring/metrics

./build/finalis-cli mint_alert_history \
  --url http://127.0.0.1:8080/monitoring/alerts/history

./build/finalis-cli mint_event_policy \
  --url http://127.0.0.1:8080/monitoring/events/policy

./build/finalis-cli mint_alert_silences \
  --url http://127.0.0.1:8080/monitoring/events/silences

./build/finalis-cli mint_notifier_list \
  --url http://127.0.0.1:8080/monitoring/notifiers

./build/finalis-cli mint_dead_letters \
  --url http://127.0.0.1:8080/monitoring/dead_letters

./build/finalis-cli mint_incident_timeline_export \
  --url http://127.0.0.1:8080/monitoring/incidents/export

./build/finalis-cli mint_dead_letter_replay \
  --url http://127.0.0.1:8080/monitoring/dead_letters/replay \
  --dead-letter-id <dead-letter-id> \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111
```

```bash
./build/finalis-cli mint_redemptions_pause \
  --url http://127.0.0.1:8080/policy/redemptions \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111 \
  --reason "reserve low"

./build/finalis-cli mint_redemptions_resume \
  --url http://127.0.0.1:8080/policy/redemptions \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111

./build/finalis-cli mint_redemptions_auto_pause_enable \
  --url http://127.0.0.1:8080/policy/redemptions \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111

./build/finalis-cli mint_redemptions_auto_pause_disable \
  --url http://127.0.0.1:8080/policy/redemptions \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111

./build/finalis-cli mint_alert_ack \
  --url http://127.0.0.1:8080/monitoring/events/ack \
  --event-id <event-id> \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111 \
  --note "seen"

./build/finalis-cli mint_alert_silence \
  --url http://127.0.0.1:8080/monitoring/events/silence \
  --event-type policy.auto_pause \
  --until 4102444800 \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111 \
  --reason "maintenance"

./build/finalis-cli mint_event_policy_update \
  --url http://127.0.0.1:8080/monitoring/events/policy \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111 \
  --retention-limit 128 \
  --export-include-acknowledged false

./build/finalis-cli mint_notifier_upsert \
  --url http://127.0.0.1:8080/monitoring/notifiers \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111 \
  --notifier-id ops-webhook \
  --kind webhook \
  --target http://127.0.0.1:9099/webhook \
  --auth-type bearer \
  --auth-token-secret-ref ops_webhook_bearer \
  --tls-verify true \
  --retry-max-attempts 3 \
  --retry-backoff-seconds 30
```

```bash
curl http://127.0.0.1:8080/accounting/summary
curl http://127.0.0.1:8080/reserves
curl http://127.0.0.1:8080/operator/key
curl http://127.0.0.1:8080/attestations/reserves
./build/finalis-cli mint_audit_export \
  --url http://127.0.0.1:8080/audit/export \
  --operator-key-id dev-operator \
  --operator-secret-hex 1111111111111111111111111111111111111111111111111111111111111111
```

## Notes

- Deposit references are deterministic hashes of `(txid, vout, mint_id)`.
- Blind issuance responses are deterministic RSA blind signatures derived from a local seed.
- Each issuance creates persistent `note_ref` entries with explicit denominations.
- If a reserve wallet and lightserver are configured, signed operators can approve pending redemptions for automatic L1 tx construction and broadcast.
- Broadcasted reserve inputs are excluded from spendable reserve inventory. Pending in-flight reserve usage is tracked separately via `pending_spend_commitment_count` and `pending_spend_input_count`.
- Coin selection uses `smallest-sufficient-non-dust-change` with `min_change=1000` and `max_inputs=8`; if no non-dust change set can be formed within the max-input budget, the redemption stays `pending`.
- Redemption batches that cannot yet be funded stay `pending`; operators may reject them, but `broadcast` must go through `/redemptions/approve_broadcast`.
- `finalized` is derived from observed L1 tx status via the configured lightserver.
- `/reserves` includes live reserve-wallet UTXO count/value, locked UTXO count/value, simple fragmentation metrics, operator-facing alert fields such as reserve exhaustion risk, max-input pressure, and fragmentation threshold breach, and the active coin-selection thresholds when lightserver + reserve address are configured.
- `/policy/redemptions` now includes auto-pause recommendations and threshold metadata derived from the current reserve state.
- `/reserves/consolidate_plan` includes an `estimated_post_action` section so operators can see expected post-consolidation fragmentation before broadcasting.
- `/monitoring/reserve_health` provides a compact monitoring/export summary with `healthy|warn|critical` status, current alert booleans, and the current auto-pause recommendation.
- `/monitoring/worker` exposes worker leadership / lock-owner state.
- `/monitoring/worker` also exposes stale lease detection and takeover policy.
- `/monitoring/alerts/history` provides the recent persisted operator/auto-pause event log.
- `/monitoring/events/policy` exposes event retention/export settings.
- `/monitoring/events/silences` exposes active and expired silences.
- `/monitoring/notifiers` exposes configured notifier hooks.
- `/monitoring/dead_letters` exposes failed notifier deliveries that exhausted retries.
- `/monitoring/incidents/export` exposes a signed incident timeline including events, silences, dead letters, and notifier state.
- `/dashboard` and `/dashboard/incidents` expose a minimal operator HTML view over reserve health, recent events, queue state, and incident data.
- `POST /monitoring/dead_letters/replay` requeues a dead-lettered delivery and retries it immediately.
- `/monitoring/metrics` exports Prometheus-style reserve, pause, and alert counters.
- Notifier hooks currently support:
  - `webhook`
  - `alertmanager`
  - `email_spool` for local `.eml` drop delivery
- Each notifier supports:
  - `retry_max_attempts`
  - `retry_backoff_seconds`
- `webhook` and `alertmanager` notifiers also support:
  - `auth_type=none|bearer|basic`
  - `auth_token_secret_ref`
  - `auth_user_secret_ref`
  - `auth_pass_secret_ref`
  - `tls_verify`
  - `tls_ca_file`
- `tls_client_cert_file`
- `tls_client_key_file`
- The service runs a background retry worker (`--notifier-retry-interval-seconds`) backed by a persisted delivery job queue, so retries survive restart and do not depend on request traffic.
- `--mode server` runs only the HTTP service.
- `--mode worker` runs only the queue worker.
- `--mode all` keeps the old combined behavior when needed.
- If `--worker-lock-file` is configured, the worker uses a renewable lease file with stale-timeout takeover policy.
- Secret values can come from:
  - `--notifier-secret-dir` as one file per secret ref
  - `FINALIS_MINT_SECRET_<REF>` environment variables
  - `--notifier-secrets-file` as a fallback JSON map
- Or from `--notifier-secret-helper-cmd <cmd>` when `--notifier-secret-backend=command`; the ref is appended as the final argument.
- A helper implementation is included at [secret_helper.py](./secret_helper.py).
- `--notifier-secret-backend` may be `auto|dir|env|json|command`.
- The state file stores refs, not the secret values themselves.

## systemd units

Example split units and env file template live in:

- [services/finalis-mint/systemd/finalis-mint-server.service](./systemd/finalis-mint-server.service)
- [services/finalis-mint/systemd/finalis-mint-worker.service](./systemd/finalis-mint-worker.service)
- [services/finalis-mint/systemd/finalis-mint.env.example](./systemd/finalis-mint.env.example)
- [services/finalis-mint/systemd/finalis-mint.tmpfiles.conf](./systemd/finalis-mint.tmpfiles.conf)
- [services/finalis-mint/systemd/install_finalis_mint.sh](./systemd/install_finalis_mint.sh)
- [services/finalis-mint/systemd/smoke_deploy.sh](./systemd/smoke_deploy.sh)

The install helper also places:

- [secret_helper.py](./secret_helper.py)
  as `/usr/local/libexec/finalis-mint-secret-helper`
- operator deployment should follow the service flags and systemd examples in
  this directory
- Event entries now include per-notifier delivery status in their `deliveries` map.
- Signed operators can explicitly trigger reserve consolidation; the service persists consolidation records and includes them in audit export.
- Signed operators can pause new redemptions and inspect a dry-run consolidation plan before broadcasting reserve actions.
- `POST /redemptions/update` and `GET /audit/export` require signed operator headers:
  - `X-Finalis-Operator-Key`
  - `X-Finalis-Timestamp`
  - `X-Finalis-Signature`
- Reserve/accounting/attestation endpoints are derived from persisted deposits, issuances, note records, and redemption state.

## Service tests

```bash
python3 -m unittest services/finalis-mint/test_state.py
python3 -m unittest services/finalis-mint/test_packaging.py
python3 -m unittest services/finalis-mint/test_integration.py
bash services/finalis-mint/systemd/smoke_deploy.sh
```

CI wiring for the packaging/deploy checks lives in:

- [.github/workflows/finalis-mint-packaging.yml](../../.github/workflows/finalis-mint-packaging.yml)

That workflow now runs:
- packaging/state tests
- temp-prefix install smoke check
- split server/worker live integration tests
