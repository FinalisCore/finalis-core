# Finalis Explorer

`Finalis Explorer` is a thin in-tree explorer for exchange and operator support.

Current restarted mainnet identity reference:

- `network_name = mainnet`
- `network_id = fe561911730912cced1e83bc273fab13`
- `genesis_hash = eaae655a1eec3c876bd2e66d899fc8da93d205a5df36a2665f736387aa3cb78a`

It is intentionally narrow:

- backed by `finalis-lightserver`
- finalized-state only
- no consensus logic
- no independent canonical index
- no marketing UI
- local-first cached startup / tx / transition views

Supported routes:

- `/committee`
- `/tx/<txid>`
- `/transition/<height>`
- `/transition/<hash>`
- `/address/<address>`
- `/search?q=<query>`

Supported API routes:

- `/healthz`
- `/api/status`
- `/api/committee`
- `/api/recent-tx`
- `/api/tx/<txid>`
- `/api/transition/<height_or_hash>`
- `/api/address/<address>`
- `/api/search?q=<query>`
- `/api/v1/status`
- `/api/v1/committee`
- `/api/v1/recent-tx`
- `/api/v1/tx/<txid>`
- `/api/v1/transition/<height_or_hash>`
- `/api/v1/address/<address>`
- `/api/v1/search?q=<query>`
- `/api/v1/transactions/status:batch` (POST)
- `/api/v1/withdrawals` (POST)
- `/api/v1/withdrawals/<client_withdrawal_id_or_txid>`
- `/api/v1/events/finalized?from_sequence=<n>`
- `/api/v1/fees/recommendation`
- `/api/v1/webhooks/dlq`
- `/api/v1/webhooks/dlq/replay` (POST)
- `/metrics`

What it shows:

- current bounded Ticket PoW difficulty, clamp, epoch health, and streaks
- current finalized committee operator view with representative pubkey, base
  weight, ticket bonus, and final weight
- page-level summaries for operator-facing views:
  - homepage recent activity summary
  - committee summary cards
  - transaction payment summary
  - transition summary cards
  - address visible-slice summary
- transaction finalized status, credit-safe status, transition linkage,
  finalized flow classification, inferred payer/payee summary, timestamp when
  available, inputs, and outputs
- transition height, hash, previous finalized hash, timestamp, tx list, and a
  finalized summary layer:
  - tx count
  - finalized out
  - distinct recipients
  - flow mix
- address finalized UTXOs and finalized history with address-relative direction:
  - received
  - sent
  - self-transfer
- recent finalized transaction activity on the homepage
- copyable page/API paths for operator and support workflows
- stable finalized-only JSON for exchange, wallet, and mobile consumers
- cached-vs-live provenance and per-surface freshness markers
- adaptive checkpoint regime observability:
  - qualified operator depth
  - adaptive committee target
  - adaptive eligible threshold
  - adaptive bond floor
  - eligibility slack
  - target expand / contract streaks
  - rolling fallback and sticky-fallback rates
  - telemetry summary counts
  - adaptive alert flags

What it does not show:

- non-finalized or mempool state
- durable withdrawal tracking
- state outside current lightserver capabilities
- any non-finalized object as a creditable transaction
- transparent-style confidential amount or recipient disclosure

Transaction status semantics:

- `finalized: true` means the transaction is in finalized state
- `credit_safe: true` means the explorer is presenting the transaction as safe
  to credit from finalized state
- tx page labels use:
  - `FINALIZED (CREDIT SAFE)`
  - `FINALIZED`
  - `NOT FINALIZED`

## Canonical terminology

- `accepted_for_relay`
  - relay admission only
  - not inclusion
  - not finality
- `flow`
  - explorer-side interpretation of finalized tx structure
  - not wallet ownership proof
- `finalized_out`
  - sum of finalized outputs in a finalized transaction or aggregate view
  - explorer keeps legacy `total_out` aliases where needed for compatibility
- `recipient_count`
  - count of decoded finalized output recipients
- `net_amount`
  - signed address-relative amount in address history
  - positive means net received in the finalized transaction
  - negative means net sent in the finalized transaction
- `finalized`
  - present in finalized state
- `finalized_only`
  - response is limited to finalized-state data
- `credit_safe`
  - current finalized-state view is safe to credit
- `not_finalized`
  - not present in finalized explorer state
- mempool diagnostics
  - local operational hints only
- `relay_unavailable`
  - relay transport failure, not a settlement verdict

## API semantics

All API responses are finalized-only and include:

- `finalized_only: true`

Partner API v1:

- `GET /api/v1/...` mirrors stable finalized read surfaces with explicit
  `api_version: "v1"` in responses
- `POST /api/v1/withdrawals` provides idempotent withdrawal submission using
  `Idempotency-Key`
  - response includes `idempotency` metadata:
    - `status` (`created`, `replayed`, `bound_existing`)
    - `first_seen_unix_ms`
    - `request_hash` (SHA256 of request body)
- `GET /api/v1/withdrawals/<client_withdrawal_id_or_txid>` provides one
  canonical lifecycle shape
- `GET /api/v1/events/finalized?from_sequence=<n>` provides a replayable
  finalized event feed
- `GET /api/v1/fees/recommendation` provides fee policy guidance for
  withdrawal submitters
- governance and compatibility policy:
  - `apps/finalis-explorer/PARTNER_API_CHANGELOG.md`
  - `apps/finalis-explorer/PARTNER_API_DEPRECATIONS.md`
  - OpenAPI diff + changelog/deprecation gate:
    - canonical checker: `scripts/check_partner_api_governance.py`
    - compatibility wrapper: `apps/finalis-explorer/scripts/check_partner_api_governance.py`
  - CI runner command:
    - `apps/finalis-explorer/scripts/partner_api_governance_ci.sh <base-ref> <head-ref>`

Contract guarantees:

- response headers:
  - every `/api/v1/*` response emits `X-Finalis-Api-Version: v1`
  - legacy `/api/*` partner routes emit:
    - `Deprecation: true`
    - `Sunset: Wed, 31 Dec 2026 23:59:59 GMT`
    - `Link: </api/v1/...>; rel="successor-version"`
- stable error envelope:
  - `{"error":{"code":"<stable_code>","message":"<human_message>"}}`
- deterministic partner status classes:
  - `400` malformed request/body/query
  - `401` auth material/clock/mtls failures
  - `403` auth denied (key/scope/lifecycle/ip/signature)
  - `404` finalized object not found
  - `405` method not allowed
  - `409` idempotency/replay conflict
  - `429` partner rate limit exceeded
  - `502` upstream RPC unavailable/error

Compatibility rules:

- additive changes (new optional fields/endpoints) require OpenAPI + changelog
  update with semver increase
- breaking/deprecating changes require:
  - OpenAPI semver increase
  - changelog top entry with concrete deltas
  - deprecations doc update with sunset window
  - runtime legacy headers (`Deprecation`/`Sunset`/`Link`) in explorer

Partner auth (when enabled):

- configured by:
  - `--partner-auth-required 1`
  - `--partner-api-key <key>`
  - `--partner-api-secret <secret>`
- protected `v1` endpoints require:
  - `X-Finalis-Api-Key`
  - `X-Finalis-Timestamp` (unix seconds)
  - `X-Finalis-Nonce`
  - `X-Finalis-Signature` (hex HMAC-SHA256)
- canonical signature payload:
  - `METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + SHA256_HEX(BODY)`
- replay protection:
  - nonce reuse inside the allowed skew window is rejected
- basic per-partner rate limit:
  - configured by `--partner-rate-limit-per-minute`
  - limit responses return `429` with `Retry-After`
- optional mTLS verification gate for protected partner endpoints:
  - `--partner-mtls-required 1`
  - requires header `X-Finalis-Mtls-Verified: true`
- optional global source CIDR allowlist:
  - `--partner-allowed-ipv4-cidrs 10.0.0.0/8,127.0.0.1/32`
  - startup rejects malformed CIDRs (global or partner-level) with explicit
    config error; invalid allowlists are never accepted silently

Multi-tenant partner registry:

- configure with `--partner-registry /path/partners.json`
- registry entries support:
  - `partner_id`
  - `api_key`
  - `active_secret`
  - optional `lifecycle_state` (`active`, `draining`, `revoked`)
  - optional `next_secret` (rotation window acceptance)
  - optional `rate_limit_per_minute`
  - optional `scope_rate_limit_per_minute` object:
    - `read`
    - `withdraw_submit`
    - `events_read`
    - `webhook_manage`
  - optional `webhook_url`
  - optional `webhook_secret`
  - optional `allowed_ipv4_cidrs`
  - optional `scopes` (`read`, `withdraw_submit`, `events_read`,
    `webhook_manage`)
  - optional `enabled`
- when a registry is loaded, partner auth is enabled for protected `/api/v1/*`
  routes automatically
- lifecycle enforcement:
  - `active`: normal authenticated behavior
  - `draining`: read/event/webhook management remains available, new withdrawal
    submission is rejected with `403 auth_partner_draining`
  - `revoked`: all protected partner operations are rejected with
    `403 auth_partner_revoked`
- scope enforcement matrix on protected `/api/v1/*` routes:
  - `read`: finalized read APIs (`/status` excepted as public, plus
    `/committee`, `/recent-tx`, `/tx/*`, `/transition/*`, `/address/*`,
    `/search`, `/withdrawals/{id}`)
  - `withdraw_submit`: `POST /api/v1/withdrawals`
  - `events_read`: `GET /api/v1/events/finalized`
  - `webhook_manage`: `GET /api/v1/webhooks/dlq`,
    `POST /api/v1/webhooks/dlq/replay`
- rate-limit precedence:
  - if `scope_rate_limit_per_minute.<scope>` is present, it overrides
    `rate_limit_per_minute` for that scope
  - otherwise `rate_limit_per_minute` is used

Minimal `partners.json` lifecycle example:

```json
{
  "partners": [
    {
      "partner_id": "exchange-a",
      "api_key": "ex_a_key",
      "active_secret": "ex_a_secret",
      "lifecycle_state": "active",
      "scope_rate_limit_per_minute": {
        "read": 1200,
        "withdraw_submit": 120,
        "events_read": 600,
        "webhook_manage": 120
      },
      "scopes": ["read", "withdraw_submit", "events_read", "webhook_manage"],
      "webhook_url": "https://exchange-a.example/webhooks/finalis",
      "webhook_secret": "ex_a_webhook_secret"
    },
    {
      "partner_id": "exchange-b",
      "api_key": "ex_b_key",
      "active_secret": "ex_b_secret",
      "lifecycle_state": "draining",
      "scopes": ["read", "events_read", "webhook_manage"]
    },
    {
      "partner_id": "exchange-c",
      "api_key": "ex_c_key",
      "active_secret": "ex_c_secret",
      "lifecycle_state": "revoked",
      "enabled": true
    }
  ]
}
```

Webhook delivery:

- finalized withdrawal transitions enqueue signed webhook deliveries when
  `webhook_url` and `webhook_secret` are configured for that partner
- payload contains:
  - `delivery_id` (stable deterministic identifier per partner+event sequence)
  - `event`
  - `signature` (`hmac_sha256` over event JSON)
- delivery retries use exponential backoff:
  - `--partner-webhook-max-attempts`
  - `--partner-webhook-max-replay-attempts`
  - `--partner-webhook-initial-backoff-ms`
  - `--partner-webhook-max-backoff-ms`
- persisted-state GC/TTL bounds:
  - `--partner-idempotency-ttl-seconds` (default `604800`)
  - `--partner-events-ttl-seconds` (default `2592000`)
  - `--partner-webhook-queue-ttl-seconds` (default `604800`)
- webhook crash-recovery semantics are at-least-once:
  - queue entries are durable
  - successful delivery removes an entry
  - crash before snapshot flush may replay a webhook after restart
- exhausted retries move deliveries to partner-scoped DLQ
- DLQ records include replay controls:
  - `delivery_id`
  - `replay_attempts`
  - `quarantined`
  - `quarantine_reason`
- replay DLQ entries with:
  - `POST /api/v1/webhooks/dlq/replay`
  - accepts `sequence` or `delivery_id`
  - once `replay_attempts` reaches `--partner-webhook-max-replay-attempts`, entry is quarantined and replay is rejected (`409`)
- legacy route deprecation signaling:
  - `/api/v1/*` emits `X-Finalis-Api-Version: v1`
  - legacy `/api/*` partner routes emit:
    - `Deprecation: true`
    - `Sunset: Wed, 31 Dec 2026 23:59:59 GMT`
    - `Link: </api/v1/...>; rel=\"successor-version\"`

Prometheus partner/SRE metrics (`GET /metrics`) include:

- auth and abuse:
  - `finalis_partner_auth_failures_total`
  - `finalis_partner_auth_failures_by_reason_total{reason=...}`
  - `finalis_partner_rate_limited_total`
  - `finalis_partner_rate_limited_by_scope_total{scope=...}`
  - `finalis_partner_rate_limited_by_partner_scope_total{partner_id=...,scope=...}`
- webhook reliability:
  - `finalis_partner_webhook_deliveries_total`
  - `finalis_partner_webhook_failures_total`
  - `finalis_partner_webhook_dlq_total`
  - `finalis_partner_webhook_replays_total`
  - `finalis_partner_webhook_quarantined_total`
  - `finalis_partner_webhook_delivery_latency_seconds_*{outcome=success|failure}`
- backlog and lag:
  - `finalis_partner_webhook_queue_depth`
  - `finalis_partner_webhook_dlq_depth`
  - `finalis_partner_webhook_oldest_age_seconds`
  - `finalis_partner_webhook_queue_depth_by_partner{partner_id=...}`
  - `finalis_partner_webhook_dlq_depth_by_partner{partner_id=...}`
  - `finalis_partner_webhook_oldest_age_seconds_by_partner{partner_id=...}`

Alert-friendly SLI/SLO profile (recommended):

- evaluation windows:
  - fast detection: `5m`
  - paging: `15m`
  - SLO tracking: `30d`
- target SLOs:
  - partner auth success ratio: `>= 99.90%` over `30d`
  - webhook delivery success ratio: `>= 99.50%` over `30d`
  - webhook p95 delivery latency: `<= 60s` over `30d`
  - webhook p99 delivery latency: `<= 300s` over `30d`
  - webhook queue oldest age: `<= 120s` steady-state
  - DLQ depth: `0` steady-state, non-zero is operational debt

SLI formulas (PromQL style):

- auth success ratio:
  - `1 - (increase(finalis_partner_auth_failures_total[30d]) / clamp_min(increase(finalis_http_requests_total{route=~"/api/v1/.*",status=~"2..|4..|5.."}[30d]), 1))`
- webhook delivery success ratio:
  - `increase(finalis_partner_webhook_deliveries_total[30d]) / clamp_min(increase(finalis_partner_webhook_deliveries_total[30d]) + increase(finalis_partner_webhook_failures_total[30d]), 1)`
- webhook latency p95:
  - `histogram_quantile(0.95, sum by (le) (rate(finalis_partner_webhook_delivery_latency_seconds_bucket{outcome="success"}[30d])))`
- webhook latency p99:
  - `histogram_quantile(0.99, sum by (le) (rate(finalis_partner_webhook_delivery_latency_seconds_bucket{outcome="success"}[30d])))`
- queue age:
  - `max(finalis_partner_webhook_oldest_age_seconds)`
- DLQ depth:
  - `sum(finalis_partner_webhook_dlq_depth)`

Recommended alerts:

- `SEV2 PartnerAuthFailureSpike`:
  - trigger: auth failure ratio `> 2%` for `5m`
  - escalation: if `> 5%` for `15m`
- `SEV2 WebhookDeliveryDegraded`:
  - trigger: webhook failure ratio `> 1%` for `15m`
  - escalation: if `> 5%` for `15m`
- `SEV2 WebhookLatencyHigh`:
  - trigger: p95 latency `> 60s` for `15m`
  - escalation: p99 latency `> 300s` for `15m`
- `SEV1 WebhookBacklogGrowing`:
  - trigger: `finalis_partner_webhook_oldest_age_seconds > 300` for `10m`
- `SEV2 DlqNonZero`:
  - trigger: `sum(finalis_partner_webhook_dlq_depth) > 0` for `15m`
- `SEV2 PerPartnerBacklog`:
  - trigger: any `finalis_partner_webhook_queue_depth_by_partner > 100` for `10m`

Operator response order (recommended):

- inspect auth failure reason mix:
  - `sum by (reason) (increase(finalis_partner_auth_failures_by_reason_total[15m]))`
- inspect per-partner backlog and age:
  - `finalis_partner_webhook_queue_depth_by_partner`
  - `finalis_partner_webhook_oldest_age_seconds_by_partner`
- inspect DLQ entries:
  - `GET /api/v1/webhooks/dlq`
- replay fixed deliveries after root-cause mitigation:
  - `POST /api/v1/webhooks/dlq/replay`

Health behavior:

- `GET /healthz` returns JSON only
- `200` means the explorer process is up and can reach the required upstream
  `get_status` path on `finalis-lightserver`
- `502` means upstream is unavailable or returned an invalid response
- explorer does not maintain its own chain or index state

Error behavior:

- `400` malformed identifier/query
- `404` well-formed but not found in finalized state
- `502` upstream lightserver failure

Error body shape:

```json
{
  "error": {
    "code": "machine_code",
    "message": "short message"
  }
}
```

Search classification is deterministic:

1. numeric query:
   - always treated as transition height
   - unknown finalized height returns `404`
2. 64-hex query:
   - resolved as tx first
   - if no finalized tx is found, resolved as transition hash
   - if neither exists in finalized state, search returns `classification: "not_found"`
3. valid Finalis address

Address behavior:

- malformed address -> `400`
- valid address with finalized activity -> `200`
- valid address with no finalized activity -> `200` with:
  - `found: false`
  - empty `utxos`
  - empty `history.items`
  - `has_more: false`
  - `next_cursor: null`
- address history items are address-relative and expose:
  - `direction`
  - `net_amount`
  - `detail`
- address responses also expose a visible-slice `summary`:
  - `finalized_balance`
  - `received`
  - `sent`
  - `self_transfer`
- `history.has_more` indicates whether another finalized history page exists
- `history.next_cursor` is only non-null when another page exists
- if `history.has_more` is `false`, `history.next_cursor` is always `null`
- `history.next_page_path` is a user-facing explorer path for older finalized
  history
- `history.loaded_pages` reports how many backend history pages were merged into
  the visible slice

API contract is intended to be stable for exchange, wallet, mobile, and
operator consumers.

Ticket PoW observability:

- `/api/status` includes a `ticket_pow` object
- `/api/status` includes current adaptive checkpoint observability and the
  separate `adaptive_telemetry_summary` block
- `/api/committee` shows the current finalized committee with operator-facing
  weight fields
- explorer presents Ticket PoW as bounded, operator-based, and secondary to
  bond and BFT finality
- the restarted mainnet begins directly on the live bounded-search policy

Fresh-genesis boundary:

- if an explorer endpoint reports a different `network_id` or `genesis_hash`,
  treat it as a different network immediately
- abandoned-chain explorer data must not be interpreted as current mainnet data

## Exchange Integration

Explorer API is finalized-only.

Recommended deposit flow:

1. call `/api/tx/<txid>`
2. ensure `finalized=true`
3. ensure `credit_safe=true`
4. credit the user

Finalis does not expose mempool or unfinalized transaction state via the
explorer API.

After finalization, explorer surfaces canonical finalized state only. There is
no reorg-handling flow in the explorer integration path.

## Ticket PoW (Operational Summary)

- one operator = one bounded search
- fixed nonce budget: `4096`
- bounded bonus capped in `bps`
- live difficulty clamp: `8..12`
- streak-based adjustment
- operator-based ticket search
- secondary to bond
- does not affect BFT finality

## API Stability

Stable finalized surfaces:

- `/api/status`
  - `finalized_height`
  - `finalized_transition_hash`
  - `ticket_pow`
- `/api/committee`
  - current finalized committee operator view
- `/api/tx/<txid>`
  - finalized-only transaction status
  - returns `404` if the tx is not finalized in explorer state
- `/api/transition/<height_or_hash>`
  - finalized transition plus `summary`:
    - `tx_count`
    - `finalized_out`
    - `distinct_recipient_count`
    - `flow_mix`
- `/api/address/<address>`
  - finalized-only address view
  - includes `summary` and address-relative history
- `/api/recent-tx`
  - recent finalized activity
  - includes top-level `summary`
  - recent items include:
    - `finalized_out`
    - `fee`
    - `flow_kind`
    - `flow_summary`
    - `primary_sender`
    - `primary_recipient`

Related lightserver note:

- lightserver `get_committee` keeps its legacy default array response
- lightserver `get_committee` with `verbose=true` exposes the stable extended
  operator breakdown
- explorer `/api/committee` always serves the structured current finalized view

Stability guarantees:

- field names are stable across minor releases
- new fields may be added
- existing fields will not change meaning silently
- breaking changes require an explicit version bump or clearly announced
  compatibility change

Version note:

- explorer presents the live bounded-search ticket policy
- the restarted mainnet begins with the live bounded-search policy active from
  genesis

## Example Responses

`GET /api/status`

```json
{
  "network": "mainnet",
  "finalized_height": 225,
  "finalized_transition_hash": "32a442db9ee0325a19b610f80aaa65d0795288364d63a6a10c805dbaacdf4197",
  "backend_version": "finalis-lightserver/1.x",
  "ticket_pow": {
    "difficulty": 10,
    "difficulty_min": 8,
    "difficulty_max": 12,
    "epoch_health": "healthy",
    "streak_up": 1,
    "streak_down": 0,
    "nonce_search_limit": 4096,
    "bonus_cap_bps": 1000
  },
  "finalized_only": true
}
```

`GET /api/committee`

```json
{
  "height": 225,
  "epoch_start_height": 225,
  "members": [
    {
      "operator_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "representative_pubkey": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "base_weight": 100,
      "ticket_bonus_bps": 1000,
      "final_weight": 1010000,
      "ticket_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "ticket_nonce": 12
    }
  ],
  "finalized_only": true
}
```

`GET /api/tx/<txid>`

```json
{
  "txid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "finalized": true,
  "finalized_height": 608,
  "credit_safe": true,
  "status_label": "FINALIZED (CREDIT SAFE)",
  "transition_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "finalized_out": 41000000000,
  "total_out": 41000000000,
  "fee": 1000,
  "flow": {
    "kind": "transfer-with-change",
    "summary": "Likely payment with one external recipient and one change output"
  },
  "primary_sender": "sc1...",
  "primary_recipient": "sc1...",
  "recipient_count": 2,
  "participant_count": 2,
  "finalized_only": true
}
```

`GET /api/transition/<height_or_hash>`

```json
{
  "height": 608,
  "hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "tx_count": 3,
  "summary": {
    "tx_count": 3,
    "finalized_out": 74135649710,
    "distinct_recipient_count": 2,
    "flow_mix": {
      "transfer-with-change": 2,
      "issuance": 1
    }
  },
  "finalized_only": true
}
```

`GET /api/address/<address>`

```json
{
  "address": "sc1...",
  "found": true,
  "finalized_balance": 74135649710,
  "summary": {
    "finalized_balance": 74135649710,
    "received": 74135649710,
    "sent": 0,
    "self_transfer": 0
  },
  "history": {
    "items": [
      {
        "txid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "height": 608,
        "direction": "received",
        "net_amount": 74135649710,
        "detail": "Finalized credit to this address"
      }
    ],
    "has_more": false,
    "next_cursor": null,
    "next_page_path": null,
    "loaded_pages": 1
  },
  "finalized_only": true
}
```

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target finalis-explorer -j"$(nproc)"
```

## Run

Run a synced node and lightserver first, then:

```bash
./build/finalis-explorer \
  --bind 127.0.0.1 \
  --port 18080 \
  --rpc-url http://127.0.0.1:19444/rpc
```

Open:

```text
http://127.0.0.1:18080/
```

## Backend assumptions

- lightserver is reachable over HTTP JSON-RPC
- lightserver is returning finalized state
- `get_tx_status`, `get_transition_by_height`, `get_history_page`, `get_tx`,
  `get_transition`, `get_utxos`, `get_status`, and `get_committee` are available

## Deployment notes

- `finalis-explorer` is intended to sit behind a reverse proxy such as nginx or
  caddy for public exposure
- the explorer remains a thin finalized-state read surface and does not maintain
  its own chain/index database
- `/healthz` is suitable for simple process-plus-upstream reachability checks

Branding note:

- the shipped binary target is `finalis-explorer`

## Manual verification checklist

1. Open `/` and confirm the explorer shows the configured lightserver and the
   current finalized tip.
2. Open `/transition/<height>` for a known finalized height and confirm:
   - finalized badge is visible
   - transition hash and previous finalized hash are shown
   - tx list is shown
3. Open `/tx/<txid>` for a known finalized tx and confirm:
   - finalized badge is visible
   - finalized transition height/hash are linked
   - outputs are shown
4. Open `/address/<address>` for a known address and confirm:
   - finalized-only note is visible
   - UTXOs and/or finalized history appear
5. Open `/tx/<unknown-txid>` and confirm the page states the tx is not present
   in finalized lightserver state.
