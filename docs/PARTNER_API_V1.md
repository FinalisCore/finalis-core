# Finalis Partner API v1

This document defines the exchange-facing `v1` contract exposed by `finalis-explorer`.

Machine-readable OpenAPI contract:

- `openapi/finalis-partner-v1.yaml`
- `docs/PARTNER_API_REFERENCE.md` (generated)

Governance artifacts:

- `docs/PARTNER_API_COMPATIBILITY_POLICY.md`
- `docs/PARTNER_API_CHANGELOG.md`
- `docs/PARTNER_API_DEPRECATIONS.md`

Base routes:

- `GET /api/v1/status`
- `GET /api/v1/committee`
- `GET /api/v1/recent-tx`
- `GET /api/v1/tx/{txid}`
- `GET /api/v1/transition/{id}`
- `GET /api/v1/address/{address}`
- `GET /api/v1/search?q=<query>`
- `POST /api/v1/transactions/status:batch`
- `POST /api/v1/withdrawals`
- `GET /api/v1/withdrawals/{id}`
- `GET /api/v1/events/finalized?from_sequence=<n>`
- `GET /api/v1/fees/recommendation`
- `GET /api/v1/webhooks/dlq`
- `POST /api/v1/webhooks/dlq/replay`

## Withdrawal lifecycle

States:

- `submitted`
- `accepted_for_relay`
- `finalized`
- `rejected`

Transition rules:

- `submitted -> accepted_for_relay`
- `submitted -> rejected`
- `accepted_for_relay -> finalized`

`finalized` and `rejected` are terminal.

## Idempotency

`POST /api/v1/withdrawals` requires `Idempotency-Key`.

Rules:

- same key + same request body => returns the original withdrawal record
- same key + different request body => `409 idempotency_conflict`

## Partner auth

When enabled, protected partner routes require:

- `X-Finalis-Api-Key`
- `X-Finalis-Timestamp` (unix seconds)
- `X-Finalis-Nonce`
- `X-Finalis-Signature` (hex HMAC-SHA256)

Canonical signed string:

`METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + SHA256_HEX(BODY)`

Nonce replay inside the configured skew window is rejected.

Multi-tenant behavior:

- auth resolves partner identity by `api_key`
- idempotency and withdrawal tracking are partner-scoped
- optional `next_secret` allows key rotation windows without downtime
- optional `allowed_ipv4_cidrs` enforces source CIDR allowlist per partner
- optional `scopes` enforces per-partner permissions:
  - `read`
  - `withdraw_submit`
  - `events_read`
  - `webhook_manage`
- optional deployment-wide mTLS gate via `X-Finalis-Mtls-Verified` when
  `partner_mtls_required=true`

## Webhook delivery

If a partner registry entry provides `webhook_url` and `webhook_secret`,
Finalis delivers signed webhook notifications when a withdrawal transitions to
`finalized`.

Payload shape:

- `event`: finalized event object
- `delivery_id`: stable deterministic delivery identifier
- `signature`: hex `HMAC-SHA256(webhook_secret, event_json)`
- `signature_algorithm`: `hmac_sha256`

Delivery policy:

- at-least-once delivery
- crash before queue-snapshot flush can replay a delivered event after restart
- exponential retry backoff
- bounded by configured max attempts
- consumers should deduplicate by `delivery_id` (or `(partner_id, sequence)`)
- terminal failures are moved to partner DLQ
- DLQ replay is available via `POST /api/v1/webhooks/dlq/replay` using
  `sequence` or `delivery_id`
- persisted partner state is GC-bounded by TTL controls:
  - `partner_idempotency_ttl_seconds`
  - `partner_events_ttl_seconds`
  - `partner_webhook_queue_ttl_seconds`

## Retry model

- `400`: malformed input; do not retry
- `401/403`: auth/signature issue; fix request then retry
- `404`: not found in finalized state
- `409`: idempotency conflict; do not retry with modified body
- `429`: rate limited; retry after `Retry-After`
- `502/503`: upstream or service pressure; retry with backoff
