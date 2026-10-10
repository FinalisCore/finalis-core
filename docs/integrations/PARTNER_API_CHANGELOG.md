# Partner API Changelog

This changelog tracks contract-level changes for:

- `openapi/finalis-partner-v1.yaml`

Entry format:

- heading: `## YYYY-MM-DD - vX.Y.Z [NON-BREAKING|BREAKING]`
- include changed endpoints/schemas and operational impact

## 2026-04-24 - v1.2.1 [NON-BREAKING]

- Added explicit idempotency replay metadata to `POST /api/v1/withdrawals`
  responses:
  - `idempotency.status` (`created`, `replayed`, `bound_existing`)
  - `idempotency.first_seen_unix_ms`
  - `idempotency.request_hash`
- Clarified TTL-boundary behavior for idempotency keys and added test coverage
  for stale-key reuse after expiry.

## 2026-04-24 - v1.2.0 [NON-BREAKING]

- Brought OpenAPI into full parity with implemented explorer `v1` routes.
- Added missing contract paths:
  - `GET /api/v1/committee`
  - `GET /api/v1/recent-tx`
  - `GET /api/v1/tx/{txid}`
  - `GET /api/v1/transition/{id}`
  - `GET /api/v1/address/{address}`
  - `GET /api/v1/search`
- Expanded schemas to explicit request/response shapes for all `v1` endpoints,
  including:
  - webhook DLQ item fields (`delivery_id`, `replay_attempts`, `quarantined`,
    `quarantine_reason`, `quarantined_unix_ms`)
  - replay selector contract (`sequence` or `delivery_id`)
  - finalized state read surfaces (`status`, `committee`, `recent`, `tx`,
    `transition`, `address`, `search`)
- Added explicit error response coverage (`400/401/403/404/409/429/502`) for
  partner endpoints where applicable.

## 2026-04-22 - v1.1.0 [NON-BREAKING]

- Added webhook DLQ management endpoints:
  - `GET /api/v1/webhooks/dlq`
  - `POST /api/v1/webhooks/dlq/replay`
- Clarified partner auth scope model and operational controls for mTLS edge
  verification and source CIDR allowlisting.

## 2026-04-22 - v1.0.0 [NON-BREAKING]

- Established initial `/api/v1` partner contract and OpenAPI publication.
- Added idempotent withdrawal submit/read lifecycle, batch tx status, finalized events feed, and fee recommendation endpoint.
- Added multi-tenant auth model (`api_key`, `active_secret`, optional `next_secret`) and webhook delivery semantics.
