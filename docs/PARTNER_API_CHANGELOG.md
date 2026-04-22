# Partner API Changelog

This changelog tracks contract-level changes for:

- `openapi/finalis-partner-v1.yaml`

Entry format:

- heading: `## YYYY-MM-DD - vX.Y.Z [NON-BREAKING|BREAKING]`
- include changed endpoints/schemas and operational impact

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
