# Partner API Changelog (Explorer Scope)

## v1.2.1 - 2026-04-24

- Added explicit idempotency metadata to `POST /api/v1/withdrawals`
  responses:
  - `idempotency.status` (`created`, `replayed`, `bound_existing`)
  - `idempotency.first_seen_unix_ms`
  - `idempotency.request_hash`
- Clarified deterministic idempotency TTL reuse behavior and added test coverage
  for conflict-vs-expiry paths.

## v1.1.1 - 2026-04-24

- Added governance-facing runtime headers for strict contract migration behavior:
  - `/api/v1/*` now emits `X-Finalis-Api-Version: v1`.
  - legacy `/api/*` partner routes now emit `Deprecation`, `Sunset`, and `Link` successor headers.
- Added app-scope governance checker (`apps/finalis-explorer/scripts/check_partner_api_governance.py`) for:
  - OpenAPI diff summary and semver bump checks
  - changelog-entry enforcement
  - deprecation-policy enforcement

## v1.1.0 - 2026-04-23

- Introduced batch status, withdrawal lifecycle, finalized events, fee recommendation, and webhook DLQ management in partner API v1.
- Established stable finalized-only response semantics and idempotent submission behavior.
