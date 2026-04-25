# Partner API Changelog (Explorer Scope)

## v1.2.2 - 2026-04-25

- Enforced partner route method policy through centralized runtime method map
  (`required_partner_method_for_path`) for `/api/v1/*`.
- Moved partner governance header application into shared response builders so
  `/api/v1/*` and legacy `/api/*` compatibility headers are applied
  deterministically for all explorer responses.
- Consolidated governance checker implementation to canonical
  `scripts/check_partner_api_governance.py`; app script now delegates to the
  canonical checker for backwards-compatible local calls.
- Strengthened canonical governance checker to require runtime contract markers
  in `apps/finalis-explorer/main.cpp` in addition to OpenAPI/changelog checks.
- Documented alert-friendly contract guarantees and compatibility rules directly
  in explorer README.
- Added structured partner auth audit logging (`--partner-auth-audit-log-path`)
  with deterministic reason/status fields for success and failure decisions.
- Added `GET /api/v1/audit/auth` (partner-scoped) for exchange ops to inspect
  recent auth denials (`include_success=1` optional).

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
