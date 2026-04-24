# Partner API Deprecations (Explorer Scope)

This document tracks deprecated partner-facing routes and required migration behavior.

## Legacy `/api/*` surfaces

- Scope: legacy non-versioned JSON routes under `/api/*` used before partner packaging lock.
- Deprecation header: `Deprecation: true`
- Sunset: `Wed, 31 Dec 2026 23:59:59 GMT`
- Successor signaling:
  - `Link: </api/v1/...>; rel="successor-version"`
  - `X-Finalis-Api-Successor: /api/v1/...`

Mapped legacy routes:

- `/api/status` -> `/api/v1/status`
- `/api/committee` -> `/api/v1/committee`
- `/api/recent-tx` -> `/api/v1/recent-tx`
- `/api/search` -> `/api/v1/search`
- `/api/tx/<txid>` -> `/api/v1/tx/<txid>`
- `/api/transition/<height_or_hash>` -> `/api/v1/transition/<height_or_hash>`
- `/api/address/<address>` -> `/api/v1/address/<address>`
