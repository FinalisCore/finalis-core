# Lightserver Component

## Purpose

`src/lightserver/` contains finalized-state RPC support logic used by the lightserver binary and related read surfaces.

## Responsibilities

- Finalized-state query support.
- RPC-facing glue for status, transaction, and history lookups.

## RPC Surfaces

- TCP (`--bind`/`--port`): public read methods and `broadcast_tx`.
- Admin Unix socket (`--admin-socket`, default `/var/run/finalis/admin.sock`, mode 0600, peer uid
  checked on Linux): additionally `validator_onboarding_status` / `validator_onboarding_start`
  (keystore unlock). On TCP these answer `method not found`. `--no-admin-socket` disables it.
  Clients use `unix:///var/run/finalis/admin.sock` (`lightserver::kDefaultAdminRpcUrl`).
- Connections are served by a bounded worker pool (4-8 threads, queue of 64); a full queue gets
  HTTP 503 with `Retry-After`.
- Public rate limits (token buckets): 100 req/min per IP, `broadcast_tx` 10/min per IP, 1000/min
  global; over limit returns HTTP 429 with `Retry-After`. Loopback peers are exempt unless
  `--rate-limit-loopback` is set (required behind a same-host reverse proxy).
- Operator runbook: [docs/operations/LIGHTSERVER-OPERATIONS.md](../../docs/operations/LIGHTSERVER-OPERATIONS.md).

## Non-Goals

- Consensus evolution rules.
- Wallet desktop UX concerns.

## Dependency Notes

- Depends on storage/state and shared protocol types.
- Should keep API surface deterministic and finalized-state focused.
