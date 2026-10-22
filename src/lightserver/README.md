# Lightserver Component

## Purpose

`src/lightserver/` contains finalized-state RPC support logic used by the lightserver binary and related read surfaces.

## Responsibilities

- Finalized-state query support.
- RPC-facing glue for status, transaction, and history lookups.

## RPC Surfaces

- TCP (`--bind`/`--port`): public read methods and `broadcast_tx`.
- Admin Unix socket (`--admin-socket`, default `/var/run/finalis/<network>/admin.sock`, mode 0600, peer uid
  checked on Linux): additionally `validator_onboarding_status` / `validator_onboarding_start`
  (keystore unlock). On TCP these answer `method not found`. `--no-admin-socket` disables it.
  Clients use `unix:///var/run/finalis/<network>/admin.sock` (`lightserver::default_admin_rpc_url(network)`).
- Connections are served by a bounded worker pool (4-8 threads, queue of 64); a full queue gets
  HTTP 503 with `Retry-After`.
- Public rate limits (token buckets): 100 req/min per IP, `broadcast_tx` 10/min per IP, 1000/min
  global; over limit returns HTTP 429 with `Retry-After`. Loopback peers are exempt unless
  `--rate-limit-loopback` is set. Behind a same-host reverse proxy use `--trusted-proxy 127.0.0.1/32`
  (node: `--lightserver-trusted-proxy`): requests it forwards are limited by their `X-Real-IP` and
  never exempt.
- Light-client proofs ([docs/spec/LIGHT_CLIENT.md](../../docs/spec/LIGHT_CLIENT.md)):
  `get_committee_handoffs` (each epoch's committee, proven from the previous one) and
  `get_utxo_proofs` (UTXO membership proofs with the tip's transition and certificate), so clients
  can check answers against validator signatures instead of trusting this server.
- Responses read by the client library are capped at 16 MB (servers are untrusted).
- Operator runbook: [docs/operations/LIGHTSERVER-OPERATIONS.md](../../docs/operations/LIGHTSERVER-OPERATIONS.md).

## Non-Goals

- Consensus evolution rules.
- Wallet desktop UX concerns.

## Dependency Notes

- Depends on storage/state and shared protocol types.
- Should keep API surface deterministic and finalized-state focused.
