# Finalis Mainnet Reference

This document is the canonical mainnet access and operations reference for
exchange and operator integrations.

It should be used together with:

- `docs/EXCHANGE_INTEGRATION.md`
- `docs/EXCHANGE_CHECKLIST.md`
- `docs/LIVE_PROTOCOL.md`

## 1. Network

- network name: `mainnet`
- address HRP: `sc`
- network id: `fe561911730912cced1e83bc273fab13`
- genesis hash: `eaae655a1eec3c876bd2e66d899fc8da93d205a5df36a2665f736387aa3cb78a`
- magic: `0x499602D2` (`1234567890`)
- default p2p port: `19440`
- default lightserver RPC port: `19444`

## 2. Public lightserver RPC endpoints

This repository does not hardcode production public RPC endpoints.
Publish current public endpoints here before sending this reference to external
integrators.

- primary RPC URL: operator-published value
- secondary RPC URL: operator-published value

If multiple public endpoints are available, exchanges should compare them for
agreement on finalized height and finalized transition hash before relying on a
newly added endpoint.

Fresh-genesis note:

- if the network has been relaunched from a new genesis, all published RPC
  endpoints must be revalidated against the new `network_id` and
  `genesis_hash`; old-chain endpoints are irrelevant even if the hostname or IP
  is reused

## 3. Expected RPC behavior

Public lightserver RPC endpoints should expose the current lightserver / wallet
API contract implemented in this repository.

Exchange-relevant expectations:

- `get_status` returns finalized tip identity
- `get_status` returns current adaptive checkpoint observability, including
  qualified depth, adaptive target, adaptive eligible threshold, adaptive bond
  floor, and rolling fallback metrics
- `get_tx_status` returns finalized transaction status for both transparent and
  confidential transactions
- `get_history_page` returns finalized address history only
- `get_utxos` returns finalized UTXO state only
- `broadcast_tx` submits a transaction for relay but does not complete a
  withdrawal

Confidential transaction interpretation:

- confidential transaction presence can be finalized and credit-safe without
  exposing confidential amounts or recipient semantics through public RPC
- explorer / RPC surfaces should expose transaction type, finalized status, and
  consensus identity, but must not invent transparent-style amount/address
  fields for confidential outputs

Settlement decisions must use finalized state only.

## 4. Uptime and availability expectations

Operators publishing public RPC endpoints should define and publish their own
availability target.

Recommended exchange-facing baseline:

- publish at least two independently monitored RPC endpoints when possible
- monitor finalized height progression
- alert on endpoint unavailability
- alert on endpoint lag
- alert on endpoint divergence at the same height

## 5. Software version and compatibility

Published endpoints should identify the serving software version through
`get_status`.

Exchange guidance:

- verify `version` before production enablement
- verify `network_name` is `mainnet`
- verify `sync.mode` is `finalized_only`
- verify `wallet_api_version`
- treat version mismatch across public endpoints as an operational signal to
  review compatibility before depending on that endpoint

## 6. Endpoint consistency guidance

When more than one endpoint is available, exchanges should compare:

- `network_name`
- `network_id`
- `genesis_hash`
- `version`
- `finalized_height`
- `finalized_transition_hash`

Safe interpretation:

- same finalized transition hash at the same height -> healthy
- lower finalized height on one endpoint -> endpoint is lagging
- different finalized transition hashes at the same height -> investigate
  immediately

## 7. Finalized-only interpretation

Finalis exchange integrations should use one rule:

- if a transaction is present in finalized RPC state, it is credit-safe

Operational meaning:

- `finalized = true` means included in finalized ledger state
- `credit_safe = true` means safe for exchange crediting
- `finalized_only` means the API does not represent mempool or pending truth
  for settlement decisions

Exchanges should not build credit logic around:

- mempool visibility
- relay admission
- confirmation counting
- reorg rollback workflows

Ingress and admission safety boundary:

- transaction relay or mempool acceptance is not a settlement signal
- finalized execution consumes certified ingress that is epoch-pinned to the
  current expected epoch
- stale-epoch ingress certificates are rejected by consensus validation paths
- validator-control scripts (`SCONBREG`, `SCVALJRQ`, `SCVALREG`) are validated
  with consistent semantics across legacy `Tx` and transparent outputs in `TxV2`

## 8. Minimal transaction status example

Request:

```json
{"jsonrpc":"2.0","id":1,"method":"get_tx_status","params":{"txid":"<operator-supplied-known-txid>"}}
```

Exchange interpretation:

- `finalized = true` -> credit
- otherwise -> do not credit yet

Do not hardcode a demonstration txid here unless a canonical finalized txid is
published by the operator.

## 9. Self-hosted operator notes

For self-hosted exchange infrastructure:

- CMake auto-fetches `secp256k1-zkp` if the vendored tree is missing (network required)
- for offline builds, disable auto-fetch and provide the vendored tree:
  `cmake -S . -B build -G Ninja -DFINALIS_AUTO_FETCH_DEPS=OFF`
  `git submodule update --init --recursive`
- run your own `finalis-node` with lightserver enabled
- use persistent storage
- expose the lightserver endpoint only through exchange-controlled network
  policy where possible
- monitor finalized height and finalized transition hash continuously
- cross-check multiple endpoints before production crediting

Example startup:

```bash
./build/finalis-node \
  --db ~/.finalis/mainnet \
  --public \
  --with-lightserver \
  --lightserver-bind 0.0.0.0 \
  --lightserver-port 19444
```
