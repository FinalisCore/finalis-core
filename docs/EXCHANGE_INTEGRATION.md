# Finalis Exchange Integration Guide

This document describes the current live exchange integration model for
`finalis-core`.

Finalis exposes finalized-state settlement surfaces. Exchange accounting should
use finalized state only.

The exchange rule is:

- credit deposits only from finalized visibility
- complete withdrawals only from finalized visibility
- treat relay admission as submission only, not settlement

There is no exchange-side confirmation-count model after finalization and no
ordinary reorg-rollback branch in accounting logic.

Use this with:

- [EXCHANGE_API_EXAMPLES.md](EXCHANGE_API_EXAMPLES.md)
- [EXCHANGE_CHECKLIST.md](EXCHANGE_CHECKLIST.md)
- [EXCHANGE_OPERATOR_RUNBOOK.md](EXCHANGE_OPERATOR_RUNBOOK.md)
- [MAINNET.md](MAINNET.md)

## 1. Authoritative interfaces

Primary integration surface:

- `finalis-lightserver` JSON-RPC

Optional secondary surface:

- `finalis-explorer` finalized-only REST wrapper

Build exchange automation against lightserver. Explorer is useful for thin REST
consumers and human support tooling, but it is not the canonical contract.

## 2. Recommended deployment shape

Recommended minimum:

- 1 primary `finalis-node`
- 1 secondary `finalis-node`
- 2 monitored `finalis-lightserver` endpoints backed by those nodes

Optional:

- 1 thin `finalis-explorer` instance for support-facing REST/HTML access

Exchanges should compare finalized identity across at least two trusted
lightserver endpoints before enabling automated crediting.

## 3. Canonical methods

Core methods:

- `get_status`
- `validate_address`
- `get_history_page`
- `get_utxos`
- `get_tx_status`
- `get_tx`
- `broadcast_tx`

Operationally useful:

- `get_committee`
- `get_transition`
- `get_transition_by_height`
- `get_adaptive_telemetry`

Exchange settlement does not require adaptive telemetry, but it may be useful
for operator diagnostics.

## 4. Status and endpoint agreement

Use `get_status` for:

- network identity checks
- finalized height checks
- finalized transition hash checks
- sync health checks
- endpoint agreement checks

Important live fields:

- `network_name`
- `network_id`
- `genesis_hash`
- `version`
- `wallet_api_version`
- `tip.height`
- `tip.transition_hash`
- `finalized_tip.height`
- `finalized_tip.transition_hash`
- `finalized_height`
- `finalized_transition_hash`
- `sync.mode = "finalized_only"`
- `healthy_peer_count`
- `bootstrap_sync_incomplete`
- `peer_height_disagreement`

Adaptive observability fields may also be present under:

- `availability.adaptive_regime`
- `adaptive_telemetry_summary`

These are operational diagnostics. Exchanges do not need them for deposit
crediting or withdrawal completion.

Endpoint agreement rule:

- same `network_name`, `network_id`, `genesis_hash`
- same `finalized_height`
- same `finalized_transition_hash`

If two endpoints report the same finalized height but different
`finalized_transition_hash`, stop automated settlement and investigate.

## 5. Deposit model

Recommended deposit flow:

1. validate deposit addresses with `validate_address`
2. store `scripthash_hex`
3. poll `get_history_page` and/or `get_tx_status`
4. when a deposit transaction is finalized, validate the credited output
5. credit exactly once

Canonical credit rule:

- `get_tx_status.result.finalized = true`
- `get_tx_status.result.credit_safe = true`
- credited output matches the exchange-controlled script/value expectation

Equivalent finalized-history rule:

- finalized transaction appears in `get_history_page`
- exchange validates the expected output from `get_tx`

Do not credit from:

- user-reported relay visibility
- explorer screenshots alone
- `broadcast_tx` output
- mempool admission

## 6. Withdrawal model

Recommended withdrawal flow:

1. construct transactions from finalized UTXO state
2. submit with `broadcast_tx`
3. persist:
   - returned `txid`
   - full broadcast result
   - endpoint used
   - internal withdrawal reference
4. poll `get_tx_status(txid)`
5. mark complete only after finalized visibility

Interpretation of `broadcast_tx`:

- `accepted=true` and `status="accepted_for_relay"` means relay submission only
- `finalized` in the broadcast result is always `false`
- completion still comes from finalized lookup

## 7. Address and Wallet Reconciliation

Use `get_history_page` for deterministic paging and replay-safe history scans.

Use `get_utxos` for:

- finalized exchange-controlled wallet balance reconstruction
- finalized withdrawal input selection
- internal balance reconciliation

Reconciliation rule:

- internal accounting
- finalized history
- finalized UTXO state

must agree.

## 8. Explorer REST surface

Explorer is optional. Current relevant routes are:

- `/api/status`
- `/api/committee`
- `/api/tx/<txid>`
- `/api/transition/<height_or_hash>`
- `/api/address/<address>`
- `/api/search?q=<query>`

Do not build against non-existent or stale routes such as `/api/block/...`.

Explorer field names are similar to lightserver but not identical. When the
same integration is possible through lightserver, prefer lightserver.

## 9. Failure handling

### Broadcast accepted but not finalized

Meaning:

- relay admission succeeded
- settlement has not happened yet

Action:

- keep polling finalized state
- do not mark the withdrawal complete yet

### Transaction not found after broadcast

Meaning:

- still not finalized
- or never propagated successfully despite submission

Action:

- keep the withdrawal operationally pending
- reconcile by `txid` against finalized state
- do not classify it as settled

### RPC unavailable

Action:

- fail over to another trusted finalized endpoint
- alert operators
- pause automated settlement if no trusted finalized endpoint remains

### Endpoint divergence

Action:

- compare `finalized_height` and `finalized_transition_hash`
- if they diverge at the same finalized height, stop automated crediting and
  investigate immediately

## 10. Integration contract

For exchanges, the authoritative settlement contract is:

- `get_status` for identity and finalized-tip health
- `get_history_page` for finalized deposit discovery
- `get_tx_status` for finalized transaction state
- `get_tx` for finalized payload inspection
- `get_utxos` for finalized exchange-controlled wallet state
- `broadcast_tx` for submission only

Everything else is operational convenience.

Terminology note:

- `treasury` in exchange operations means your own exchange-controlled hot,
  warm, or withdrawal wallet set
- it does not refer to the protocol-native reserve used by consensus economics
