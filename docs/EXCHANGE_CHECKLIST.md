# Finalis Exchange Checklist

This checklist is for production exchange enablement.

The operating rule is:

- deposits are credited from finalized state only
- withdrawals are completed from finalized state only

## 1. Verify identity and sync

- poll `get_status`
- confirm `network_name`
- confirm `network_id`
- confirm `genesis_hash`
- confirm `sync.mode = "finalized_only"`
- confirm `bootstrap_sync_incomplete = false`

Pass condition:

- the endpoint serves stable finalized-state data for repeated checks
- the endpoint reports the intended fresh-network identity after the current
  genesis reset

## 2. Verify finalized tip progression

- record `finalized_height`
- record `finalized_transition_hash`
- confirm finalized height advances under normal network conditions
- alert if finalized height stalls beyond your internal threshold

Pass condition:

- finalized identity progresses consistently with new finalized transitions

Genesis-reset operational note:

- if this is a restarted network from fresh genesis, old endpoints or old DBs
  from the abandoned chain must not be reused for automated settlement

## 3. Verify endpoint agreement

- operate at least two monitored lightserver endpoints
- compare:
  - `network_name`
  - `network_id`
  - `genesis_hash`
  - `finalized_height`
  - `finalized_transition_hash`
- reject lagging or divergent endpoints from automated settlement

Pass condition:

- trusted endpoints agree on finalized identity

## 4. Verify deposit flow

- validate deposit addresses with `validate_address`
- persist `scripthash_hex`
- send a test deposit
- poll `get_history_page` and/or `get_tx_status`
- confirm the deposit is not credited before finalized visibility
- confirm the deposit is credited exactly once after finalized visibility
- confirm the credited output matches the expected value/script

Pass condition:

- deposits are credited exactly once and only from finalized state
- confidential transaction presence does not cause the exchange to invent
  transparent-style amount/address interpretation

## 5. Verify withdrawal flow

- construct a withdrawal from finalized UTXO state
- submit with `broadcast_tx`
- record the full broadcast result
- confirm the exchange does not treat broadcast submission as completion
- poll `get_tx_status`
- mark complete only when finalized visibility is returned

Pass condition:

- withdrawals remain pending after submission and complete only on finalized
  visibility
- support tooling does not require explorer-style transparent output rendering
  for confidential txs

## 6. Verify reconciliation

- rescan finalized address history with `get_history_page`
- verify deposits match finalized history
- verify completed withdrawals match finalized transaction lookups
- compare exchange-controlled wallet balance to finalized `get_utxos`
- confirm restart logic resumes from saved cursors or an earlier finalized
  checkpoint

Pass condition:

- finalized history, finalized UTXO state, and internal accounting reconcile

## 7. Define incident policy

- define response for stalled finalized height
- define response for endpoint divergence at the same finalized height
- define response for RPC unavailability
- define response for `accepted_for_relay` without later finalization
- define response for mempool-pressure rejection and retry

Pass condition:

- operators have written actions for lag, divergence, RPC failure, delayed
  finalization, and relay rejection

## 8. Production enablement rule

Before enabling user deposits and withdrawals, confirm:

- finalized-state polling works
- endpoint agreement checks are in place
- deposit crediting uses finalized visibility only
- withdrawal completion uses finalized visibility only
- reconciliation passes on test activity
- incident handling is owned and documented
- partner API v1 auth and idempotency are enabled and tested
- partner metrics (`/metrics`) are scraped and alerting is active
- partner API governance gate is active and green:
  - `.github/workflows/partner-api-governance.yml`
  - `docs/PARTNER_API_CHANGELOG.md`

## 9. Never build settlement around

- mempool visibility
- relay admission
- probabilistic confirmation counting
- reorg rollback workflows

## 10. Always build settlement around

- `get_status` for health and finalized identity
- `get_history_page` for finalized deposit discovery
- `get_tx_status` for finalized transaction state
- `get_tx` for finalized payload inspection
- `get_utxos` for finalized wallet state and exchange-controlled withdrawal
  inventory
- `broadcast_tx` for submission only
