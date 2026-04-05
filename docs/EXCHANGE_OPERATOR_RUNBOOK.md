# Exchange Operator Runbook

## Scope

This runbook is for exchange operations and support teams using Finalis through
the current finalized-only lightserver surface.

Use it with:

- [EXCHANGE_INTEGRATION.md](./EXCHANGE_INTEGRATION.md)
- [EXCHANGE_API_EXAMPLES.md](./EXCHANGE_API_EXAMPLES.md)

## Operational rules

- finalized state is the accounting truth surface
- `accepted_for_relay` is not settlement
- mempool diagnostics are local operational hints only
- mempool rejection is not proof of on-chain invalidity
- different relay nodes may make different local admission decisions

## Common incidents

### Relay service unavailable

Symptoms:

- `broadcast_tx` returns `error_code=relay_unavailable`
- `retryable=true`
- `retry_class=transport`

Action:

1. check `get_status`
2. verify node and relay service health
3. retry later or use another relay-capable node
4. do not mark the withdrawal failed on-chain from this result alone

### Withdrawal accepted for relay but not yet finalized

Symptoms:

- `accepted=true`
- `status=accepted_for_relay`
- `get_tx_status` still returns `not_found`

Action:

1. treat this as operationally pending
2. keep polling finalized-state APIs by `txid`
3. escalate only after your internal timeout is exceeded
4. avoid duplicate operator actions until finalized reconciliation is complete

### Mempool pressure rejection

Symptoms:

- `error_code=mempool_full_not_good_enough`
- `retry_class=after_fee_bump`
- `mempool_full=true`

Action:

1. do not classify the transaction as invalid
2. if your wallet supports it, rebuild with a higher fee
3. otherwise retry later under changed conditions
4. keep operator handling idempotent

### Minimum relay fee rejection

Symptoms:

- `error_code=tx_fee_below_min_relay`
- `retry_class=after_fee_bump`

Action:

1. rebuild with a higher fee
2. do not keep replaying the same payload

### Duplicate submission confusion

Symptoms:

- `error_code=tx_duplicate`

Action:

1. reconcile by `txid` first
2. check whether the transaction is already finalized
3. check whether the same withdrawal was already submitted operationally

### Deposit seen by user but not credited yet

Symptoms:

- user reports a `txid`
- finalized lookup still returns `not_found`

Action:

1. do not credit yet
2. verify the exact `txid` and deposit address
3. continue monitoring finalized-state APIs
4. explain that relay visibility is not finality

### Broadcast result and finalized history disagree

Examples:

- relay accepted but tx never appears finalized within your timeout
- one node rejects under mempool pressure while another later relays the tx

Action:

1. trust finalized reconciliation over prior relay outcomes
2. review the logged relay endpoint and full broadcast payload
3. use multi-endpoint finalized cross-checks if you operate multiple readers

## Retry guidance by retry class

| `retry_class` | Meaning | Operator action |
| --- | --- | --- |
| `none` | terminal for the current payload | stop and rebuild or cancel |
| `after_state_change` | may succeed after finalized-state changes | wait for state change, then retry if still needed |
| `after_fee_bump` | fee is not acceptable under local policy | rebuild with higher fee or retry later |
| `transport` | relay path unavailable | retry another node or retry later |

## Support checklist

Collect these before escalation:

- `txid`
- full `broadcast_tx` response
- endpoint used
- submission timestamp
- current `get_status` output
- current `get_tx_status` output
- current `finalized_height`
- current `finalized_transition_hash`
- internal withdrawal or deposit reference

## Audit and reconciliation checklist

For withdrawals:

- verify one operator intent maps to one tx build attempt or a documented
  replacement flow
- retain every broadcast response
- reconcile later by `txid` against finalized state

For deposits:

- reconcile from finalized history periodically
- keep a persisted finalized cursor or reconciliation checkpoint
- log the finalized payload used for every credit decision

Terminology note:

- if internal ops use the word `treasury`, treat it as shorthand for the
  exchange-controlled wallet inventory only
- it is not the consensus reserve balance
