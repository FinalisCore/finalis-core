# Exchange Outreach Message

## 1. Short first-contact version

Hello,

We are reaching out regarding `finalis-core`.

`finalis-core` is a finalized-state settlement chain. Exchange integration is
designed around finalized-state lightserver APIs: deposits are credited from
finalized visibility only, and withdrawals are completed from finalized
visibility only. Relay admission is not treated as settlement.

The current network identity should always be confirmed from live `get_status`
fields (`network_id`, `genesis_hash`) before operational onboarding, especially
after a fresh-genesis relaunch.

The current exchange integration documents are:

- [EXCHANGE_ONE_PAGER.md](EXCHANGE_ONE_PAGER.md)
- [EXCHANGE_INTEGRATION.md](EXCHANGE_INTEGRATION.md)
- [EXCHANGE_API_EXAMPLES.md](EXCHANGE_API_EXAMPLES.md)

If useful, we can provide a direct technical review against the live repo
implementation.

## 2. Slightly fuller technical intro

Hello,

We are reaching out about `finalis-core` exchange integration.

`finalis-core` exposes finalized-state settlement interfaces through
`finalis-lightserver`. The intended exchange model is:

- run `finalis-node` with lightserver enabled
- query finalized status, transaction, history, and UTXO state
- credit deposits only from finalized visibility
- mark withdrawals complete only from finalized visibility
- treat relay acceptance as submission only

Current documentation:

- [EXCHANGE_ONE_PAGER.md](EXCHANGE_ONE_PAGER.md)
- [EXCHANGE_INTEGRATION.md](EXCHANGE_INTEGRATION.md)
- [EXCHANGE_API_EXAMPLES.md](EXCHANGE_API_EXAMPLES.md)
- [EXCHANGE_CHECKLIST.md](EXCHANGE_CHECKLIST.md)

If your team is open to review, we can answer directly against the current RPC
surface and provide integration support.

## 3. Operator-to-operator version

Hello,

`finalis-core`’s exchange-facing model is finalized-state only.

The practical path is:

- `finalis-node` with built-in lightserver
- JSON-RPC reads for `get_status`, `get_tx_status`, `get_tx`, `get_utxos`,
  `get_history_page`, and `validate_address`
- `broadcast_tx` for submission only
- optional explorer REST for support-facing finalized reads

The intent is simple: exchange accounting runs from finalized state, not
mempool state and not confirmation counts.

If confidential-capable transactions are in use, that does not change the
settlement rule: finalized status is the accounting truth; public APIs do not
expand confidential outputs into transparent-style public fields.

Docs:

- [EXCHANGE_INTEGRATION.md](EXCHANGE_INTEGRATION.md)
- [EXCHANGE_API_EXAMPLES.md](EXCHANGE_API_EXAMPLES.md)

If your team wants a technical review pass, we can work directly from the live
implementation and docs.
