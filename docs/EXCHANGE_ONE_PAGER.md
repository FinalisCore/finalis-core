# Exchange One Pager

`finalis-core` is a finalized-state settlement chain.

For exchanges, the model is narrow:

- use finalized state only
- do not use mempool state for accounting
- do not implement confirmation-count settlement rules

## What the exchange runs

Run `finalis-node` with lightserver enabled.

Example:

```bash
./build/finalis-node \
  --db ~/.finalis/mainnet \
  --public \
  --with-lightserver \
  --lightserver-bind 0.0.0.0 \
  --lightserver-port 19444
```

Common ports:

- P2P: `19440`
- lightserver: `19444`

## Why integration is simple

The live system exposes finalized-state read surfaces. Exchange accounting uses
finalized state as the source of truth.

That means exchanges do not need:

- mempool accounting
- probabilistic confirmation counting
- reorg rollback logic after finalization
- fork-choice handling in ordinary settlement flows

## Deposit and withdrawal handling

Use lightserver:

- `get_status`
- `get_history_page`
- `get_tx_status`
- `get_tx`
- `get_utxos`
- `broadcast_tx`

Credit deposits only from finalized visibility.

Mark withdrawals complete only from finalized visibility.

Treat `broadcast_tx` as submission only.

Explorer REST is optional:

- `/api/status`
- `/api/tx/<txid>`
- `/api/address/<address>`
- `/api/transition/<height_or_hash>`

## Read next

- full guide: [EXCHANGE_INTEGRATION.md](EXCHANGE_INTEGRATION.md)
- API examples: [EXCHANGE_API_EXAMPLES.md](EXCHANGE_API_EXAMPLES.md)
- validation checklist: [EXCHANGE_CHECKLIST.md](EXCHANGE_CHECKLIST.md)
