# Exchange One Pager

`finalis-core` is a finalized-state settlement chain.

For exchanges, the model is narrow:

- use finalized state only
- do not use mempool state for accounting
- do not implement confirmation-count settlement rules
- treat a fresh-genesis relaunch as a new network identity, not an extension of
  the abandoned chain

Current mainnet identity:

- `network_name = mainnet`
- `network_id = fe561911730912cced1e83bc273fab13`
- `genesis_hash = eaae655a1eec3c876bd2e66d899fc8da93d205a5df36a2665f736387aa3cb78a`
- `magic = 0x499602D2`

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

Always confirm the live endpoint still reports that same identity through
`get_status` before enabling settlement automation.

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

If confidential-capable transactions are present, public settlement tooling
still uses finalized status only; it must not invent transparent-style
amount/address interpretation for confidential outputs.

Explorer REST is optional:

- `/api/status`
- `/api/tx/<txid>`
- `/api/address/<address>`
- `/api/transition/<height_or_hash>`

## Read next

- full guide: [EXCHANGE_INTEGRATION.md](EXCHANGE_INTEGRATION.md)
- API examples: [EXCHANGE_API_EXAMPLES.md](EXCHANGE_API_EXAMPLES.md)
- validation checklist: [EXCHANGE_CHECKLIST.md](EXCHANGE_CHECKLIST.md)
