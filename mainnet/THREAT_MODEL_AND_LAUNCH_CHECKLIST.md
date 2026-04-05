# Threat Model and Launch Checklist

This file is the bootstrap launch go/no-go checklist for the current
`finalis-core` implementation.

It is intentionally operational. Every item below exists because the repo now
has real failure modes that must be checked before calling a bootstrap launch
healthy:

- embedded genesis drift versus canonical `mainnet/genesis.bin`
- `chain_id_ok=false` on live RPC
- wallet history versus UTXO mismatch
- mobile submitted-to-finalized reconciliation lag
- explorer rendering drift from lightserver truth
- exchange tooling built against stale field names

Use this together with:

- [GENESIS_SPEC.md](GENESIS_SPEC.md)
- [GENESIS_VALIDATOR_CEREMONY.md](GENESIS_VALIDATOR_CEREMONY.md)
- [MAINNET_PLAN.md](MAINNET_PLAN.md)
- [../docs/MAINNET.md](../docs/MAINNET.md)
- [../docs/EXCHANGE_INTEGRATION.md](../docs/EXCHANGE_INTEGRATION.md)

## 1. Threat Model

The current bootstrap threat surface is:

- genesis mismatch between published artifacts and embedded mainnet bytes
- node DB reuse across incompatible genesis histories
- seed / peer divergence at the same finalized height
- stale client assumptions about finalized identity fields
- wallet local-state drift after finalized transaction inclusion
- exchange settlement logic that confuses relay admission with settlement
- operator launch with local validator not recognized by availability/runtime

The first serious launch rule is:

- do not trust any endpoint unless `chain_id_ok=true`

The second is:

- do not treat `broadcast_tx` acceptance, mempool presence, or submitted local
  state as settlement

## 2. Genesis Integrity Gate

Before launch, reproduce the canonical genesis artifacts:

```bash
./build/finalis-cli genesis_build --in mainnet/genesis.json --out mainnet/genesis.bin
./build/finalis-cli genesis_hash --in mainnet/genesis.bin
./build/finalis-cli genesis_verify --json mainnet/genesis.json --bin mainnet/genesis.bin
```

Pass condition:

- `genesis_verify` returns `verified=1`
- the reported `genesis_hash` is the one you intend to launch

Then verify that embedded mainnet bytes match the canonical binary:

```bash
python3 scripts/genesis_to_cpp.py --in mainnet/genesis.bin --out src/genesis/embedded_mainnet.cpp
cmake --build build -j
```

Pass condition:

- the rebuilt node/lightserver reports the same `genesis_hash` as
  `mainnet/genesis.bin`
- a fresh `get_status` returns `chain_id_ok=true`

This gate exists because a stale `src/genesis/embedded_mainnet.cpp` can cause a
live node to report `chain_id_ok=false` even when `mainnet/genesis.json` and
`mainnet/genesis.bin` are internally correct.

## 3. Bootstrap Validator Identity Gate

After starting the bootstrap node, check:

```bash
curl -s http://127.0.0.1:19444/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_status","params":{}}' | jq
```

Pass condition:

- `network_name = "mainnet"`
- `chain_id_ok = true`
- `sync.mode = "finalized_only"`
- `availability.local_operator.known = true`
- `availability.local_operator.pubkey` matches the intended bootstrap operator

Launch blocker:

- `chain_id_ok=false`
- `availability.local_operator.known=false` on the intended bootstrap node

## 4. Lightserver Settlement Gate

The current authoritative exchange / wallet methods are:

- `get_status`
- `validate_address`
- `get_history_page`
- `get_utxos`
- `get_tx_status`
- `get_tx`
- `broadcast_tx`

Run the exchange sanity script against at least one endpoint:

```bash
scripts/exchange_sanity_test.sh --rpc http://127.0.0.1:19444/rpc
```

If you have a known finalized txid:

```bash
scripts/exchange_sanity_test.sh \
  --rpc http://127.0.0.1:19444/rpc \
  --txid <known-finalized-txid>
```

Pass condition:

- `get_status` contains stable finalized-state fields
- finalized height does not regress across repeated polls
- a known txid returns:
  - `status = "finalized"`
  - `finalized = true`
  - `credit_safe = true`

## 5. Endpoint Agreement Gate

For at least two monitored endpoints, compare:

- `network_name`
- `network_id`
- `genesis_hash`
- `chain_id_ok`
- `finalized_height`
- `finalized_transition_hash`

Pass condition:

- same `network_name`, `network_id`, and `genesis_hash`
- `chain_id_ok=true` on all trusted endpoints
- same `finalized_transition_hash` at the same `finalized_height`

Launch blocker:

- same finalized height with different finalized transition hash
- any trusted endpoint still reporting `chain_id_ok=false`

## 6. Desktop Wallet Balance Gate

The desktop wallet must be checked against backend truth, not only UI output.

For the exact wallet address under test:

```bash
curl -s http://127.0.0.1:19444/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"validate_address","params":{"address":"<wallet-address>"}}' | jq
```

Take `scripthash_hex` from that result, then run:

```bash
curl -s http://127.0.0.1:19444/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"get_utxos","params":{"scripthash_hex":"<scripthash_hex>"}}' | jq

curl -s http://127.0.0.1:19444/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"get_history_page","params":{"scripthash_hex":"<scripthash_hex>","limit":20}}' | jq
```

Pass condition:

- desktop `Available balance` matches finalized unspent outputs from
  `get_utxos`
- desktop Activity is explainable by finalized history from
  `get_history_page`

Important interpretation rule:

- non-empty history with empty UTXOs is valid if the address has historical
  finalized activity but no current unspent outputs

## 7. Mobile Submitted-to-Finalized Gate

Submit a real transaction from mobile, record the `txid`, then verify:

```bash
curl -s http://127.0.0.1:19444/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":4,"method":"get_tx_status","params":{"txid":"<txid>"}}' | jq
```

Pass condition:

- backend eventually reports:
  - `status = "finalized"`
  - `finalized = true`
  - `credit_safe = true`
- on mobile, after foreground resume or manual refresh:
  - submitted count drops appropriately
  - reserved balance no longer includes the finalized spend
  - visible activity no longer remains stuck as local submitted-only state

Launch blocker:

- backend finalized truth is present, but the shipping mobile build leaves the
  tx indefinitely in submitted/reserved state

## 8. Explorer and Lightserver Surface Gate

Explorer must match lightserver truth for finalized identity and committee
state.

Check:

- `/api/status`
- `/api/committee`
- `/api/tx/<txid>`
- `/api/transition/<height_or_hash>`
- `/api/address/<address>`

Pass condition:

- explorer status reflects:
  - `finalized_height`
  - `finalized_transition_hash`
  - `chain_id_ok`
  - adaptive checkpoint fields
- explorer committee view reflects the current finalized checkpoint and verbose
  committee metadata
- explorer does not rely on stale routes or stale field names

## 9. Exchange Settlement Gate

Before declaring bootstrap launch ready for exchange-facing integration, verify:

- `validate_address` returns stable:
  - `normalized_address`
  - `server_network_match`
  - `script_pubkey_hex`
  - `scripthash_hex`
- `get_history_page` discovers finalized deposits
- `get_tx_status` returns finalized settlement truth
- `get_tx` allows output/value/script inspection
- `get_utxos` matches finalized exchange-controlled wallet state
- `broadcast_tx` is treated as submission only

Exchange pass condition:

- deposit crediting is driven by finalized visibility only
- withdrawal completion is driven by finalized visibility only
- no settlement workflow depends on:
  - mempool visibility
  - `accepted_for_relay`
  - confirmation counting

## 10. Current Go / No-Go Checklist

Mark every item before calling bootstrap launch healthy:

- [ ] `mainnet/genesis.json` and `mainnet/genesis.bin` reproduce cleanly
- [ ] embedded genesis was regenerated from the canonical binary before the
      release build
- [ ] bootstrap node reports `chain_id_ok=true`
- [ ] intended bootstrap validator is recognized as `availability.local_operator.known=true`
- [ ] trusted endpoints agree on `finalized_height` and `finalized_transition_hash`
- [ ] desktop wallet available balance matches `get_utxos`
- [ ] desktop wallet activity is explainable by `get_history_page`
- [ ] mobile submitted txs reconcile out of local submitted/reserved state once
      `get_tx_status` becomes finalized
- [ ] explorer status and committee views match lightserver truth
- [ ] exchange sanity script passes against the intended public RPC endpoint(s)
- [ ] exchange operators understand that `accepted_for_relay` is not settlement
- [ ] no trusted endpoint in production monitoring reports `chain_id_ok=false`

If any item above fails, do not call the bootstrap launch healthy.
