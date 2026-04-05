# Exchange API Examples

This document shows the current exchange-facing live interfaces.

There are two surfaces:

1. lightserver JSON-RPC
2. explorer finalized-only REST

Do not assume the same field names appear in both.

Terminology note:

- any exchange-side `treasury` or `withdrawal wallet` balance should be derived
  from your own finalized address/script set
- this is separate from the protocol-native reserve used by post-cap consensus
  economics

## 1. Lightserver JSON-RPC

Example base URL:

```text
http://127.0.0.1:19444/rpc
```

### 1.1 `get_status`

Request:

```bash
curl -s http://127.0.0.1:19444/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_status","params":{}}'
```

Example response shape:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "network_name": "mainnet",
    "network_id": "...",
    "genesis_hash": "...",
    "tip": {
      "height": 225,
      "transition_hash": "32a442db9ee0325a19b610f80aaa65d0795288364d63a6a10c805dbaacdf4197"
    },
    "finalized_tip": {
      "height": 225,
      "transition_hash": "32a442db9ee0325a19b610f80aaa65d0795288364d63a6a10c805dbaacdf4197"
    },
    "finalized_height": 225,
    "finalized_transition_hash": "32a442db9ee0325a19b610f80aaa65d0795288364d63a6a10c805dbaacdf4197",
    "version": "finalis-core/...",
    "binary_version": "finalis-lightserver/...",
    "wallet_api_version": "...",
    "healthy_peer_count": 1,
    "established_peer_count": 1,
    "sync": {
      "mode": "finalized_only",
      "local_finalized_height": 225,
      "observed_network_finalized_height": 225,
      "finalized_lag": 0,
      "bootstrap_sync_incomplete": false,
      "peer_height_disagreement": false,
      "next_height_committee_available": true,
      "next_height_proposer_available": true
    }
  }
}
```

Exchange use:

- finalized identity monitoring
- endpoint agreement
- sync health

### 1.2 `get_tx_status`

Request:

```bash
curl -s http://127.0.0.1:19444/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"get_tx_status","params":{"txid":"<txid>"}}'
```

Example finalized response:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "txid": "<txid>",
    "status": "finalized",
    "finalized": true,
    "height": 225,
    "finalized_depth": 1,
    "credit_safe": true,
    "transition_hash": "32a442db9ee0325a19b610f80aaa65d0795288364d63a6a10c805dbaacdf4197"
  }
}
```

Example missing response:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "txid": "<txid>",
    "status": "not_found",
    "finalized": false,
    "finalized_depth": 0,
    "credit_safe": false
  }
}
```

### 1.3 `get_tx`

Request:

```bash
curl -s http://127.0.0.1:19444/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"get_tx","params":{"txid":"<txid>"}}'
```

Example response:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "height": 225,
    "tx_hex": "..."
  }
}
```

### 1.4 `validate_address`

Request:

```bash
curl -s http://127.0.0.1:19444/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":4,"method":"validate_address","params":{"address":"<address>"}}'
```

Example response shape:

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "valid": true,
    "server_network_hrp": "sc",
    "normalized_address": "<address>",
    "hrp": "sc",
    "network_hint": "mainnet",
    "server_network_match": true,
    "addr_type": "p2pkh",
    "pubkey_hash_hex": "...",
    "script_pubkey_hex": "...",
    "scripthash_hex": "...",
    "error": null
  }
}
```

Use `scripthash_hex` with `get_history_page` and `get_utxos`.

### 1.5 `get_utxos`

Request:

```bash
curl -s http://127.0.0.1:19444/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":5,"method":"get_utxos","params":{"scripthash_hex":"<scripthash_hex>"}}'
```

Example response:

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "result": [
    {
      "txid": "<txid>",
      "vout": 0,
      "value": 123456789,
      "height": 225,
      "script_pubkey_hex": "..."
    }
  ]
}
```

### 1.6 `get_history_page`

Request:

```bash
curl -s http://127.0.0.1:19444/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":6,"method":"get_history_page","params":{"scripthash_hex":"<scripthash_hex>","limit":100}}'
```

Example response:

```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "result": {
    "items": [
      {
        "txid": "<txid>",
        "height": 225
      }
    ],
    "has_more": false,
    "ordering": "height_asc_txid_asc",
    "next_start_after": null
  }
}
```

### 1.7 `broadcast_tx`

Request:

```bash
curl -s http://127.0.0.1:19444/rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":7,"method":"broadcast_tx","params":{"tx_hex":"<serialized_tx_hex>"}}'
```

Example accepted-for-relay response:

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "result": {
    "ok": true,
    "accepted": true,
    "status": "accepted_for_relay",
    "finalized": false,
    "txid": "<txid>",
    "message": "accepted_for_relay",
    "retryable": false,
    "retry_class": "none",
    "mempool_full": false,
    "min_fee_rate_to_enter_when_full": null,
    "min_fee_rate_to_enter_when_full_milliunits_per_byte": null
  }
}
```

Example fee-pressure rejection:

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "result": {
    "ok": true,
    "accepted": false,
    "status": "rejected",
    "finalized": false,
    "txid": "<txid>",
    "error_code": "mempool_full_not_good_enough",
    "error_message": "Network is busy. Transaction fee rate is too low for current mempool pressure.",
    "error": "Network is busy. Transaction fee rate is too low for current mempool pressure.",
    "retryable": true,
    "retry_class": "after_fee_bump",
    "mempool_full": true,
    "min_fee_rate_to_enter_when_full": 25000,
    "min_fee_rate_to_enter_when_full_milliunits_per_byte": 25000
  }
}
```

## 2. Explorer finalized-only REST

Explorer is optional. It is a thin wrapper around finalized-state data.

Example base URL:

```text
http://127.0.0.1:8080
```

### 2.1 `/api/status`

Request:

```bash
curl -s http://127.0.0.1:8080/api/status
```

Key fields mirror finalized status:

- `network`
- `tip.height`
- `tip.transition_hash`
- `finalized_height`
- `finalized_transition_hash`
- `availability.*`

### 2.2 `/api/tx/<txid>`

Request:

```bash
curl -s http://127.0.0.1:8080/api/tx/<txid>
```

Example response shape:

```json
{
  "txid": "<txid>",
  "status": "finalized",
  "finalized": true,
  "height": 225,
  "finalized_depth": 1,
  "credit_safe": true,
  "transition_hash": "32a442db9ee0325a19b610f80aaa65d0795288364d63a6a10c805dbaacdf4197"
}
```

### 2.3 `/api/transition/<height_or_hash>`

Request by height:

```bash
curl -s http://127.0.0.1:8080/api/transition/225
```

Request by transition hash:

```bash
curl -s http://127.0.0.1:8080/api/transition/32a442db9ee0325a19b610f80aaa65d0795288364d63a6a10c805dbaacdf4197
```

Use `/api/transition/...`, not `/api/block/...`.

### 2.4 `/api/address/<address>`

Request:

```bash
curl -s http://127.0.0.1:8080/api/address/<address>
```

Use this for support tooling and human reconciliation. Automated exchange
accounting should still prefer lightserver JSON-RPC.
