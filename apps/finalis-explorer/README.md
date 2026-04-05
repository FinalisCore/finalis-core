# Finalis Explorer

`Finalis Explorer` is a thin in-tree explorer for exchange and operator support.

It is intentionally narrow:

- backed by `finalis-lightserver`
- finalized-state only
- no consensus logic
- no indexer of its own
- no marketing UI

Supported routes:

- `/committee`
- `/tx/<txid>`
- `/transition/<height>`
- `/transition/<hash>`
- `/address/<address>`
- `/search?q=<query>`

Supported API routes:

- `/healthz`
- `/api/status`
- `/api/committee`
- `/api/tx/<txid>`
- `/api/transition/<height_or_hash>`
- `/api/address/<address>`
- `/api/search?q=<query>`

What it shows:

- current bounded Ticket PoW difficulty, clamp, epoch health, and streaks
- current finalized committee operator view with representative pubkey, base
  weight, ticket bonus, and final weight
- transaction finalized status, credit-safe status, transition linkage, timestamp
  when available, inputs, and outputs
- transition height, hash, previous finalized hash, timestamp, and tx list
- address finalized UTXOs and finalized history
- recent finalized transaction activity on the homepage
- copyable page/API paths for operator and support workflows
- stable finalized-only JSON for exchange, wallet, and mobile consumers
- adaptive checkpoint regime observability:
  - qualified operator depth
  - adaptive committee target
  - adaptive eligible threshold
  - adaptive bond floor
  - eligibility slack
  - target expand / contract streaks
  - rolling fallback and sticky-fallback rates
  - telemetry summary counts
  - adaptive alert flags

What it does not show:

- non-finalized or mempool state
- durable withdrawal tracking
- state outside current lightserver capabilities
- any non-finalized object as a creditable transaction

Transaction status semantics:

- `finalized: true` means the transaction is in finalized state
- `credit_safe: true` means the explorer is presenting the transaction as safe
  to credit from finalized state
- tx page labels use:
  - `FINALIZED (CREDIT SAFE)`
  - `FINALIZED`
  - `NOT FINALIZED`

## Canonical terminology

- `accepted_for_relay`
  - relay admission only
  - not inclusion
  - not finality
- `finalized`
  - present in finalized state
- `finalized_only`
  - response is limited to finalized-state data
- `credit_safe`
  - current finalized-state view is safe to credit
- `not_finalized`
  - not present in finalized explorer state
- mempool diagnostics
  - local operational hints only
- `relay_unavailable`
  - relay transport failure, not a settlement verdict

## API semantics

All API responses are finalized-only and include:

- `finalized_only: true`

Health behavior:

- `GET /healthz` returns JSON only
- `200` means the explorer process is up and can reach the required upstream
  `get_status` path on `finalis-lightserver`
- `502` means upstream is unavailable or returned an invalid response
- explorer does not maintain its own chain or index state

Error behavior:

- `400` malformed identifier/query
- `404` well-formed but not found in finalized state
- `502` upstream lightserver failure

Error body shape:

```json
{
  "error": {
    "code": "machine_code",
    "message": "short message"
  }
}
```

Search classification is deterministic:

1. numeric query:
   - always treated as transition height
   - unknown finalized height returns `404`
2. 64-hex query:
   - resolved as tx first
   - if no finalized tx is found, resolved as transition hash
   - if neither exists in finalized state, search returns `classification: "not_found"`
3. valid Finalis address

Address behavior:

- malformed address -> `400`
- valid address with finalized activity -> `200`
- valid address with no finalized activity -> `200` with:
  - `found: false`
  - empty `utxos`
  - empty `history.items`
  - `has_more: false`
  - `next_cursor: null`
- `history.has_more` indicates whether another finalized history page exists
- `history.next_cursor` is only non-null when another page exists
- if `history.has_more` is `false`, `history.next_cursor` is always `null`

API contract is intended to be stable for exchange, wallet, mobile, and
operator consumers.

Ticket PoW observability:

- `/api/status` includes a `ticket_pow` object
- `/api/status` includes current adaptive checkpoint observability and the
  separate `adaptive_telemetry_summary` block
- `/api/committee` shows the current finalized committee with operator-facing
  weight fields
- explorer presents Ticket PoW as bounded, operator-based, and secondary to
  bond and BFT finality
- the restarted mainnet begins directly on the live bounded-search policy

## Exchange Integration

Explorer API is finalized-only.

Recommended deposit flow:

1. call `/api/tx/<txid>`
2. ensure `finalized=true`
3. ensure `credit_safe=true`
4. credit the user

Finalis does not expose mempool or unfinalized transaction state via the
explorer API.

After finalization, explorer surfaces canonical finalized state only. There is
no reorg-handling flow in the explorer integration path.

## Ticket PoW (Operational Summary)

- one operator = one bounded search
- fixed nonce budget: `4096`
- bounded bonus capped in `bps`
- live difficulty clamp: `8..12`
- streak-based adjustment
- operator-based ticket search
- secondary to bond
- does not affect BFT finality

## API Stability

Stable finalized surfaces:

- `/api/status`
  - `finalized_height`
  - `finalized_transition_hash`
  - `ticket_pow`
- `/api/committee`
  - current finalized committee operator view
- `/api/tx/<txid>`
  - finalized-only transaction status
  - returns `404` if the tx is not finalized in explorer state

Related lightserver note:

- lightserver `get_committee` keeps its legacy default array response
- lightserver `get_committee` with `verbose=true` exposes the stable extended
  operator breakdown
- explorer `/api/committee` always serves the structured current finalized view

Stability guarantees:

- field names are stable across minor releases
- new fields may be added
- existing fields will not change meaning silently
- breaking changes require an explicit version bump or clearly announced
  compatibility change

Version note:

- explorer presents the live bounded-search ticket policy
- the restarted mainnet begins with the live bounded-search policy active from
  genesis

## Example Responses

`GET /api/status`

```json
{
  "network": "mainnet",
  "finalized_height": 225,
  "finalized_transition_hash": "32a442db9ee0325a19b610f80aaa65d0795288364d63a6a10c805dbaacdf4197",
  "backend_version": "finalis-lightserver/1.x",
  "ticket_pow": {
    "difficulty": 10,
    "difficulty_min": 8,
    "difficulty_max": 12,
    "epoch_health": "healthy",
    "streak_up": 1,
    "streak_down": 0,
    "nonce_search_limit": 4096,
    "bonus_cap_bps": 1000
  },
  "finalized_only": true
}
```

`GET /api/committee`

```json
{
  "height": 225,
  "epoch_start_height": 225,
  "members": [
    {
      "operator_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "representative_pubkey": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "base_weight": 100,
      "ticket_bonus_bps": 1000,
      "final_weight": 1010000,
      "ticket_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "ticket_nonce": 12
    }
  ],
  "finalized_only": true
}
```

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target finalis-explorer -j"$(nproc)"
```

## Run

Run a synced node and lightserver first, then:

```bash
./build/finalis-explorer \
  --bind 127.0.0.1 \
  --port 18080 \
  --rpc-url http://127.0.0.1:19444/rpc
```

Open:

```text
http://127.0.0.1:18080/
```

## Backend assumptions

- lightserver is reachable over HTTP JSON-RPC
- lightserver is returning finalized state
- `get_tx_status`, `get_transition_by_height`, `get_history_page`, `get_tx`,
  `get_transition`, `get_utxos`, `get_status`, and `get_committee` are available

## Deployment notes

- `finalis-explorer` is intended to sit behind a reverse proxy such as nginx or
  caddy for public exposure
- the explorer remains a thin finalized-state read surface and does not maintain
  its own chain/index database
- `/healthz` is suitable for simple process-plus-upstream reachability checks

Branding note:

- the shipped binary target is `finalis-explorer`

## Manual verification checklist

1. Open `/` and confirm the explorer shows the configured lightserver and the
   current finalized tip.
2. Open `/transition/<height>` for a known finalized height and confirm:
   - finalized badge is visible
   - transition hash and previous finalized hash are shown
   - tx list is shown
3. Open `/tx/<txid>` for a known finalized tx and confirm:
   - finalized badge is visible
   - finalized transition height/hash are linked
   - outputs are shown
4. Open `/address/<address>` for a known address and confirm:
   - finalized-only note is visible
   - UTXOs and/or finalized history appear
5. Open `/tx/<unknown-txid>` and confirm the page states the tx is not present
   in finalized lightserver state.
