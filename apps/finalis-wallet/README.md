# Finalis Wallet

`Finalis Wallet` is the Qt desktop wallet shipped in this repository. It manages a local keystore, reads finalized wallet state through lightserver, signs transactions locally, and exposes the wallet flows already implemented by the backend.

Current mainnet identity reference:

- `network_name = mainnet`
- `network_id = fe561911730912cced1e83bc273fab13`
- `genesis_hash`: published at launch (mainnet has not launched)

## Build and run

If Qt5 Widgets is available, the wallet target is built with the normal project build:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target finalis-wallet -j"$(nproc)"
./build/finalis-wallet
```

## Mainnet and testnet

The selector in the header switches the wallet between `Mainnet` and `Testnet` (as in finalis-mobile).
The choice is remembered.

- The open wallet keeps its key and shows that network's address (`sc1…` on mainnet, `tsc1…` on
  testnet). Every signature commits to its chain, so a transaction signed for one network is invalid
  on the other.
- Lightserver endpoints, validator paths and the explorer URL are kept per network. Testnet defaults to
  the public lightserver in [testnet/SEEDS.json](../../testnet/SEEDS.json), mainnet to a local node
  (`http://127.0.0.1:19444/rpc`).
- Local wallet state (history, pending transactions, confidential accounts and coins) is kept per
  network: `<wallet>.json.walletdb` for mainnet, `<wallet>.json.testnet.walletdb` for testnet.
- Create and Import write the keystore for the selected network.
- Sends refuse a recipient address of the other network.
- Testnet shows a banner: testnet coins have no value.

## Connected services

- Lightserver: finalized-state reads and transaction broadcast

The wallet does not embed a node. It depends on the configured external endpoints.

The wallet is local-first:

- cached wallet/runtime snapshots are rendered immediately on startup
- network refresh runs in the background
- pending-tx inspection is cached-first
- stale / freshness state is surfaced explicitly instead of blanking the UI

## UI structure

The wallet is now split into screen widgets under `apps/finalis-wallet/widgets/`:

- `Overview`
- `Send`
- `Receive`
- `Activity`
- `Advanced`
- `Settings`

`Advanced` contains the operator-heavy and protocol-heavy sections:

- `Validator`
- `Connections`
- `Diagnostics`

`Advanced -> Diagnostics` now includes:

- endpoint cross-check output
- adaptive checkpoint regime diagnostics
  - checkpoint mode / fallback reason
  - qualified operator depth
  - adaptive committee target / eligible threshold / bond floor
  - eligibility slack
  - target expand / contract streaks
  - rolling fallback and sticky-fallback rates
  - observability-only alert flags

The wallet now also includes confidential-capable UX for the currently
supported subset:

- confidential account creation / import
- one-time confidential receive request generation
- request import in send flow
- imported confidential coin tracking
- reservation / pending-send visibility
- cached pending-tx status and inline inspection surfaces
- chain scan of confidential receipts: each refresh queries `get_confidential_history_page` with the
  one-time keys derived from every account (requests `0 .. next_request_index + 100`), imports matching
  outputs and marks spent coins. Importing an account (view + spend secret) scans from height 0, so a
  wallet restored from its keys recovers its confidential coins without the original wallet file.
- created confidential accounts derive their secrets from the wallet key (account 0, 1, ...), so the
  exported private key is the whole backup. Import Wallet restores account 0 and scans for it;
  creating accounts again restores 1, 2, ... in order. Accounts imported from a raw view + spend
  secret need that pair backed up separately.

## Time-locked sends

`Send -> Transparent -> Transparent (time-locked)` seals a transfer until a height is final
(`TxTimed`, see docs/CONSENSUS.md "Timed Transactions"): "Opens after" N blocks puts the unlock
height at next block + N. Past the end of the current committee epoch it is a long lock: the current
committee opens it, the envelope pays 0.001 FLS per epoch of lock, its sealed transfer is at most 1 KiB,
and the review warns when the lock runs past the validators' one-year bond hold. One coin pays the envelope
(prepaid fee + a bond, the rest returns as change); the transfer is planned from the other coins
(`plan_timed_p2pkh_send`). Its coins stay reserved until it opens: the wallet records the sealed
transfer as a pending spend dated at the unlock height, so the usual not-found release cannot free
them early. The bond comes back when the transfer applies in block unlock + 1.

`Cancel Time-Locked...` lists sends that have not opened yet and spends the transfer's coins back to
the wallet, which makes the transfer fail when it opens (the bond is forfeited, by design: a free
cancel would make every envelope a free option). If the envelope is not in a block yet, it also spends
the fee coin, which keeps the bond if that spend finalizes first. Records are kept in the wallet store
(`TIMED:`), because the chain holds the transfer encrypted until it opens.

`Send -> Sealed data (published at a block)` seals the text in the data field (up to 1016 bytes)
instead of a transfer: nobody can read it until the unlock height is final, then it is published for
anyone (`get_timed_reveal`) and the bond comes back. It needs only the envelope's coin and cannot be
cancelled once in a block.

## Height-locked sends

`Send -> Transparent -> Height-locked (vesting / inheritance)` pays an output the recipient can spend
only from a chosen block (`SCHLOCK1`), for any distance. With "I keep spending it until then" it is an
inheritance output (`SCHLOCK2`): this wallet can still spend it at any time, the recipient (heir) from
that block. Locked coins are found by the recipient's normal address; the balance shows them as
"Height-locked" until spendable, and ordinary sends use them from then on (no separate claim step).

## Lightserver failover

The wallet accepts an ordered list of lightserver RPC endpoints in `Advanced -> Connections`.
Enter one endpoint per line, for example:

```text
http://127.0.0.1:19444/rpc
http://192.168.0.104:19444/rpc
```

Behavior:

- the wallet tries the configured endpoints in order
- if `Always try the first lightserver first` is disabled, the wallet prefers the last known good endpoint on the next refresh
- existing single-endpoint settings are migrated into the new list automatically

An endpoint is treated as failed if the wallet cannot connect, cannot read a valid RPC response, or receives a chain/network response that does not match the wallet network.

This improves availability only. It does not change consensus security or replace endpoint cross-checking.

## Balance verification

The wallet does not take a server's word for its balance
([docs/spec/LIGHT_CLIENT.md](../../docs/spec/LIGHT_CLIENT.md)):

- It starts from the genesis compiled into the binary and learns each epoch's validator committee
  from the previous one. No server can introduce a committee.
- On every refresh it asks all configured lightservers for the wallet's coins and checks the union
  against the validators' signatures on the finalized tip. Only proven coins count. A coin invented
  by a server is dropped. A coin hidden by one server is still found if another server reports it.
- A server that sends an invalid proof, misdescribes a coin, or (at the same height) leaves out or
  invents one is listed under the connection status as `failed verification`.
- The tip label shows `verified` or `NOT VERIFIED`; the tooltip gives the proven height or the
  reason. An unverified balance is the server's report and must not be relied on for incoming
  payments.
- Confidential coins are proven too. One received in the latest refresh shows as "not yet
  verified" until the next.
- Progress is saved per network in the wallet settings, so a restart resumes instead of walking
  from genesis.
- Mainnet shows `NOT VERIFIED` until the embedded genesis names its validators (genesis ceremony).

## Lightserver cross-check

On refresh, the wallet also samples up to three configured lightserver endpoints and compares their
network identity, finalized height and transition hash, shown under `Advanced -> Connections`. This
is a diagnostic; balance verification (above) is what protects the balance.

## Branding assets

The wallet uses resource-backed branding assets from:

- `branding/finalis-app-icon.svg`
- `branding/finalis-logo-horizontal.svg`
- `branding/finalis-symbol.svg`

## Current scope

- keystore create, open, import, and export
- transparent receive and send flows
- bounded confidential-capable send/receive flows:
  - transparent -> confidential
  - confidential -> confidential (multi-coin, confidential change)
  - confidential -> transparent
- finalized-state activity view
- local connection settings with multi-endpoint lightserver failover under `Advanced`
- persisted Light and Dark themes through `QSettings`
- minimal About dialog and resource-backed branding
- optional validator interactions under `Advanced`
- local-first cached status / activity / pending-tx surfaces

The UI remains intentionally narrow. It does not expose backend capabilities that are not already present.

Branding note:

- the shipped binary target is `finalis-wallet`
