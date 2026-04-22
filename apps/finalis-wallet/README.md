# Finalis Wallet

`Finalis Wallet` is the Qt desktop wallet shipped in this repository. It manages a local keystore, reads finalized wallet state through lightserver, signs transactions locally, and exposes the wallet and mint flows already implemented by the backend.

Current restarted mainnet identity reference:

- `network_name = mainnet`
- `network_id = fe561911730912cced1e83bc273fab13`
- `genesis_hash = eaae655a1eec3c876bd2e66d899fc8da93d205a5df36a2665f736387aa3cb78a`

## Build and run

If Qt5 Widgets is available, the wallet target is built with the normal project build:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target finalis-wallet -j"$(nproc)"
./build/finalis-wallet
```

## Connected services

- Lightserver: finalized-state reads and transaction broadcast
- Mint endpoint: optional mint deposit, issuance, and redemption flows

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
- `Mint / Privacy`
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

## Lightserver cross-check

On refresh, the wallet also samples up to three configured lightserver endpoints and compares the reported:

- network name
- finalized height
- finalized transition hash

It reports one of:

- `Cross-check: consistent`
- `Cross-check: one endpoint differs`
- `Cross-check: endpoint disagreement`

This is an informational confidence signal only. It does not verify the chain, does not block wallet operations, and endpoints can disagree temporarily.

Adaptive regime diagnostics are also informational only. They are rendered from
canonical lightserver status and do not influence wallet behavior or consensus.

Fresh-genesis boundary:

- if a configured endpoint reports a different `network_id` or `genesis_hash`,
  it is not the same network
- abandoned-chain DBs or stale wallet assumptions must not be reused as if they
  belonged to the restarted mainnet

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
  - confidential -> transparent
- finalized-state activity view
- local connection settings with multi-endpoint lightserver failover under `Advanced`
- persisted Light and Dark themes through `QSettings`
- minimal About dialog and resource-backed branding
- optional validator and mint interactions under `Advanced`
- local-first cached status / activity / pending-tx surfaces

The UI remains intentionally narrow. It does not expose backend capabilities that are not already present.

Branding note:

- the shipped binary target is `finalis-wallet`
