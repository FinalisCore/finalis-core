# Finalis Wallet

`Finalis Wallet` is the Qt desktop wallet shipped in this repository. It manages a local keystore, reads finalized wallet state through lightserver, signs transactions locally, and exposes the wallet and mint flows already implemented by the backend.

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

This is a structural refactor only. Core wallet behavior, finalized-state assumptions, storage, validator onboarding logic, and mint protocol behavior are intentionally preserved.

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

## Branding assets

The wallet uses resource-backed branding assets from:

- `branding/finalis-app-icon.svg`
- `branding/finalis-logo-horizontal.svg`
- `branding/finalis-symbol.svg`

## Current scope

- keystore create, open, import, and export
- receive and send flows
- finalized-state activity view
- local connection settings with multi-endpoint lightserver failover under `Advanced`
- persisted Light and Dark themes through `QSettings`
- minimal About dialog and resource-backed branding
- optional validator and mint interactions under `Advanced`

The UI remains intentionally narrow. It does not expose backend capabilities that are not already present.

Branding note:

- the shipped binary target is `finalis-wallet`
