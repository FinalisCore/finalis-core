# QUICK STAT

## Purpose

This is a fast user guide for going from install to validator registration on:

- Linux
- macOS
- Windows

It covers both:

- CLI flow
- Wallet UI/UX flow

## 1) Prerequisites

- Build tools installed (CMake, Ninja, C++ toolchain).
- Qt5 Widgets installed if you want the wallet UI.
- A running local node/lightserver RPC endpoint, usually:
  - http://127.0.0.1:19444/rpc

## 2) Build

Run from repo root.

### Linux and macOS

```bash
cmake -S . -B build -G Ninja
cmake --build build -j
```

### Windows (PowerShell)

```powershell
cmake -S . -B build -G Ninja
cmake --build build -j
```

## 3) Default data paths

### Linux and macOS

- DB: ~/.finalis/mainnet
- Validator key: ~/.finalis/mainnet/keystore/validator.json

### Windows

- DB: %APPDATA%\\.finalis\\mainnet
- Validator key: %APPDATA%\\.finalis\\mainnet\\keystore\\validator.json

## 4) Reward participation vs registration

These are now separate paths.

- A zero-balance operator can participate in the `3%` onboarding reward bucket by producing valid finalized epoch tickets.
- Wallet funding is required only for on-chain onboarding registration and later validator registration.

Funding is required when you want to:

- submit `onboarding-register` (`SCONBREG`)
- submit `validator-register`
- pay fees and post the validator bond

If `validator_status` shows:

- `spendable_utxos=0`
- `spendable_balance=0`

then on-chain registration will fail until coins are sent to that wallet address and become finalized.

## 5) CLI flow (install to validator registration)

Step 1: Onboarding registration (SCONBREG)

This step is only needed if you want on-chain onboarding registration. It is not required just to compete for the `3%` onboarding reward bucket through valid finalized epoch tickets.

### Linux and macOS

```bash
./build/finalis-cli onboarding-register \
  --db ~/.finalis/mainnet \
  --file ~/.finalis/mainnet/keystore/validator.json \
  --rpc http://127.0.0.1:19444/rpc
```

### Windows (PowerShell)

```powershell
.\build\finalis-cli.exe onboarding-register `
  --db "$env:APPDATA\.finalis\mainnet" `
  --file "$env:APPDATA\.finalis\mainnet\keystore\validator.json" `
  --rpc http://127.0.0.1:19444/rpc
```

Advanced option:

- Use `--validator-file <path>` only if the validator identity key is different from the funding wallet key passed with `--file`.

Step 2: Start validator registration/join flow

### Linux and macOS

```bash
./build/finalis-cli validator-register \
  --db ~/.finalis/mainnet \
  --file ~/.finalis/mainnet/keystore/validator.json \
  --rpc http://127.0.0.1:19444/rpc
```

### Windows (PowerShell)

```powershell
.\build\finalis-cli.exe validator-register `
  --db "$env:APPDATA\.finalis\mainnet" `
  --file "$env:APPDATA\.finalis\mainnet\keystore\validator.json" `
  --rpc http://127.0.0.1:19444/rpc
```

Step 3: Check status

### Linux and macOS

```bash
./build/finalis-cli validator-register-status \
  --db ~/.finalis/mainnet \
  --file ~/.finalis/mainnet/keystore/validator.json \
  --rpc http://127.0.0.1:19444/rpc

./build/finalis-cli validator_status \
  --db ~/.finalis/mainnet \
  --file ~/.finalis/mainnet/keystore/validator.json
```

### Windows (PowerShell)

```powershell
.\build\finalis-cli.exe validator-register-status `
  --db "$env:APPDATA\.finalis\mainnet" `
  --file "$env:APPDATA\.finalis\mainnet\keystore\validator.json" `
  --rpc http://127.0.0.1:19444/rpc

.\build\finalis-cli.exe validator_status `
  --db "$env:APPDATA\.finalis\mainnet" `
  --file "$env:APPDATA\.finalis\mainnet\keystore\validator.json"
```

## 6) Wallet UI/UX flow

Step 1: Build wallet target

### Linux and macOS

```bash
cmake -S . -B build -G Ninja
cmake --build build --target finalis-wallet -j
./build/finalis-wallet
```

### Windows (PowerShell)

```powershell
cmake -S . -B build -G Ninja
cmake --build build --target finalis-wallet -j
.\build\finalis-wallet.exe
```

Step 2: In the wallet

- Open your wallet key.
- Go to Advanced -> Validator.
- Fill:
  - Node DB Path
  - Validator Key Path
  - RPC Endpoint (for example http://127.0.0.1:19444/rpc)
- Click Register Validator.

Important:

- the wallet must already control finalized spendable funds for on-chain registration flows
- zero-balance operators may still participate in the ticket-based onboarding reward path before registration

Behavior:

- If onboarding registration is still required, the wallet runs onboarding registration first.
- Then it proceeds with validator registration and tracking.

## 7) Quick checks if registration fails

- Confirm RPC endpoint is reachable and synced.
- Confirm DB path and validator key path point to mainnet data.
- Confirm wallet/key network matches mainnet.
- Confirm there are spendable finalized funds for registration fees/bond when using on-chain registration.
- Confirm validator key can be decrypted with the provided passphrase.
- Confirm the funding wallet address has received coins and that they are finalized, not just pending.

## 8) One-line summary

CLI and Wallet both support full install -> onboarding registration -> validator registration flows on Linux, macOS, and Windows, while ticket-based onboarding reward participation can begin before funded on-chain registration.
