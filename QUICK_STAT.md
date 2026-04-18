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

## 4) CLI flow (install to validator registration)

Step 1: Onboarding registration (SCONBREG)

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

## 5) Wallet UI/UX flow

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

Behavior:

- If onboarding registration is still required, the wallet runs onboarding registration first.
- Then it proceeds with validator registration and tracking.

## 6) Quick checks if registration fails

- Confirm RPC endpoint is reachable and synced.
- Confirm DB path and validator key path point to mainnet data.
- Confirm wallet/key network matches mainnet.
- Confirm there are spendable finalized funds for fees/bond.
- Confirm validator key can be decrypted with the provided passphrase.

## 7) One-line summary

CLI and Wallet both support full install -> onboarding registration -> validator registration flows on Linux, macOS, and Windows when local node/lightserver and key paths are configured correctly.
