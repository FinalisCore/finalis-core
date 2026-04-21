# Wallet Core Component

## Purpose

`src/wallet/` contains wallet-related core logic and primitives used by wallet-facing applications.

## Responsibilities

- Wallet data and transaction preparation support.
- Core wallet logic shared by wallet-integrated flows.

## Non-Goals

- Desktop UI behavior.
- Network transport internals.
- Protocol-level consensus decisions.

## Dependency Notes

- Should depend on shared primitives and transaction/state layers as needed.
- Should avoid direct UI coupling.
