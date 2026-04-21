# Keystore Component

## Purpose

`src/keystore/` contains key storage and key-management support used by node and wallet-adjacent flows.

## Responsibilities

- Key persistence helpers.
- Key loading and validation support.

## Non-Goals

- Wallet UI interactions.
- Network transport or consensus policy ownership.

## Dependency Notes

- Depends on crypto/common primitives.
- Should avoid importing app-specific behavior.
