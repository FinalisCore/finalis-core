# Crypto Component

## Purpose

`src/crypto/` contains cryptographic primitives and wrappers needed by protocol, wallet, and address functionality.

## Responsibilities

- Signature/hash primitives and helper wrappers.
- Deterministic cryptographic operations used by core validation paths.

## Non-Goals

- Consensus orchestration.
- Network transport behavior.

## Dependency Notes

- Serves as a low-level dependency for multiple components.
- Should remain free of app-layer coupling.
