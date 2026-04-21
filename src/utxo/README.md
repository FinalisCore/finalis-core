# UTXO Component

## Purpose

`src/utxo/` implements UTXO data model behavior and finalized-state transition logic tied to transaction application.

## Responsibilities

- UTXO set operations.
- Transition helpers for apply/validate flows.

## Non-Goals

- P2P connection management.
- Wallet UI behavior.

## Dependency Notes

- Core dependency for node execution and finalized-state read surfaces.
- Should remain focused on state-model correctness.
