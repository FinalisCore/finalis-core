# Lightserver Component

## Purpose

`src/lightserver/` contains finalized-state RPC support logic used by the lightserver binary and related read surfaces.

## Responsibilities

- Finalized-state query support.
- RPC-facing glue for status, transaction, and history lookups.

## Non-Goals

- Consensus evolution rules.
- Wallet desktop UX concerns.

## Dependency Notes

- Depends on storage/state and shared protocol types.
- Should keep API surface deterministic and finalized-state focused.
