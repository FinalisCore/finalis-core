# Mempool Component

## Purpose

`src/mempool/` manages pending transaction admission and in-memory transaction lifecycle prior to finalized inclusion.

## Responsibilities

- Transaction intake and policy gating.
- Pending transaction bookkeeping and retrieval support.

## Non-Goals

- Final consensus decisions.
- Public API/UI rendering.

## Dependency Notes

- Works with validation, policy, and node orchestration layers.
- Should avoid taking ownership of finalized-state persistence concerns.
