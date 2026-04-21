# Consensus Component

## Purpose

`src/consensus/` implements validator committee behavior, voting/finality mechanics, and epoch/checkpoint-related consensus rules.

## Responsibilities

- Committee and epoch logic.
- Vote, quorum, and finality rule handling.
- Deterministic consensus artifacts needed by runtime execution.

## Non-Goals

- Network transport details.
- Wallet UX logic.
- Explorer/light UI concerns.

## Dependency Notes

- Should remain protocol-focused and deterministic.
- Should avoid dependencies on application-layer modules.
