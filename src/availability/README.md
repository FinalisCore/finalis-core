# Availability Component

## Purpose

`src/availability/` contains availability-related logic used by checkpoint and committee eligibility flows.

## Responsibilities

- Availability state support for consensus-era decisions.
- Retention and completeness helpers used by finalized-state derivation.

## Non-Goals

- P2P transport implementation.
- Explorer or wallet presentation behavior.

## Dependency Notes

- Works closely with consensus/state layers.
- Should avoid dependencies on UI and app-facing modules.
