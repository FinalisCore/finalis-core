# Onboarding Component

## Purpose

`src/onboarding/` contains validator/operator onboarding logic and related state transitions.

## Responsibilities

- Onboarding eligibility and transition support.
- Workflow-level primitives for validator lifecycle entry.

## Non-Goals

- Wallet UI workflows.
- General P2P transport concerns.

## Dependency Notes

- Closely related to policy and consensus state.
- Should preserve deterministic behavior and clear boundary ownership.
