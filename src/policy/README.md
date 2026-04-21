# Policy Component

## Purpose

`src/policy/` defines policy-level validation and admission rules used by node execution paths.

## Responsibilities

- Admission and gatekeeping logic for transactions and operations.
- Centralized policy checks consumed by higher-level orchestration.

## Non-Goals

- Transport-level network concerns.
- UI or client presentation behavior.

## Dependency Notes

- Should provide clear policy interfaces to runtime components.
- Avoid circular coupling with high-level orchestration code.
