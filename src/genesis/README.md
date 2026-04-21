# Genesis Component

## Purpose

`src/genesis/` handles genesis state loading, validation, and initialization support.

## Responsibilities

- Canonical genesis data handling.
- Startup validation logic for genesis compatibility.

## Non-Goals

- Ongoing runtime consensus behavior.
- UI or operator workflow concerns.

## Dependency Notes

- Should provide startup/state bootstrap services to runtime initialization.
- Should avoid broad cross-component dependencies.
