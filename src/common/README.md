# Common Component

## Purpose

`src/common/` contains shared foundational types, configuration helpers, constants, and cross-cutting utilities.

## Responsibilities

- Reusable primitives used by multiple core components.
- Network/configuration scaffolding shared across binaries.

## Non-Goals

- Feature-specific business logic ownership.
- App UI behavior.

## Dependency Notes

- Intended as a dependency target for many components.
- Should not become a dumping ground for unrelated feature code.
