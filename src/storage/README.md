# Storage Component

## Purpose

`src/storage/` handles persistence and indexing needed for finalized-state operation.

## Responsibilities

- State persistence primitives.
- Index and retrieval support for runtime and read surfaces.
- Durable storage plumbing used by core components.

## Non-Goals

- Defining consensus policy.
- Implementing application/UI behavior.

## Dependency Notes

- Provides persistence services to higher-level runtime components.
- Should avoid acquiring dependencies on app-facing layers.
