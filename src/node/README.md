# Node Component

## Purpose

`src/node/` contains orchestration code for node runtime execution, integrating consensus decisions, state transition application, and subsystem coordination.

## Responsibilities

- Coordinate finalized-state progression.
- Integrate consensus and committee outcomes into runtime execution.
- Drive interactions across networking, mempool, storage, and validation subsystems.

## Non-Goals

- Defining cryptographic primitives.
- Owning low-level storage engine internals.
- Replacing protocol specification documents.

## Dependency Notes

- Depends on consensus, storage, p2p, and shared/common layers.
- Should not pull in application/UI-specific concerns.
