# P2P Component

## Purpose

`src/p2p/` contains peer networking and transport logic used by node components.

## Responsibilities

- Peer lifecycle and connectivity.
- Message transport and framing.
- Networking utilities needed for distributed operation.

## Non-Goals

- Defining protocol truth.
- Owning consensus validation rules.
- Exposing end-user application surfaces.

## Dependency Notes

- Should provide transport capabilities to higher-level orchestration.
- Should avoid embedding high-level policy or application behavior.
