# Codec Component

## Purpose

`src/codec/` provides encoding and decoding support for protocol and storage-adjacent data structures.

## Responsibilities

- Binary/structured serialization helpers.
- Deterministic encode/decode behavior expected by protocol components.

## Non-Goals

- High-level consensus policy.
- Network peer lifecycle management.

## Dependency Notes

- Acts as a low-level utility layer.
- Should avoid depending on high-level orchestration modules.
