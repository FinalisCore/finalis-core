# Address Component

## Purpose

`src/address/` contains address encoding, decoding, and validation primitives used across core and application surfaces.

## Responsibilities

- Address representation helpers.
- Encoding and decode utilities.
- Validation rules tied to supported address formats.

## Non-Goals

- Wallet UI behavior.
- Consensus policy decisions.

## Dependency Notes

- Should depend on shared utility and crypto primitives as needed.
- Should remain independent from app-layer concerns.
