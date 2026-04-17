# Finalis: A Finalized-Tip Byzantine Settlement Protocol

**Technical Whitepaper**  
April 2026 | reikagitakashi@gmail.com

## Abstract

Finalis is a blockchain protocol designed around deterministic finality rather than fork-choice competition. The live protocol advances only at `finalized_height + 1`. A transition is committed when a quorum certificate over `(height, round, transition_id)` is verified against the canonical committee for that context. The protocol removes non-finalized chain selection, derives committee checkpoints deterministically from finalized state, and replays state from authoritative finalized artifacts.

The design objective is strict settlement semantics with bounded validation cost, explicit replay authority, and auditable consensus behavior under standard Byzantine assumptions.

## 1. Introduction

Classical proof-of-work chains expose probabilistic finality through depth and fork choice. Many BFT systems add explicit finality but still carry complex runtime branches around pending forks and speculative views.

Finalis adopts a narrower model:

- There is one authoritative finalized tip.
- Consensus work is meaningful only for `height = finalized_height + 1`.
- Deterministic replay from finalized artifacts reconstructs canonical state.

This model is intended for systems that prioritize unambiguous settlement over speculative throughput.

## 2. Model and Notation

Let:

- `H_f` be current finalized height.
- `T_h` be the frontier transition proposed for height `h`.
- `id(T_h)` be transition identifier.
- `C(h, r)` be canonical committee for height `h`, round `r`.
- `N = |C(h, r)|` and `Q = floor(2N/3) + 1`.

A vote message is bound to `(h, r, id(T_h))`.

A finality certificate contains:

- `height`, `round`, `transition_id`
- committee members used for verification
- canonicalized valid signatures (deduplicated, sorted, quorum-truncated)

## 3. Consensus Rule

A transition `T_h` is finalized iff:

1. `h = H_f + 1`
2. certificate payload matches `T_h`
3. committee context is valid for `(h, r)`
4. at least `Q` distinct committee signatures verify on the vote message

The runtime rejects work outside `H_f + 1` on the live path.

### 3.1 Safety intuition

Two conflicting finalized transitions at the same `(h, r)` require two quorum signer sets over different payloads. Quorum intersection implies at least one overlapping honest signer would need to sign conflicting messages, violating Byzantine assumptions.

### 3.2 Liveness assumptions

Liveness remains conditional on:

- eventual synchrony
- quorum participation
- valid proposal propagation

Failure of these conditions causes halt/degradation, not protocol-level ambiguous finalization.

### 3.3 Numbered propositions

**Proposition 1 (Single-Context Safety).**  
Under quorum intersection and honest non-equivocation assumptions, two distinct
transitions cannot both finalize at the same `(height, round)` context.

*Proof sketch.* Distinct finalized transitions at one `(h, r)` imply two quorum
signature sets over different payloads. Quorum intersection yields at least one
common honest signer, contradicting non-equivocation.

**Proposition 2 (Context Binding).**  
A valid vote for `(h, r, id(T_h))` cannot be reused as a valid vote for a
different `(h', r', id(T_{h'}))`.

*Proof sketch.* Signature verification binds the exact message tuple
`(height, round, transition_id)`. Any tuple change changes the verified
message.

## 4. Certified Ingress Layer

Finalis executes ordered ingress records into transitions. Each certified ingress record binds a transaction payload to lane and sequence context.

Ingress validity requires:

- certificate epoch equals `committee_epoch_start(finalized_height + 1)`
- non-empty, signature-valid, deduplicated signer set
- signer committee membership when committee context is available
- payload parse success with exact `txid` and `tx_hash` match
- lane assignment recomputes and matches certificate lane
- strict sequence continuity and `prev_lane_root` chaining

Stale-epoch ingress is rejected. Equivocation at fixed `(epoch, lane, seq)` is rejected and persisted as deterministic evidence.

**Proposition 3 (Ingress Epoch Freshness).**  
Certified ingress from a stale epoch cannot enter canonical execution.

*Proof sketch.* Ingress validation enforces
`certificate.epoch = committee_epoch_start(finalized_height + 1)`. Mismatch is
rejected pre-execution.

## 5. Deterministic State Transition

Canonical replay is defined as:

`S_h = ApplyFinalizedRecord(S_{h-1}, R_h)`

where `R_h` is the finalized record at height `h`.

### 5.1 Block and Frontier Append Path

```
 tx admission (AnyTx)
         |
         v
 certified ingress records (lane, seq, epoch-pinned cert)
         |
         v
 per-lane chaining + round-robin merge
         |
         v
 ordered frontier slice ---------> execute against parent UTXO/state
         |                                      |
         |                                      v
         |                           frontier transition T_h
         |                                      |
         +-------------------------------> proposal + votes
                                                |
                                                v
                                     QC(h, r, id(T_h)) verified
                                                |
                                                v
                              finalized frontier height h appended
                              (next starts at h+1 only)
```

Authoritative replay inputs are:

- genesis/network identity
- finalized frontier transitions in height order
- canonical finality certificate per finalized height
- finalized ingress artifacts required for transition verification

Non-authoritative caches may be rebuilt and cannot change canonical output.

**Proposition 4 (Replay Uniqueness).**  
For fixed authoritative finalized inputs, canonical derived state is unique.

*Proof sketch.* Replay applies a deterministic transition function in height
order over canonical finalized records. No alternate fork-choice branch is in
the live model.

## 6. Committee Checkpoints

Committee source is finalized-state-derived checkpoint metadata at epoch boundaries. Live proposal/vote handling consumes this output rather than recomputing policy heuristics locally.

Adaptive checkpoint parameters are deterministic from finalized qualified operator depth:

- target committee size
- minimum eligible operators
- checkpoint minimum bond

Fallback mode is explicit when eligibility falls below threshold; fallback metadata is part of deterministic checkpoint state.

## 7. Transaction and Script Semantics

Finalis supports version-aware execution:

- `Tx` (legacy transparent)
- `TxV2` (confidential-capable)
- runtime dispatch via `AnyTx`

Validator-control scripts (`SCONBREG`, `SCVALJRQ`, `SCVALREG`) are enforced with aligned semantics across legacy `Tx` and transparent outputs in `TxV2`.

Validation hardening includes:

- explicit input/output sum overflow checks
- max-fee policy enforcement on both V1 and V2 paths
- V2 fee validation: transparent inputs must cover transparent outputs + fee; confidential value conservation is enforced via commitment balance checks

**Proposition 5 (Script-Parity Invariant).**  
Validator-control script semantics are consistent across legacy `Tx` and
transparent outputs in `TxV2`.

*Proof sketch.* Validation dispatch uses shared script-semantic checks for
`SCONBREG`, `SCVALJRQ`, and `SCVALREG` invariants.

## 8. Economics and Incentives

Economics is separated into two deterministic planes:

1. Height-gated economics policy (`active_economics_policy(network, height)`) for reward/ticket parameters.
2. Adaptive checkpoint control plane for committee target/eligibility/bond thresholds.

Emission is finite and deterministic in current implementation:

- total primary emission: `7,000,000 FLS`
- emission horizon: `2,102,400` blocks
- reserve accrual during emission: `10%` of gross issuance

After cap, new issuance is zero; fees are epoch-pooled and settlement remains deterministic.

## 9. Ticket PoW Boundary

Ticket PoW is secondary and bounded:

- one bounded search per operator
- fixed nonce budget
- bounded bonus capped by active economics policy

Ticket PoW does not define finality and does not bypass admission controls. Admission PoW for onboarding/join scripts is a separate mechanism validated in script semantics.

## 10. Security Boundaries

Finalis security requires:

- signature unforgeability
- deterministic serialization and hashing
- quorum intersection assumptions
- deterministic checkpoint and replay rules

The protocol intentionally prefers safe halt over speculative reconstruction when authoritative finalized artifacts are missing or inconsistent.

**Proposition 6 (Fail-Closed Recovery).**  
Missing/inconsistent authoritative finalized artifacts lead to halt, not
speculative canonical continuation.

*Proof sketch.* Startup/replay requires canonical finalized artifacts and
consistency checks; violations are terminal in consensus-critical paths.

## 11. Operational Interpretation

For integrators and exchanges:

- settlement decisions must use finalized state only
- relay/mempool acceptance is not a settlement signal
- finalized inclusion is the credit-safe condition

No confirmation-depth heuristic is required by protocol semantics.

## 12. Conclusion

Finalis frames blockchain consensus as deterministic finalized-state progression rather than fork-choice competition. By constraining live processing to `finalized_height + 1`, binding finality to quorum certificates over exact transition context, and deriving committee and replay state from finalized artifacts, the protocol aims to provide auditable, bounded, and unambiguous settlement behavior.

## Appendix A. Threat Model (Short Form)

Adversary classes considered:

- Byzantine validators: equivocation, withholding, malformed votes/proposals.
- Network adversary: delay, drop, partition, eclipse.
- Storage adversary: cache corruption, partial persistence, artifact deletion.
- Economic/Sybil adversary: operator fragmentation, capital concentration,
  bounded ticket optimization.

Out-of-scope guarantees:

- real-world identity uniqueness of `operator_id`
- off-chain governance/social coordination guarantees
- wallet/explorer UX correctness as a safety primitive

Security posture:

- safety prioritized over availability during inconsistency
- deterministic replay prioritized over speculative reconstruction
- bounded validation and explicit artifact authority prioritized over heuristic
  acceptance

## References

- `docs/PROTOCOL-SPEC.md`
- `docs/CONSENSUS.md`
- `docs/LIVE_PROTOCOL.md`
- `docs/ECONOMICS.md`
- `docs/ONBOARDING-PROTOCOL.md`
- `docs/ADVERSARIAL_MODEL.md`
- `docs/spec/CHECKPOINT_DERIVATION_SPEC.md`
- `docs/spec/AVAILABILITY_STATE_COMPLETENESS.md`
