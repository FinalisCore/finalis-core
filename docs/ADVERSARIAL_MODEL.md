# Adversarial Model

## 1. Scope

This document defines the adversarial model for Finalis Core consensus as currently implemented.

Current restarted mainnet identity:

* `network_name = mainnet`
* `network_id = 258038c123a1c9b08475216e5f53a503`
* `genesis_hash = fd5570810b163e43a90ef5e8203e8aef34c89072f5f261c4de74aa724a615211`

It covers:

* consensus safety
* liveness assumptions
* deterministic replay and derived-state correctness
* finality certificate binding in block headers
* operator and economics-related attack surface
* classification of faults into safe halt, safety failure, liveness degradation, economic degradation, and operational risk

It does not cover:

* wallet UX
* explorer behavior
* non-consensus RPC convenience behavior
* generic operational practices unless they directly affect protocol safety
* social, legal, or governance processes outside protocol execution

---

## 2. System Model

Finalis Core is a deterministic finalized-state blockchain.

At any time:

* there is exactly one finalized tip
* there is exactly one canonical derived consensus state for a given finalized record sequence

A finalized record is:

* one finalized frontier transition
* one canonical finality certificate for that finalized height

Finalized history is the ordered sequence of finalized records starting from genesis.

Consensus state is derived from finalized history, not from any fork-choice rule. There is no longest-chain or heaviest-chain selection.

Authoritative replay input is strictly:

* genesis and network configuration
* the finalized frontier transition sequence
* one canonical finality certificate per finalized height
* finalized ingress certificates/bytes and lane state needed to verify frontier transitions

After the fresh-genesis reset, DB contents or endpoint assumptions from the
abandoned chain are outside this authoritative replay input and must not be
treated as valid inputs to the current network.

Post-activation binding rule:

Let `H_bind` be the activation height.

* For all finalized records with height `h <= H_bind`:

  ```
  prev_finality_cert_hash = ZERO_HASH
  ```

* For all finalized records with height `h > H_bind` and `h > 1`:

  ```
  prev_finality_cert_hash = H(cert[h-1])
  ```

This binds finalized certificate history into subsequent finalized artifacts.

Definitions:

* Finalized transition: a frontier transition accepted through valid finality certificate verification and canonical application.
* Finality certificate: a quorum certificate over the exact `(height, round, block_id)` payload, including committee membership and canonicalized signer set.
* Certified ingress record: `(certificate, tx_bytes)` pair where certificate epoch is pinned to the expected active epoch and lane/seq/root links validate.
* Canonical derivation: the deterministic transition from prior derived state and a finalized record to the next derived state.
* Committee checkpoint: the canonical epoch-level committee representation derived from finalized state.
* Proposer schedule: deterministic proposer ordering derived from checkpoint inputs.
* Operator grouping: economics grouping keyed by `operator_id`. It is not a real-world identity guarantee.
* Ticket work: bounded, versioned search used as a secondary selection input, not open-ended mining.

---

## 3. Authoritative Inputs and Derived State

Authoritative inputs:

* genesis and network configuration
* finalized frontier transition sequence
* canonical finality certificate per finalized height

Canonical derived state includes:

* finalized height and hash
* validator registry
* operator mapping
* finalized randomness
* reward state
* committee checkpoints
* proposer schedule inputs
* consensus-state commitment
* finalized frontier vector and lane roots

Non-authoritative (cache only):

* validator rows
* reward rows
* checkpoint rows
* randomness caches
* commitment cache
* auxiliary indexes

These may be deleted or recomputed without changing consensus output.

Replay invariants:

* For any finalized history `F`:

  ```
  derive(F) = unique canonical state S
  ```

* There exists no alternate valid derivation path producing a different state.

---

## 4. Adversary Classes

### 4.1 Byzantine Validator Adversary

Capabilities:

* vote withholding
* equivocation
* malformed proposals
* selective participation

Protocol response:

* invalid blocks rejected
* invalid certificates rejected
* certificate verification enforces membership, payload, and quorum

Residual risk:

* if quorum assumptions fail, safety failure becomes possible
* selective participation degrades liveness

---

### 4.2 Network Adversary

Capabilities:

* message delay, drop, reorder
* partitioning
* eclipsing validators
* suppressing proposer visibility

Protocol response:

* safety is independent of timing assumptions
* liveness depends on eventual synchrony and quorum connectivity

Residual risk:

* partitions may halt progress
* proposer suppression may stall rounds

---

### 4.3 Storage / Persistence Adversary

Capabilities:

* corrupt cache rows
* delete certificates
* mutate commitment cache
* induce partial writes

Protocol response:

* canonical replay ignores caches
* mismatch → fatal
* missing certificate → fatal
* partial finalized writes → rejected

Residual risk:

* loss of authoritative finalized data prevents startup
* protocol prefers halt over speculative reconstruction

---

### 4.4 Economic / Sybil Adversary

Capabilities:

* multi-operator capital splitting
* capital concentration
* bounded ticket optimization
* participation strategy manipulation

Protocol response:

* operator grouping reduces intra-operator splitting advantage
* economics depend on bond, operator count, and participation

Residual risk:

* operator_id is not identity
* multi-operator control remains possible
* Sybil resistance is economic, not identity-based

---

### 4.5 Implementation / Upgrade Adversary

Capabilities:

* heterogeneous binaries
* activation mismatch
* serialization divergence

Protocol response:

* canonical encoding is unique
* activation rules are explicit
* mismatch results in rejection or halt

Residual risk:

* upgrade coordination is required to avoid partition

---

### 4.6 Ingress Relay / Replay Adversary

Capabilities:

* relaying stale certified ingress from prior epochs
* replaying mismatched lane/sequence/root chains
* submitting conflicting certificates at fixed `(epoch, lane, seq)`

Protocol response:

* ingress certificate epoch must match `committee_epoch_start(finalized_height + 1)`
* lane assignment, sequence continuity, and `prev_lane_root` chaining are re-validated
* signer validity and committee-membership checks are enforced in context
* ingress equivocation is rejected and persisted as deterministic evidence

Residual risk:

* sustained network-level suppression can still delay ingress propagation and hurt liveness

---

## 5. Assumptions

### 5.1 Cryptographic

* hash collision resistance
* signature unforgeability
* deterministic serialization
* deterministic certificate hashing

---

### 5.2 Quorum / Committee

Safety requires quorum intersection:

* certificates bind `(height, round, block_id)`
* signer sets intersect
* honest signer does not sign conflicting payloads

Violation → safety failure.

---

### 5.3 Network

Liveness requires:

* eventual synchrony
* quorum participation
* proposer availability

Violation → halt.

---

### 5.4 Derivation

* all honest nodes use identical derivation rules
* all finalized certificates are available
* fallback derivation, when entered, is explicit and deterministic

Violation → halt.

---

### 5.5 Economics

* operator_id is not identity
* Sybil resistance is limited
* economic concentration is possible

---

## 6. Safety Model

Claim:

> Under stated assumptions, two conflicting finalized transitions at the same height cannot both be accepted as finalized by honest nodes.

Because:

* certificates bind exact payload
* committee and signature verification are canonical
* quorum intersection prevents conflicting certification

Hardening ensures:

* no multi-path replay divergence
* no cache-based reconstruction
* certificate history is chain-bound post-activation

---

## 7. Liveness Model

Liveness is conditional.

Requires:

* online quorum
* valid proposer
* message delivery

Failures result in:

* halt (not divergence)

The protocol prioritizes:

> deterministic safety over continuous availability

---

## 8. Deterministic Replay and State-Machine Integrity

Derived state is a pure function:

```
S_h = ApplyFinalizedRecord(S_{h-1}, record_h)
```

Replay and live execution must produce identical:

* state
* commitment

Failures causing halt:

* missing certificate
* checkpoint mismatch
* commitment mismatch
* invalid binding hash
* inconsistent carried certificate hash
* missing/invalid certified ingress required to verify finalized transition execution

The system enforces:

> no ambiguity in canonical derivation, explicit fallback when required, deterministic replay/rebuild

---

## 9. Economic and Sybil Model

Operator grouping addresses:

* splitting within a declared operator

It does not address:

* multiple operators under one actor

Ticket work:

* bounded
* secondary influence
* not primary security

Economic risks:

* capital concentration
* multi-operator control
* participation manipulation

---

## 10. Fault Taxonomy

| Fault                        | Effect                   | Class                |
| ---------------------------- | ------------------------ | -------------------- |
| Missing certificate          | startup failure          | Safe halt            |
| Checkpoint mismatch          | startup failure          | Safe halt            |
| Commitment mismatch          | startup failure          | Safe halt            |
| Invalid binding hash         | reject / halt            | Safe halt            |
| Pre-activation non-zero hash | reject                   | Safe halt            |
| Network partition            | stalled progress         | Liveness degradation |
| Proposer failure             | stalled progress         | Liveness degradation |
| Quorum equivocation          | conflicting finalization | Safety failure       |
| Ingress equivocation         | ingress rejection/evidence | Safe halt          |
| Stale ingress epoch replay   | ingress rejection         | Safe halt            |
| Operator splitting           | influence skew           | Economic degradation |
| Ticket optimization          | selection skew           | Economic degradation |
| Binary mismatch              | network split            | Operational risk     |

---

## 11. Residual Risks and Non-Goals

* no identity oracle
* economic centralization possible
* bounded ticket may add limited security
* partitions halt system
* safe halt is intentional
* no formal proof claimed

---

## 12. Summary

Finalis Core guarantees:

* deterministic replay
* single canonical state
* strict finality
* no ambiguous recovery

Under:

* cryptographic assumptions
* quorum honesty
* eventual synchrony

The protocol converts:

* ambiguity → halt
* inconsistency → halt

Remaining open areas:

* economics
* network resilience
* parameter tuning
