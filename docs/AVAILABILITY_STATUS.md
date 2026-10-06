# Availability Audit Status (V1.0.0)

**Status:** Intentional Simulated Baseline for V1.0.0 Production Stability.
**Applies to:** mainnet genesis through the post-genesis availability hard fork (roadmap item 26).
**Code:** `src/consensus/availability_retention.{hpp,cpp}`; driven from `node.cpp` and
`canonical_derivation.cpp` via `advance_live_availability_epoch`.

This document defines what the availability layer does on the live network in V1.0.0. It is a
specification of current behavior, not a design target. Operators should read it before relying
on availability scores, seat budgets or "retained history" as a security property.

---

## 1. Summary for operators

- **No live challenges are issued and no responses are checked.** Every bonded operator that is
  assigned at least one retained prefix in an epoch is credited with `VALID_TIMELY` for every
  audit slot of that epoch.
- **Availability scores therefore measure assignment, not storage.** A node that deletes its
  history scores exactly the same as one that keeps it.
- **History retention is not enforced on-chain.** It relies on operators honestly running nodes
  with default retention. Do not treat availability state as proof that data is retrievable.
- **No operator can be ejected or penalized by the availability layer in V1.0.0.** The only
  reachable adverse state is `PROBATION` through score decay (section 4).
- Real cryptographic challenge/response enforcement is deferred to a post-genesis hard fork
  (section 6).

---

## 2. Live protocol semantics (A1: challenges decoupled from scoring)

Per epoch, `advance_live_availability_epoch` → `refresh_live_availability_state` does the following
for every operator in the bonded set:

1. Compute `epoch_seed = availability_audit_seed(finalized_identity_id, epoch)`.
2. For each retained prefix, assign it to the `kReplicationFactor = 3` operators with the lowest
   `H(epoch_seed, prefix_id, operator_pubkey)`; `retained_count` = prefixes assigned to the operator.
3. Outcomes come from `live_epoch_audit_outcomes`, **not** from network evidence:

   | Condition | Outcomes credited |
   |---|---|
   | `retained_count > 0` | `kAuditsPerOperatorPerEpoch = 4` × `VALID_TIMELY` |
   | `retained_count == 0`, operator in `PROBATION` and previously `ACTIVE` (recovery rule active) | 1 × `VALID_TIMELY` |
   | `retained_count == 0`, otherwise | none |

4. `apply_epoch_audit_outcomes` decays and updates the score:
   `score = score × 9800 / 10000 + Σ delta` (`VALID_TIMELY` = +1), then `update_operator_status`.

The challenge/response primitives exist and are tested but are **not on the live path**:
`build_audit_challenges_for_operator`, `make_audit_response`, `verify_audit_response`,
`verify_chunk_merkle_proof`. There is no P2P message for challenges or responses. The persisted
`evidence` vector is observability-only and never affects eligibility (`operator_is_eligible`).

Because no `NO_RESPONSE`, `VALID_LATE` or `INVALID_RESPONSE` outcome is ever produced live,
`missed_audits`, `late_audits` and `invalid_audits` stay at 0 on mainnet.

---

## 3. Assignment influence (A2)

`epoch_seed` is derived from the finalized transition identity, whose content the proposer
chooses. A proposer can in principle grind transition contents to steer which operators receive
prefixes in the next epoch. Under the simulated baseline, assignment count *is* the score input,
so grinding can favor or starve specific operators' scores and seat budgets
(`operator_seat_budget`). It cannot cause ejection (section 4). The hard fork must derive the
seed from a value the proposer cannot bias (for example, the committee randomness beacon).

---

## 4. Scoring imbalance and state boundaries (A3)

Assignment is pseudo-random per epoch, so operator scores depend on luck and on how many prefixes
exist (prefixes exist only when lanes carry certified ingress; they expire after
`kRetentionWindowMinEpochs = 64` epochs).

- **Probability of zero assignment** in an epoch is roughly `(1 − 3/N)^P` for `N` operators and `P`
  retained prefixes. On a quiet network (small `P`) this is common.
- **Decay with zero assignments:** the score shrinks 2% per epoch toward 0. From the steady state
  of about 200 (4 credits per epoch at α = 0.98), an operator crosses below
  `kEligibilityMinScore = 10` after about 150 consecutive zero-assignment epochs. It then moves
  `ACTIVE → PROBATION` and loses eligibility, through no fault of its own.
- **Warmup stall:** leaving `WARMUP` requires `kMinWarmupAudits = 50` successful audits, which is at
  least 13 epochs *with* assignments. A new operator on a low-traffic network can remain in
  `WARMUP` far longer than `kWarmupEpochs = 4`.
- **Recovery:** a `PROBATION` operator that was once `ACTIVE` receives one guaranteed credit per
  epoch (table in section 2) and returns to `ACTIVE` after the recovery threshold (1 epoch with
  ≤ 3 tracked operators, otherwise 2).
- **EJECTED is unreachable in V1.0.0.** Ejection requires `invalid_audits > 0` or
  `score ≤ kEjectionScore = −20`. Neither can occur, because all live deltas are ≥ 0 and decay
  truncates toward 0.

**Risk under raw enforcement:** if real challenges were enforced with the current parameters,
`NO_RESPONSE` (−1 each) could drive honest but briefly offline operators below −20, and a single
`INVALID_RESPONSE` sets `invalid_audits > 0`, which is a **permanent** ejection with no recovery
path. These parameters must be revisited before enforcement is switched on (section 6).

---

## 5. What is already hardened for the future protocol

These changes landed before genesis (commit "Require operator signature for availability audit
evidence") so the primitives are safe to wire in later:

- `verify_audit_response` attributes a response to an operator only if the **challenged operator's**
  signature verifies. Unsigned or third-party-signed responses count as `NO_RESPONSE` with no
  evidence, so a third party cannot frame an honest operator.
- Merkle proofs are bound to the tree shape (`chunk_index < chunk_count`, exact depth), which
  rejects interior-node-as-leaf and duplicated-tail proofs without changing committed roots.

---

## 6. Post-genesis hard fork: requirements

Scheduled as roadmap item 26. The upgrade is consensus-breaking and must activate at a fixed
height. Minimum scope:

1. P2P challenge/response messages, with responses gossiped and included as on-chain evidence.
2. Live outcomes derived from verified evidence instead of `live_epoch_audit_outcomes`.
3. An unbiasable audit seed (A2).
4. Enforcer-verifiable timeliness (`responded_slot` is currently self-reported by the operator).
5. Domain-separated chunk Merkle tree (leaf vs. inner node).
6. Rebalanced scoring: bounded `NO_RESPONSE` penalties, a recovery path from ejection or an explicit
   slashing rule, and assignment-normalized scores so luck cannot cause `PROBATION` (A3).
7. A migration rule for existing operator states at the activation height.
