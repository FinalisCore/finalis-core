# Consensus

Mainnet identity (pre-launch):

- `network_name = mainnet`
- `network_id = fe561911730912cced1e83bc273fab13`
- `genesis_hash`: published at launch (mainnet has not launched)

This document describes the live finalized-tip BFT path at a high level.

It is not the normative source for checkpoint derivation. For that, use:

- [spec/CHECKPOINT_DERIVATION_SPEC.md](spec/CHECKPOINT_DERIVATION_SPEC.md)
- [spec/AVAILABILITY_STATE_COMPLETENESS.md](spec/AVAILABILITY_STATE_COMPLETENESS.md)

## Active Height Rule

The live consensus path only accepts work for:

`height = finalized_height + 1`

That means:

- there is no live longest-chain competition
- there is no non-finalized fork-choice rule
- proposals, votes, and QCs are only meaningful for the next finalized height

Relevant implementation:

- [src/node/node.cpp](../src/node/node.cpp)

Consensus execution is version-aware:

- legacy transparent transactions use `Tx`
- confidential-capable transactions use `TxV2`
- runtime dispatch uses `AnyTx`

## Committee Source

The active committee for a height is taken from the finalized checkpoint for the
epoch containing that height.

That checkpoint is derived only from finalized state at the prior epoch
boundary. It already incorporates:

- finalized validator lifecycle
- availability eligibility
- explicit `normal` / `fallback` checkpoint mode
- adaptive checkpoint target committee size
- adaptive checkpoint minimum eligible threshold
- adaptive checkpoint minimum bond

Consensus does not recompute those policy decisions in the live proposal/vote
path. It consumes the finalized checkpoint output.

## Overview

Finality is two-phase (Tendermint, Buchman / Kwon / Milosevic 2018, with timeout
certificates instead of nil votes). Design and safety argument:
[spec/TWO_PHASE_FINALITY.md](spec/TWO_PHASE_FINALITY.md).

1. The leader of `(H, r)` proposes a transition.
2. Validators **prevote** its `transition_id`.
3. A **polka** (quorum of prevotes for one `(H, r, id)`) makes a validator lock
   on `id` at `r` and **precommit** it.
4. A quorum of precommits for one `(H, r, id)` is the finality certificate.

Rounds advance on a timeout certificate (TC). `id` is always the transition id;
there is no payload-level identity.

## Proposal

A proposal (`PROPOSE`) consists of:

- `height`, `round`, `prev_finalized_hash`
- serialized frontier proposal
- optional `pol`: a polka for the proposed transition at `pol.round < round`
- optional `justify_tc`
- `proposer_signature` by the leader of `(height, round)` over
  `sha256d("SC-PROPOSE-V1" || D || height || round || id || pol_round)`, where
  `D = sha256d("SC-CHAIN-DOMAIN-V1" || network_id || genesis_hash)` binds every consensus
  signature (propose, prevote, precommit, timeout) to this chain

Two shapes are valid:

- fresh: `transition.round == round`, no `pol`
- re-proposal of the leader's valid value: the transition unchanged
  (`transition.round <= pol.round < round`) with its polka

The node accepts a proposal only if:

- `height == finalized_height + 1` and `round >= current_round`
- `prev_finalized_hash` matches the current finalized tip hash
- the proposer signature is valid for the leader of `(height, round)`
- the transition validates against canonical state (its own leader and round), including the
  leader's VRF proof over `(parent randomness, height)`
- `round > 0` carries a `pol` or a TC (except the singleton fallback)
- a `pol`, if present, verifies as a polka for exactly this transition

The serialized payload may contain either transparent-only transactions or the
currently supported confidential-capable `TxV2` subset.

Important boundary:

- proposer selection is deterministic from the finalized checkpoint
- if the checkpoint was derived in `fallback` mode, the live consensus path
  still uses that already-finalized committee output directly

## Prevote

`PREVOTE` carries `(height, round, id)` signed over
`sha256d("SC-PREVOTE-V1" || D || height || round || id)`.

A validator prevotes once per round, for the round's proposal, only if:

- it has not timed out of the round
- unlocked, or locked on `id`, or the proposal's `pol.round >= locked_round`
- it holds, in its local certified-ingress store, every record of the
  proposal's lane ranges, and those certificates validate (epoch, signatures,
  committee membership, lane, sequence, lane-root chaining) and merge to exactly
  the proposal's ordered slice
- applying the slice to its finalized state yields exactly the transition's
  signed `next_state_commitment` (checked once per transition, see
  `docs/PROTOCOL-SPEC.md` "State Commitments")

If records are missing it defers, requests the missing ranges from the peer
that sent the proposal and from peers whose advertised lane tips cover them,
and re-handles the proposal once they arrive. Because every honest voter holds
the certified records, any finalized slice can be fetched from at least
`f + 1` honest validators.

## Precommit

The precommit is the existing `VOTE` over `(height, round, id)`, signed as
`sha256d("SC-VOTE-V1" || D || height || round || id)`. On a polka for `(H, r, id)` with the proposal known:

- any round: the polka becomes the **valid value** if `r` is the highest polka
  round seen at `H`; its proposal is persisted
- `r` is the current round, not timed out, and the certified-ingress gate is
  `Ready`: lock `(id, r)` durably, then precommit

Vote acceptance requires `height == finalized_height + 1`, a committee member
for `(height, round)`, and a valid signature in the right domain.

## Certificates

Polka and finality certificate share one shape: `height`, `round`,
`transition_id`, quorum signatures. Validation: committee for
`(height, round)`, dedup by signer, signatures in the matching domain (prevote
or precommit), at least quorum `floor(2N/3) + 1`.

## Lock Rules

Per height, durable (primary + mirror rows, one atomic batch, written before
the corresponding message leaves the process):

- lock `(locked_id, locked_round)`, set only on a polka in the current round
- valid polka (highest-round polka) and its proposal
- the transition this node prevoted in each round

The lock moves only to a polka from a later round, and is released when the
height finalizes. A node never prevotes or precommits in a round below the
highest round it already voted in (its lock round and its latest prevote
round); round resets on reconnect and restarts do not lower that floor. A node never votes in a round for which it has already signed
a timeout vote. A node with unreadable safety state abstains at that height.

The leader re-proposes its valid value unchanged with the polka as `pol`;
without one it builds a fresh transition.

## Finalization

A block finalizes when the node has:

- the block body
- the committee for `(height, commit_round)`, where `commit_round` is the round
  of the precommits (`>= transition.round` when the transition was re-proposed)
- at least quorum valid precommits for the same `(height, commit_round, id)`

Before applying finality effects, the node re-verifies the certified frontier
record against current canonical state and derives the expected committee/quorum
from that recomputation. Signature filtering and quorum counting are performed
against this expected committee.

The finality proof is canonicalized before persistence:

- signatures sorted by signer pubkey
- duplicates removed
- truncated to exactly quorum

That truncation makes the certificate compact and deterministic. It is
**not** a participation signal. Participation of height `H` is carried by
its child transition `H+1` in `prev_finality_signers`. That field holds every
precommit the `H+1` proposer observed for
`(H, prev_finality_round, transition_id_H)`, including precommits that arrived
after quorum. `prev_finality_round` is a field of `H+1`: one transition can be
finalized by precommits from different rounds on different nodes, so the child
names the commit round instead of each node using its local certificate. Nodes
verify it before applying `H+1`:

- canonical encoding (sorted by pubkey, no duplicates)
- empty if and only if the parent is genesis
- `prev_finality_round >= round_H`
- every signer is a member of `H`'s committee at `prev_finality_round`
- every signature verifies over the vote-signing message for `H`
- at least `quorum(H)` signers

Liveness and reward accounting for `H` read this record (see
[REWARD-SETTLEMENT.md](REWARD-SETTLEMENT.md)). Re-proposals carry the
transition unchanged, so its `prev_finality_signers` is the one recorded when it
was first built.

The finalized transition then drives:

- finalized tip advancement
- deterministic state transition
- reward / settlement progression
- validator lifecycle replay state
- availability replay state
- checkpoint rebuild at epoch boundaries when required

Finalized execution remains validator-signature-driven even when confidential
transactions are present; `TxV2` does not change the validator-key consensus
model.

## Time Signatures

Once a node holds the finality certificate for `H`, if it is a member of `H`'s epoch committee it
signs `time_signature_message(D, H)` with its BLS key (derived from its validator seed, registered in
genesis or in its registration, copied into the checkpoint's `ordered_bls_keys`) and sends
`TIME_SIGNATURE {H, validator, signature}`. Receivers verify the signature against the checkpoint key
and relay it once; they keep the tip and one height either side. A node never signs a height it has
not finalized, and signs nothing in fail-stop. BLS signatures are deterministic, so signing again
cannot equivocate; the own signature is re-sent every round timeout until `H + 1` finalizes.

`H + 1` carries `prev_time_signature`: strictly ascending indices into `H`'s checkpoint keys and
their Lagrange-weighted aggregate (`crypto::mcfly_aggregate`). Before applying `H + 1`, nodes require
(`consensus::verify_prev_time_signature`):

- no signers and a zero aggregate if and only if the parent is genesis
- at least `time_signature_threshold(n) = quorum(n)` signers, each index `< n`
- the aggregate verifies for those keys on `time_signature_message(D, H)`

A leader proposes only once it holds the threshold for the parent (`proposal-build-wait
reason=time-signatures` otherwise). Safety: the at most `f < quorum` faulty members cannot produce
the aggregate for a height that is not final, because the honest members sign only after finality.
Liveness: the `n - f >= quorum` honest members all sign once they learn of finality. The aggregate
of `H` is the witness that opens a short `TxTimed` locked to `H` (encrypted with the same threshold to
the same keys, `consensus::committee_bls_key_root`); long locks are opened by the committee they name
(see Timed Transactions).

## Height-Locked Outputs

Locking value needs no secret and no committee: a transparent output (Tx v1) whose script names a
height. Every node checks it against the height of the block that spends it, so a lock holds for any
horizon, whoever validates then, and nothing that leaks or colludes can open it early.

- `SCHLOCK1` (locked): `"SCHLOCK1" | u64le unlock_height | pkh(20)`: spendable by `pkh` in a block at
  height `>= unlock_height`.
- `SCHLOCK2` (inheritance): `"SCHLOCK2" | u64le unlock_height | owner_pkh(20) | heir_pkh(20)`: the owner
  spends at any height, the heir from `unlock_height`.

The input carries the usual P2PKH `script_sig` over `signing_message_for_input`. An unlock height of 0
is not a lock (invalid script). Without a block height (no validation context) such an input is
invalid. The outputs are indexed under the script and under the P2PKH address of each key that may
spend them (`script_index_hashes`), so the beneficiary's wallet finds them by its own address.
`finalis-cli lock_send` and the wallet's height-locked send mode create them; ordinary sends spend
them once spendable. Hidden transfers and secrets use `TxTimed` below (long locks for far heights).

## Data Outputs

`SCDATA01`: `"SCDATA01" | data` with 1..80 bytes of data, in a Tx v1 output or a TxV2 transparent
output. Its value must be 0 and it is never spendable: it is not added to the UTXO set, only to
address history, under its script and, when the data is longer than 32 bytes, under the data script
of its first 32 bytes (a topic, such as an auction id, that lists every output starting with it).
A sealed transfer body may carry one (a bid paid with the money itself, tagged with its auction).

## Timed Transactions

A `TxTimed` (`src/utxo/confidential_tx.hpp`) is an ordered record of its own (version 3; never an
`AnyTx`), in the lane of its fee input's outpoint. Execution of block `h`
(`consensus::execute_frontier_slice` with a `TimedExecutionContext`):

1. **Settlement first.** Every escrow locked to `h - 1`, in inclusion order: SWE-decrypt the body key
   with the block's `prev_time_signature` (the aggregate for `h - 1`), open the body, and apply it
   like a record if it is a plain transfer (P2PKH / confidential inputs and outputs, and data
   outputs). A reveal body (`"SCREVEAL" | data`, 1..1016 bytes, `TimedReveal`) moves nothing: its
   data is published in the settlement record (`revealed_data`, node rows `TR:` by timed txid with
   the settling height). Applied or revealed: the bond is refunded at `(timed txid, 1)`. Otherwise
   the bond is a fee of block `h`. No record of `h` runs before, so none can front-run a revealed body.
2. **Records.** A `TxTimed` is accepted (escrowed) when `h <= unlock_height`,
   `committee_epoch` and `committee_root` name `h`'s epoch checkpoint keys, the ciphertext has
   threshold `quorum(n)` and its well-formedness proof verifies, the fee input is an unspent P2PKH
   output signed over the envelope, and its value is exactly `prepaid_fee + forfeit_bond + change`
   with `forfeit_bond >= kTxTimedMinForfeitBond`. The prepaid fee is a fee of `h`; change appears at
   `(timed txid, 0)`.

**Long locks.** A `TxTimed` whose unlock height lies beyond its inclusion epoch is a long lock: the
committee named at inclusion signs `time_signature_message(D, unlock_height)` once that height is
final, wherever its members are then (their BLS keys are seed-derived and permanent). Rules:

- inclusion: a prepaid fee of at least `kTxTimedLongFeePerEpoch` (0.001 FLS) per epoch, started or
  whole, past the inclusion epoch, and a body ciphertext of at most 1 KiB + tag (a reveal of up to
  1016 bytes fits exactly: archiving a key or a sealed bid that needs no input held for years)
- the named key set is kept in `CanonicalDerivedState::timed_key_sets` (rows `TK:`, by
  `committee_root`, dropped once no escrow names it), since checkpoints are pruned
- a block may carry `long_time_signatures`: `(unlock_height, committee_root, signer indices,
  aggregate)`, strictly ascending by `(unlock_height, committee_root)`, at most 16, each for an unlock
  height `u` with `u < h <= u + kTimedLongGraceBlocks` (480), a stored key set with at least one
  waiting long escrow, at least `quorum(n)` signers of that set and a verifying aggregate, and at
  most 16 escrows settled through them in all; otherwise the block is invalid. They are optional: a
  block never waits for them
- settlement, after the short locks and before any record: every long escrow an entry names, in
  inclusion order, opened with the entry's aggregate and the stored keys, exactly like a short lock
- expiry: a long escrow still waiting at `u + kTimedLongGraceBlocks + 1` is refunded (bond to the
  refund script, `expired` in the settlement record, the body never runs)
- bond lien: a validator whose BLS key a waiting long escrow names cannot withdraw its bond
  (`consensus::timed_bond_lien`, "bond held by a pending long time lock") until that escrow settles
  or `kTimedLongLienBlocks` (one year) after its inclusion

Intake: a `TxTimed` travels in `TX` / `SUBMIT_TX` like any record. The node admits it with the
same `consensus::check_timed_inclusion` the block applies (against the next height), a prepaid fee at
least the relay floor, and an unused fee input, into a timed pool next to the mempool; it is
certified in its lane and relayed like other records, and dropped once its fee input is spent or its
unlock height has passed. A proposer stops a lane before the per-block cap rather than let a record
be rejected. `finalis-cli timed_send` builds one (`build_signed_timed_tx`) from the committee keys of
`get_committee` (verbose).

Bounds: at most `kMaxTimedTxPerBlock` (8) accepted per block, at most
`kMaxTimedEscrowsPerUnlockHeight` (16) waiting per unlock height. Escrows are consensus state:
`CanonicalDerivedState::timed_escrows`, committed as `timed_escrow_commitment_root` at the end of the
post-state preimage and stored as one `TE:` row each.

## Transition Timestamp

`FrontierTransition.timestamp` is unix seconds and part of the transition id.

- canonical rule (replay): strictly greater than the parent's timestamp; the genesis time is the
  parent of height 1 (`frontier-timestamp-not-increasing`)
- the proposer sets `max(wall clock, parent + 1)`; a re-proposed valid value keeps its timestamp
- honest validators do not prevote a proposal stamped more than 60 s past their own clock

It feeds finalized-chain time: mempool hashcash stamp checks and explorer block times.

## Ingress Certifier Per Lane

Each lane has one designated certifier per epoch: committee member
`sha256d("SC-INGRESS-CERTIFIER-V1" || epoch_start || lane) mod committee_size`. Routing only (any
committee signature makes a valid certificate); it keeps one writer per lane and rotates every
epoch, which bounds censorship by a certifier to one epoch. Uncertified mempool transactions are
re-forwarded to the current certifier every 5 s.

## `PROPOSE` And Finalized Transition Delivery

`PROPOSE` is the live current-round proposal path.

Finalized artifact delivery on the live path is frontier-transition based.

Both converge through the same finalized application path.

That unified path:

- canonicalizes signatures
- persists the finalized frontier transition and the height-indexed finality
  certificate
- updates finalized tip and randomness (from the leader's verified VRF output only)
- applies deterministic state transition
- updates validator and availability state
- rebuilds the next epoch checkpoint when the epoch boundary is crossed
- applies version-aware transaction effects to version-aware UTXO state

Certified ingress that feeds the transition is validated as epoch-pinned input:

- certificate epoch must match the active epoch start for
  `finalized_height + 1`
- signer set must be signature-valid and committee-valid
- stale-epoch ingress certificates are rejected on receive and on replay

## Checkpoint Boundary

The most important live consensus boundary is:

- consensus for height `H` consumes the finalized checkpoint already derived for
  `epoch_of_height(H)`
- checkpoint derivation for the next epoch is itself a deterministic function of
  finalized state at the prior epoch boundary

So the protocol is split cleanly:

- finalized-tip BFT decides the next transition
- finalized epoch-boundary derivation decides the next epoch committee and
  proposer schedule

The second part is still consensus-critical, but it is not recomputed from
local heuristics during proposal/vote handling.

## Invariants

- only `finalized_height + 1` is processed in the live path
- prevotes and precommits are bound to `(height, round, transition_id)` in
  separate signing domains
- the committee for a height comes from the finalized checkpoint for that
  height's epoch
- checkpoint output is deterministic from finalized state only
- a precommit follows a polka and a durable lock; a lock moves only to a later
  polka, so at most one transition finalizes per height
- finalized transition delivery and local quorum finalization use the same
  state transition
- local finalization rechecks committee/quorum from recomputed transition state
- finalized transitions are applied deterministically
- restart and replay must reconstruct the same validator state, availability
  state, checkpoints, committees, and proposer schedule
