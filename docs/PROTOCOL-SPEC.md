# Finalis Protocol Specification

## Scope

This document describes the current live Finalis Core protocol at a high level.

It is intentionally descriptive, not the byte-level normative source. For the
live checkpoint path, the normative documents are:

- [docs/spec/CHECKPOINT_DERIVATION_SPEC.md](spec/CHECKPOINT_DERIVATION_SPEC.md)
- [docs/spec/AVAILABILITY_STATE_COMPLETENESS.md](spec/AVAILABILITY_STATE_COMPLETENESS.md)

Primary implementation paths:

- [src/node/node.cpp](../src/node/node.cpp)
- [src/consensus/finalized_committee.cpp](../src/consensus/finalized_committee.cpp)
- [src/consensus/epoch_tickets.cpp](../src/consensus/epoch_tickets.cpp)
- [src/consensus/monetary.cpp](../src/consensus/monetary.cpp)
- [src/storage/db.cpp](../src/storage/db.cpp)

Onboarding-specific admission and reward semantics are specified in:

- [docs/ONBOARDING-PROTOCOL.md](ONBOARDING-PROTOCOL.md)

## System Model

Finalis is a finalized-tip-only blockchain.

- the live path processes only `finalized_height + 1`
- there is no non-finalized fork-choice rule
- a block is either finalized with valid proof or it is not on the committed
  chain

Consensus is validator-based and committee-based.

- validators are bonded participants in finalized validator state
- finalized committee checkpoints define the active epoch committee
- proposer order is derived deterministically from the finalized checkpoint
- finality is quorum signatures over the exact `(height, round, block_id)`
  payload

## Frontier Storage And Replay

The live implementation is frontier-only.

Authoritative finalized storage is:

- one finalized tip record
- one finalized height-to-transition mapping per finalized height
- one persisted frontier transition per finalized height
- one canonical finality certificate per finalized height
- finalized state roots and committed derived state

The live restart/replay path does not rebuild from persisted finalized blocks.

It rebuilds from:

- genesis configuration and genesis artifact identity
- finalized frontier transitions
- one canonical finality certificate per finalized height
- finalized ingress/state storage required to verify those transitions

Important boundary:

- finality certificates are indexed canonically by finalized height
- transition-hash lookups are resolved through frontier transition storage and
  then matched against the height-indexed certificate
- obsolete block-era storage must fail closed rather than being interpreted as
  live frontier state

## State Commitments

Each frontier transition commits to the state it produces:

- `next_state_root`: sparse Merkle root of the UTXO set after the transition
  (the leaves `utxo_commitment_key(op) -> utxo_commitment_value(entry)`).
- `next_state_commitment`: the post-state commitment
  `sha256d("SC-POST-STATE-V1" || height || frontier || utxo_root || validator_root ||
  finalized_randomness || reward_root || reserve || checkpoint_root || availability epoch ||
  availability_operator_root || availability_prefix_root || join window || liveness window ||
  confidential_pool_value || block_metadata_root)` (`consensus_post_state_commitment`).
  `block_metadata_root` covers each retained height's `(transition round, quorum, signer count)`,
  which ticket difficulty is derived from.

The post-state leaves out the two values derived from the transition itself
(its id and its finality link hash), so a transition can sign it. Nothing else
in the post-state depends on the transition id; the availability audit seed in
particular is `availability_audit_seed(finalized_randomness, epoch)`, which the
leader cannot grind.

History in the committed state is bounded (`prune_consensus_history`, applied at every height,
counted back from the epoch of the next height):

- committee checkpoints: the unbond delay plus 2 epochs (at least 8), so equivocation evidence can
  be checked against its height's committee for as long as the bond can be slashed;
- block metadata and per-epoch randomness: 8 epochs (ticket difficulty reads 6);
- epoch reward states: unsettled ones, and settled ones for one more epoch.

Nodes keep the full history in their database for queries; only the committed state is bounded, so
the work per block does not grow with the age of the chain.

An exiting validator whose bond is the outpoint `(zero_hash, 0)` (genesis bonds, which are not
UTXOs and so cannot be spent by an unbond) is withdrawn by consensus once its unbond delay has
passed (genesis validators while bootstrap penalty-exit protection is active).

The full state commitment is
`sha256d("SC-CANON-STATE-V3" || finalized_identity || finality_link_hash || post_state_commitment)`.

Every node checks `next_state_commitment` before it prevotes or precommits, and
again whenever it applies the transition (finalization, sync, replay), so a
finalized chain never carries a wrong value.

Startup (fast start, on by default; `--no-fast-start` disables it) loads the
finalized state from the database and accepts it only if its post-state
commitment equals the tip transition's `next_state_commitment`, its lane
roots match the tip's `ingress_commitment`, and the tip's finality certificate
verifies against the committee in the loaded (verified) checkpoints. It never
re-derives committee checkpoints. Any mismatch falls back to a full replay from
genesis. The same check lets a future state sync verify a
downloaded state against one quorum-signed transition.

## Certified Ingress Rules

Ingress is consensus-critical input to frontier transitions and is now epoch
pinned and replay-validated.

Ingress acceptance on live nodes and during frontier replay requires:

- certificate `epoch` equals `committee_epoch_start(finalized_height + 1)`
- certificate signer set is non-empty, signature-valid, and deduplicated by
  validator pubkey
- each signer is in the ingress committee for the expected epoch when committee
  context is available
- lane assignment recomputes from transaction content and must match
  `certificate.lane`
- `(lane, seq)` continuity is strict and `prev_lane_root` must chain exactly
- tx payload parse, `txid`, and `tx_hash` must match certificate fields

Equivocation handling is fail-closed:

- same `(epoch, lane, seq)` with different certificate body is treated as
  ingress equivocation
- deterministic equivocation evidence is persisted before rejection

During frontier merge, certified ingress records are verified again against the
current expected epoch and lane-root chain. Stale-epoch ingress certificates are
rejected even if signatures are otherwise valid.

## Transaction Model

The current live codebase is version-aware:

- legacy transparent transactions use `Tx`
- confidential-capable transactions use `TxV2`
- runtime dispatch uses `AnyTx`

Signatures bind the chain. Every transaction signature covers the chain domain
`D = sha256d("SC-CHAIN-DOMAIN-V1" || network_id || genesis_hash)`, the same value consensus
signatures cover:

- `Tx` input: `sha256d("SC-SIG-V4" || D || u32le(input_index) || sha256d(tx without script_sigs) || S)`
- `Tx` unbond: `sha256d("SC-UNBOND-V2" || D || sha256d(tx without script_sigs) || u32le(input_index) || S)`
- `S = sha256d("SC-SPENT-V1" || varint(n) || n x (u64le(value) || varbytes(script_pubkey)))` over the
  outputs the `n` inputs spend, in input order. A `Tx` names its inputs only by outpoint, so without
  `S` a signer told a smaller value for a coin than the chain holds would sign away the difference
  as fee; with it, any wrong value or script makes every signature of the transaction invalid.
  (`TxV2` and the `TxTimed` fee input need no `S`: the balance proof and the exact fee-input sum
  fail on a wrong value.)
- `TxV2` input (transparent or confidential): tag `SC-SIG-V3`
- `TxV2` balance proof: `sha256d("SC-BAL-V3" || D || tx without signatures)`

A transaction signed for one network fails validation on every other one, even when it spends an
outpoint that exists on both (genesis validator bonds). Validation without a chain identity fails
closed. Wallets take `D` from their network and its pinned genesis (`finalis-cli`: embedded genesis
or `--genesis-hash`; JS SDK: `chainDomainHex`).

Mainnet identity (pre-launch):

- `network_name = mainnet`
- `network_id = fe561911730912cced1e83bc273fab13`
- `genesis_hash`: published at launch (mainnet has not launched)

Version-aware paths are live in:

- mempool admission
- frontier execution
- canonical replay
- finalized read surfaces

Current supported confidential subset:

- transparent inputs -> confidential outputs
- confidential inputs -> transparent outputs

Not implemented as a live anonymity system:

- no decoys
- no hidden input set
- no Monero-style sender anonymity

The live transaction model also includes explicit validator-control outputs:

- `SCONBREG` for onboarding admission
- `SCVALJRQ` for bonded validator join request
- `SCVALREG` for the bond-carrying validator registration output

Validator-control script semantics are unified across `Tx` and `TxV2`:

- `SCONBREG` must be zero-value, PoP-valid, and cannot appear with
  `SCVALREG`/`SCVALJRQ` in the same transaction
- `SCONBREG` and `SCVALJRQ` carry the validator's BLS time-signature key with a BLS proof of
  possession; the Ed25519 proof covers that key, and a BLS key belongs to one validator only
- `SCVALJRQ` and `SCVALREG` must appear as a matched pair for the same
  validator pubkey
- admission PoW checks for onboarding/join requests are enforced from the same
  policy context in both transaction versions
- finalized replay applies lifecycle effects from accepted `AnyTx`, not
  legacy-only transaction subsets

Fee and overflow safety are also aligned:

- V1 and V2 both enforce max-fee policy bounds through validation context
- input/output accumulation performs explicit overflow checks before arithmetic
- transparent-side fee constraints for `TxV2` are strict when no confidential
  inputs exist
- frontier execution rejects special-script transactions when validation context
  is unavailable

## Two Control Planes

The live protocol now has two separate deterministic control planes.

### Height-gated economics schedule

The canonical schedule is selected by block height only through:

- `active_economics_policy(network, height)`

It remains the source of truth for:

- reward settlement policy
- capped-bond reward helpers
- ticket bonus caps
- related economics metadata

The schedule is centralized in:

- [src/common/network.hpp](../src/common/network.hpp)
- [src/common/network.cpp](../src/common/network.cpp)

The mainnet currently has a single active economics policy from genesis.

No wall clock data is used in economics activation.

### Adaptive checkpoint regime

Committee target, checkpoint minimum eligible, and checkpoint minimum bond are
not stepped by future activation heights.

They are derived at epoch boundaries from finalized qualified operator depth
only.

Live adaptive rule summary:

- allowed targets: `{16, 24}`
- initial target: `16`
- expand `16 -> 24` only after `qualified_depth >= 30` for `4` consecutive
  epochs
- contract `24 -> 16` only after `qualified_depth <= 22` for `6` consecutive
  epochs
- `adaptive_min_eligible = adaptive_target_committee_size + 3`
- `adaptive_min_bond = clamp(150 * sqrt(adaptive_target_committee_size / max(qualified_depth, 1)), 150, 500)`
- availability minimum bond is the same value as adaptive checkpoint minimum
  bond

These values are serialized into finalized checkpoint metadata and are replay
equivalent.

## Epoch Structure

Epoch boundaries are determined by `committee_epoch_blocks` in network config.

For each epoch:

- finalized randomness advances block by block, from the leader's VRF only:
  `R_h = sha256d("SC-RAND-FRONT-V2" || R_{h-1} || VRF_out(leader, alpha_h) || h)` with
  `alpha_h = "SC-RAND-VRF-V1" || R_{h-1} || h`; each transition carries the leader's proof
  (`leader_vrf_proof`, checked against `leader_pubkey`, construction in `src/crypto/vrf.hpp`).
  A leader cannot move `R_h` through the transition's timestamp, slice or round; it can only
  decline to propose, which hands the slot to the next round's leader.
- a finalized committee checkpoint is built at epoch start
- Ticket PoW difficulty is derived deterministically for the epoch
- reward accrual is tracked across finalized transitions
- the prior epoch is settled in the first block of the next epoch
- the next checkpoint target / eligible threshold / checkpoint minimum bond are
  derived from finalized state at the prior epoch boundary

## Fees And Issuance

Fees and issuance are separated.

- before the cap:
  - current-block fees are immediate on the frontier transition path
  - issuance accrues from finalized participation
  - `10%` of gross issuance accrues into protocol reserve
  - `90%` of gross issuance accrues into validator settlement rewards
- after the cap:
  - new issuance is zero
  - finalized transaction fees are pooled by epoch
  - reserve subsidy may top up the pooled epoch fees at settlement
- settlement is applied at the next epoch boundary

This separation exists because the final QC signer set is known only after
finalization.

Primary emission is exactly `7,000,000 FLS` over `2,102,400` blocks.
After that, new issuance is zero.

The active emission curve is finite and deterministic:

- `12` years
- `175,200` target blocks per year
- annual decay factor `0.8`
- exact yearly budgets precomputed to sum to the hard cap

The reserve is protocol-native state, not a treasury account controlled by a
validator or operator.

For avoidance of ambiguity:

- the protocol has a fixed primary emission total
- it has a strict hard cap in the current code

## Security Resource

The primary scarce resource is bonded stake aggregated at the operator level.

Let:

`operator_total_bond = sum(active validator bonds under one operator)`

The live economics helpers use the canonical reward/admission policy:

`min_bond(height) = clamp(min_bond_floor, min_bond_ceiling, base_min_bond * sqrt(target_validators / max(1, active_operators)))`

`max_effective_bond(height) = max_effective_bond_multiple * min_bond(height)`

`effective_bond(operator) = min(operator_total_bond, max_effective_bond(height))`

`effective_weight(operator) = max(1, floor(sqrt(effective_bond(operator))))`

This cap is applied at the operator aggregate level before influence is turned
into committee weight or reward weight.

Important boundary:

- checkpoint minimum bond for the next epoch is derived by the adaptive
  finalized-depth rule

## Committee And Availability

Checkpoint derivation is operator-based on the live path.

- validators are grouped by `operator_id`
- one bounded best-ticket search is performed per operator
- finalized validator lifecycle and finalized projected availability state gate
  future committee eligibility
- only lifecycle-active, checkpoint-bond-qualified, and availability-eligible
  operators contribute to qualified depth
- if eligible operator count is below the checkpoint minimum, the checkpoint
  enters explicit `fallback` mode with explicit fallback reason
- sticky fallback at exact threshold remains live and unchanged

Persisted availability evidence is observability-only and is excluded from:

- eligibility
- checkpoint output
- committee ordering
- proposer schedule
- state commitment semantics

## Ticket PoW

Ticket PoW is secondary.

- it does not define committee membership by itself
- it contributes only a bounded modifier

## Product / Read Surface Semantics

Lightserver, explorer, and wallet remain finalized-state-driven for settlement
decisions.

Current implementation details:

- lightserver serves version-aware transaction and finalized-status views
- explorer uses local-first caches for startup, tx, and transition summaries
- explorer exposes cached-vs-live provenance and freshness
- wallet persists local snapshots, confidential account/request/coin state, and
  cached pending-tx status so startup is not blocked on live RPC

Confidential visibility boundary:

- finalized transaction presence is public
- confidential amounts and recipient semantics are intentionally not rendered as
  transparent-style public fields
- at most one PoW contribution is counted per operator
- the active cap is always taken from
  `active_economics_policy(height).ticket_bonus_cap_bps`
- tickets are derived from `operator_id`
- exactly one bounded ticket search is performed per operator
- the full bounded nonce range is evaluated and the best result is kept
- representative validator choice is deterministic and independent of ticket
  quality

## Core Assumptions

Safety assumes:

- Ed25519 signatures are unforgeable
- finalized committee checkpoints are derived identically from the same
  finalized chain
- the same finalized chain yields the same settlement and derived state
- fewer than quorum committee members sign conflicting finality for one block

Liveness depends on:

- eventual delivery of proposals, votes, and finalized transitions
- sufficient online participation from the finalized committee
- deterministic restart recovery from finalized history

## Non-Negotiable Properties

- only one finalized transition is valid for a given height
- all finalized paths apply the same state transition
- finalized ingress is epoch-pinned to the active committee epoch and rejected
  on stale epoch mismatch
- finalized committee checkpoints are deterministic from finalized state
- adaptive checkpoint metadata is deterministic from finalized state
- operator splitting does not linearly increase primary committee influence
- the live protocol removes best-of-N Ticket PoW gain within one operator
- reward settlement is exactly once per epoch boundary
- reward/ticket-policy economics resolve through the canonical height-gated
  schedule
- checkpoint target / minimum eligible / checkpoint minimum bond resolve through
  the adaptive finalized-depth rule
