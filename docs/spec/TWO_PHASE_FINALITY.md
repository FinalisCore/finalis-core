# TWO_PHASE_FINALITY

Status: implemented (pending external BFT review, §8.5). Sections 1–2 describe the one-phase protocol it replaced.

## 1. Problem

Today a quorum of votes for `(h, r, transition_id)` is both the QC and finality. That
one-phase rule cannot be both safe and live with `n = 3f + 1`:

- **Safety.** The vote lock compares `consensus_payload_id`, which excludes round, leader and
  `prev_finality_signers`. Two transitions with the same payload (two empty slices are the common
  case) proposed in different rounds can each collect a quorum. They are distinct finalized
  transitions at one height. This was captured in a 12-node test: `a93a34a5` (round 0) and
  `57af3062` (round 1) both finalized at height 1, after validators timed out of round 0 and then
  cast late round-0 votes. The network split on `prev_finalized_hash` and halted.
- **Liveness.** The only lock release is "a QC for another payload", but a QC is already finality,
  so a lock is never released before the height finalizes. Locks split across payloads with no QC
  (3 / 2 with quorum 4) halt the height forever.

A new leader cannot tell "P finalized but the QC was not seen" from "P reached only `2f` votes".
The first forbids moving on, the second requires it. One voting phase cannot separate them.

Mitigation already in place: a validator never votes in a round it has timed out of
(`local_timed_out_rounds_`). It removes the captured trigger, not the hazard.

## 2. Goals and non-goals

Goals:

- At most one transition finalizes per height (cross-round safety), under `f < n/3` Byzantine
  committee members and an asynchronous network.
- Progress after GST with an honest leader.
- Keep "a finality certificate is a quorum of signatures over `(h, r, id)`" so sync, replay, RPC
  and exchange integrations do not change.

Non-goals: changing committee selection, ingress, execution, settlement or the economics model.

## 3. Protocol

This is Tendermint (Buchman, Kwon, Milosevic, "The latest gossip on BFT consensus", 2018,
Algorithm 1), adapted. Round changes keep the existing timeout votes and TC instead of nil votes.

### 3.1 Messages

| Message | Signed bytes | Notes |
|---|---|---|
| `PROPOSE(h, r, proposal, valid_round, pol)` | proposer signs `sha256d("SC-PROPOSE-V1" ‖ h ‖ r ‖ id ‖ valid_round)` | `pol` = prevote quorum for `id` at `valid_round` when `valid_round ≥ 0` |
| `PREVOTE(h, r, id)` | `sha256d("SC-PREVOTE-V1" ‖ h ‖ r ‖ id)` | new |
| `PRECOMMIT(h, r, id)` | `sha256d("SC-VOTE-V1" ‖ h ‖ r ‖ id)` | the existing `Vote`, unchanged on the wire |
| `TIMEOUT(h, r)` | unchanged | quorum = TC, advances the round |

A **polka** for `(h, r, id)` is `Q` distinct committee prevotes for it. A **finality certificate**
is `Q` distinct committee precommits for one `(h, r, id)`: the existing `FinalityCertificate`.

`id` is always `transition_id()` of the proposed `FrontierTransition`. No payload ids.

### 3.2 Per-height state (durable)

```
round, step ∈ {propose, prevote, precommit}
locked_id,  locked_round  = none, -1
valid_id,   valid_round   = none, -1     (+ the full FrontierProposal for valid_id)
sent_prevote[r], sent_precommit[r]       (what this node signed in each round)
timed_out[r]                             (already in place)
```

All of it is written with a durable batch **before** the corresponding message leaves the process,
as the vote lock is today. A node with unreadable safety state abstains at that height (unchanged).

### 3.3 Rules

Leader of `(h, r)`:

- if `valid_id` is set: propose that exact `FrontierProposal` (its `transition.round` is the round
  it was built in, `≤ r`) with `valid_round` and its polka;
- else build a fresh transition at round `r`, `valid_round = -1`.

On `PROPOSE(h, r, P, vr, pol)` from the leader of `(h, r)`, in step `propose`, not timed out of `r`:

- `vr = -1`: prevote `id(P)` iff `locked_round = -1` or `locked_id = id(P)`; otherwise prevote nothing
  (wait for timeout).
- `vr ≥ 0`, `vr < r`, `pol` is a valid polka for `id(P)` at `vr`: prevote `id(P)` iff
  `locked_round ≤ vr` or `locked_id = id(P)`.
- A prevote additionally requires: `P` validates against canonical state, and the certified-ingress
  vote gate is `Ready` (missing records defer, as today).

On a polka for `(h, r, id)` with the proposal for `id` known, the first time in round `r`:

- if step is `prevote`: set `locked_id = id`, `locked_round = r`, then precommit `id`
  (certified-ingress gate also required for the precommit);
- in any step: set `valid_id = id`, `valid_round = r`.

On `Q` precommits for `(h, r, id)` at any round, with the proposal known: finalize (unchanged path:
`finalize_if_quorum` → `apply_finalized_frontier_effects_locked`).

Vote-round floor: a validator never prevotes or precommits in a round below the highest round it
has already voted in (`max(locked_round, highest sent prevote round)`, both durable). Tendermint
gets this for free because its round only grows; here reconnect resets and restarts move the local
round back to 0. Without it, a late polka can make a node precommit at round `r` after it already
prevoted something else at `r' > r`, and two values finalize (TLC counterexample,
`formal/two_phase_finality.tla`).

On TC for `(h, r)`: move to `r + 1`, step `propose`. Timeouts per step grow with the round as
`round_timeout_ms_for_round` does today.

### 3.4 Canonical commit round

With re-proposal of `valid_id`, one transition can be finalized by precommits from different rounds
on different nodes. The local `FinalityCertificate.round` may then differ between nodes, and today
`resolve_parent_finality_context` reads the parent round from local metadata. That would split
verification of `prev_finality_signers` at `h + 1`.

Change: `FrontierTransition` gains `prev_finality_round`. `prev_finality_signers` must be `≥ Q(h)`
precommits for `(h, prev_finality_round, id(h))`, with `prev_finality_round ≥` the parent
transition's own round. Canonical `finalized_block_metadata[h].round` stays the transition's own
round (deterministic on every node); the local certificate round is local evidence only.

## 4. Why it is safe and live (sketch)

Safety. Suppose `T` finalizes with precommits at round `r`. Let `S` be the honest validators among
them; `|S| ≥ f + 1`, and each locked `T` at round `r` (an honest node precommits only after a polka).
Any finality for `U ≠ T` needs a polka for `U` at some round `≥ r`.

- Round `r`: there is a polka for `T` at `r`; a polka for `U` at `r` would need an honest node to
  prevote twice in `r` (quorum intersection). None exists.
- Rounds `> r`: let `r*` be the first round `> r` with a polka for some `U ≠ T`. Its `Q = 2f + 1`
  prevotes cannot all come from the `n - |S| ≤ 2f` validators outside `S`, so some node in `S`
  prevoted `U` at `r*`. Locked on `T` at a round `ℓ ≥ r`, it does that only for a proposal with a
  polka for `U` at some `vr` with `ℓ ≤ vr < r*`. No polka for `U` exists at `r` (above) or in
  `(r, r*)` (minimality of `r*`). Contradiction.

So no `U ≠ T` ever gets a polka at a round `≥ r`, and none can finalize.

Liveness. After GST with an honest leader `L` at round `r`: honest nodes that are locked are
locked on some `id` at `ℓ`; `L` carries the highest `valid_round` it has seen with its polka, which
is `≥` every honest lock once `L` has seen their polkas (gossip delivers them before the round
timeout grows past `Δ`). So every honest node prevotes, a polka forms, all precommit, and the height
finalizes. Split locks resolve because a newer polka moves every lock forward, which the one-phase
rule could not do.

## 5. Mapping onto the code

| Area | Change |
|---|---|
| `p2p/messages` | `PREVOTE` message type; `ProposeMsg` gains `valid_round`, `pol` (replaces `justify_qc`), proposer signature |
| `utxo/validate` | `prevote_signing_message`, `propose_signing_message` |
| `FrontierTransition` | `prev_finality_round` (serialized, part of `transition_id`) |
| `node` vote tracking | prevote tracker beside `votes_`; polka detection |
| `node_consensus` | `handle_propose_result` / `can_vote_for_frontier_locked` replaced by the §3.3 rules; lock set on polka, not on own vote; `local_vote_locks_` → `locked_*`, `valid_*` |
| `node.cpp` proposer | re-propose `valid_*` unchanged instead of rewriting round / leader / signers |
| safety-state persistence | serialize the §3.2 state; same primary + mirror scheme |
| `canonical_derivation` | verify `prev_finality_signers` against `prev_finality_round` |
| removed | `consensus_payload_id` lock comparison, `highest_qc_payload_by_height_`, `allow_late_round0_after_first_timeout` |
| unchanged | `FinalityCertificate`, sync, replay, certificate checks, ingress, execution |

## 6. Test plan

Deterministic multi-node tests (test hooks drive message order):

1. The captured fork: late round-0 votes plus an empty round-1 proposal. One transition finalizes.
2. Split prevotes 3 / 2 at round 0, no polka; round 1 leader proposes fresh; height finalizes.
3. Polka for `T` at round 0 seen by a minority, timeout; round 1 leader re-proposes `T` with its
   polka; locked and unlocked nodes prevote; `T` finalizes with the same `transition_id`.
4. Lock moves: locked on `T` at round 0, polka for `U` at round 1 seen; node prevotes `U` at round 2.
5. Safety: `T` finalized at round 0 by precommits a minority has not seen; no later round finalizes
   anything else (Byzantine leader proposes `U` with a forged / stale `pol`).
6. Restart while locked: lock, valid value and sent votes survive; no double prevote / precommit.
7. Same transition finalized at rounds 0 and 1 on different nodes; `h + 1` validates everywhere
   (`prev_finality_round`).
8. Singleton committee fallback still finalizes.
9. Stress: the committee test loop (12 nodes), several hundred sequential iterations, zero forks.

## 7. Rollout

Fresh chain, no migration. Wire changes (`PREVOTE`, `ProposeMsg` fields, `prev_finality_round`) are
part of genesis protocol version. Docs to update with the change: `CONSENSUS.md`, `LIVE_PROTOCOL.md`,
whitepaper §2–3 (restore a cross-round safety proposition with this proof).

## 8. Decisions

1. Proposer signature: proposals are signed by the leader of `(h, r)` over
   `(h, r, id, valid_round)`, re-proposals included. Safety does not depend on it, liveness does.
2. Round changes use TC, no nil prevotes / precommits. The liveness argument assumes TC formation
   after `Δ`.
3. One `round_timeout_ms` per round; no separate propose / prevote / precommit timeouts.
4. Certified-ingress gate on both prevote and precommit: keeps "finality certificate ⇒ `f + 1`
   honest holders of the slice's records".
5. Open: external BFT review before mainnet. Bounded model check done:
   `formal/two_phase_finality_abstract.tla` (Agreement holds, complete search, rounds 0..3,
   `n = 4`, `f = 1`; dropping the lock rule or the vote-round floor each yields a fork).

Implementation notes beyond §3:

- A body that arrives after its polka or precommit quorum (proposal or uncertified transition
  delivery) re-runs polka and finality checks for every round from its own to the current one.
- Re-gossip: while a height is stalled (`2 × round_timeout_ms` without finality), every
  `round_timeout_ms` a validator re-sends its own timeout votes and prevotes for the latest three
  rounds at that height, every precommit it cast at that height (newest 32 rounds), the
  signatures of the polka it holds and of the precommit set closest to quorum. Without it a vote
  lost during a partition is never retransmitted, and a TC that misses one side's timeout votes
  never forms: a healed no-quorum partition halted the height for good
  (`scripts/chaos_devnet.py`, first run). Precommits count per round only, so re-sending just the
  latest one stranded a round-1 quorum cast by 6 of 7 validators while later rounds fell short
  (12 rounds for one height in a Byzantine run).
- Equivocators: a validator observed sending two conflicting votes (or proposals) in one round
  keeps having its votes counted, one per round (the tracker keeps the first and records the
  conflict as evidence; a slashing record is stored). Its votes are not relayed. Ignoring an
  equivocator adds no safety (the rules are safe for `f` arbitrary voters) but leaves only honest
  validators to form quorums: with `f` equivocators caught, every honest validator is needed for
  every height.
- After a restart or a reconnect reset clears the vote trackers, the node re-adds its own recorded
  prevotes and the precommit its lock implies (Ed25519 is deterministic, so these are the votes
  already sent).
