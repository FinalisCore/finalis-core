# Signaled Activation (approved design, in progress)

Status: decisions 1–4 approved 2026-11-10 (§8); decision 5 open. Origin: Discord tester feedback 2026-11-10 (point 2) and the
2026-11-08 flag day (h=4800 → 4801, 61 min pause).

## 1. Problem

Consensus changes activate at a height hard-coded in the release (`NetworkConfig::*_activation_height`).
Two things follow:

1. Old and new binaries refuse each other at handshake as soon as the new binary starts, because
   `consensus_rules_fingerprint` includes the rules version. Nodes split into two groups that cannot
   talk, even before the activation height.
2. At the activation height the chain stops until enough of **both** the current committee and the
   previous one (time signatures need ⅔ of the parent epoch's signers) have upgraded. On 2026-11-08
   the new committee had quorum at 18:10, but only 8 of the 13 previous signers had upgraded, so
   proposals waited until 18:31.

A flag day only works when everyone follows the announcement. On mainnet one idle operator holding
more than ⅓ of a committee stops the chain, and nobody can see from the chain itself that an upgrade
is pending.

## 2. Goals

- An upgrade activates only when the network has shown it is ready. If it never becomes ready,
  the chain keeps running on the old rules. Either way, no halt.
- Validators that upgrade late do not stop the chain. They stop earning until they upgrade.
- The schedule is on-chain and visible: `get_status` shows pending upgrades, readiness and the
  activation height.
- No admin key and no founder action. Operators decide by running the release
  (project goal: the chain must run without the founder).
- Deterministic: every node, including one replaying from genesis, computes the same activation height.

Not goals: on-chain governance of *what* the rules are (that stays in the code release), and
emergency activation without signaling.

## 3. Mechanism

### 3.1 Upgrade definition (in the binary)

Each release that changes consensus carries a table of known upgrades:

```
UpgradeDef {
  id            : Hash32   // H("FINALIS-UPGRADE-V1" || name || new_rules_fingerprint)
  name          : string   // e.g. "c2-certifier-terms"
  signal_start  : height   // the node auto-signals from here on (policy, not consensus)
}
```

The table is **not a consensus input** (A1, 2026-11-11). Signal admission, `UPG:` state, lock-in,
window and exclusion are functions of finalized state only, so a binary that does not know an
upgrade derives exactly the state of one that does. Otherwise the first signal would split old
binaries off long before activation, which §3.5 must avoid. The table decides only which rules a
binary implements, what it signals, and when it reports `upgrade_required` (§3.6).

Rule code keeps both paths behind `upgrade_active(id, height)` instead of
`height >= cfg.network.X_activation_height`. This is the pattern already used for the current
activation heights. Only the source of the height changes, from a constant to chain state.

### 3.2 Readiness signal (on-chain)

A fee-free transaction with no inputs and exactly one zero-value `SCUPGSIG` output: prefix(8) |
validator_pubkey(32) | upgrade_id(32) | expiry_height(u64le) | sig(64). Nothing is spent, so the node
can send it with the validator key alone and the operator funds nothing (decision 7, §8). It is
accepted from the network's `upgrade_signal_activation_height` (mainnet 0; testnet-3 set at its flag
day), so releases without the mechanism never see one in a block they validate. Rules (stateless
ones in step 2a, stateful ones in 2b):

- The validator key signs `upgrade_signal_message(chain_domain, upgrade_id, validator_pubkey,
  expiry_height)`; the operator is the validator's canonical operator id.
- `SCUPGSIG` is valid only as the single output of a transaction without inputs, and only at heights
  `h` with `h <= expiry_height <= h + committee_epoch_blocks`. A transaction without inputs can be
  sent again by anyone, so the signed expiry is what stops a replay: after a window fails, an old
  signature cannot reopen it for a validator that no longer runs the upgrade. It also gives each new
  signal its own txid.
- It is valid only if `operator` is an active operator and has no earlier signal for this id, and,
  unless the upgrade is already locked in, the operator holds fewer than
  `kMaxOpenUpgradeSignalsPerOperator` (2) signals on upgrades not yet locked in. Any id is
  admissible. Open state is therefore bounded by 2 records per operator whatever ids are signaled.
- The first signal for an id creates its record and opens its window: not locked in by
  `first_signal_height + upgrade_signal_window_blocks`, it fails and the record is removed at that
  epoch end, so a later signal opens a new window. A signal for a locked-in or active upgrade is
  always valid (late signal, §3.4).
- The output is never spendable and is not added to the UTXO set.
- Relay: nodes and the lightserver exempt it from the minimum relay fee, the full-mempool fee rate
  and hashcash; a stamped one is invalid. Spam stays bounded because only an active validator key can
  make a valid one, the mempool holds at most one per (validator, upgrade), and drops it once it
  expired or is no longer admissible.
- A node whose binary implements the upgrade signals by itself, after each finalized height, from the
  upgrade's `signal_start` on, while its signal is admissible (so it signals again after a failed
  window), with an expiry one epoch ahead (opt out with `--no-upgrade-signal`). Upgrading the binary
  is the vote. `finalis-cli upgrade-signal` sends the same transaction by hand.

Stored in state as `UPG:<id> -> {state, first_signal_height, lock_in_height, activation_height, signalers}` and included
in the state commitment, so light clients can prove the schedule.

A validator's own state changes only through an on-chain transaction. That makes the signal
deterministic and auditable without changing the vote or certificate formats.

### 3.3 Lock-in and activation

States: `DEFINED → SIGNALING → LOCKED_IN → ACTIVE`, or `FAILED` (record removed) once the window
passes.

Evaluated at each epoch end L, on finalized state:

- **Operator threshold:** signalers ≥ ⌈⅔ × active operators⌉ (one operator, one vote, as in
  committee selection today).
- **Committee threshold:** the committee for L+1, derived at that same boundary, has at least a
  quorum of signalers.

If both hold, the upgrade is `LOCKED_IN` at L and becomes active at the start of epoch A = L+2.

**Re-check before activation (decision 8a).** At the end of L+1, before committee(A) is derived, the
operator threshold is evaluated again over the operators active at A. If signalers have fallen below
it (operators left or were removed), the record is removed: the upgrade does not activate, the old
rules continue, nodes without the upgrade stop reporting `upgrade_required`, and a later signal opens
a new window (`cancel_unsupported_upgrade_activations`).

This gives activation the two things the 4800 flag day lacked:

- The parent committee for the first new-rules block, committee(L+1), has a ready quorum, so time
  signatures are available.
- Committee(A) is derived at the end of L+1 from **signalers only** (§3.4), so its whole membership
  is ready.

### 3.4 Late validators: excluded, not halting

From the derivation of committee(A) on, an operator that has not signaled an ACTIVE upgrade cannot
be selected for a committee:

- It earns nothing: no committee seat, no settlement share. This is the tester's "skipped on
  earning", and it falls out of existing committee selection with no new penalty code.
- It is not slashed, its bond is untouched, and it can still exit.
- It upgrades → its node submits the signal → it is eligible from the next derived committee.

Without this rule every later committee could again draw more than ⅓ laggards and stop the chain.

### 3.4.1 Required changes to checkpoint derivation

Confirmed against [CHECKPOINT_DERIVATION_SPEC](CHECKPOINT_DERIVATION_SPEC.md) §3–4: `CP[E+1]` is
derived from finalized state at `epoch_end_height(E)`, so committee(L+1) is known when lock-in is
evaluated at the end of L. Derivation consumes a closed input list, so:

- `InputState(E)` gains `upgrade_state_at_H` (the `UPG:` rows at H).
- Candidate filtering: from the activation epoch on, an operator that has not signaled every ACTIVE
  upgrade is not a candidate. This applies in NORMAL and FALLBACK mode.
- Emergency prior-committee recovery (§11.1) also skips such operators. Otherwise an emergency
  after activation could rebuild the committee from pre-activation members.
- Lock-in also requires signalers ≥ the committee's minimum eligible operator count, so excluding
  non-signalers cannot leave derivation without enough candidates.

### 3.4.2 No signaler left (decision 8b)

After activation the record stays ACTIVE: blocks under the new rules exist, so there is no way back.
If a derivation finds no signaler to seat, not as a candidate, not by emergency recovery and not by
the A2 step (every signaler exited), it derives by the rule without the upgrade filter instead of
failing closed. A halt there would be permanent, because no block could include a late signal. The
seated non-signalers sign once they run the new binary, which signals in its first block; from the
next derivation on the filter seats only signalers again. This is the one case where a committee
seat may belong to a non-signaler (formal/signaled_activation.tla, `lastResort`). The checkpoint is
the one the old rule derives, so nodes agree on it.

### 3.5 Handshake

`consensus_rules_fingerprint` becomes a function of the rules **active at the local finalized
tip**, plus the binary's known upgrade ids advertised separately (`upg=<id,...>`):

- Before activation, old and new binaries share the same active rules, so they connect and keep
  one network.
- After activation, the fingerprints differ and peers disconnect, as today. The point-1 diagnostic
  (`halt_reason=other_consensus_rules`) already reports this.
- The signal rules themselves are in the fingerprint from `upgrade_signal_activation_height` on
  (that height and `upgrade_signal_window_blocks`), so the release that sets the height can be
  installed early without splitting the network, and at the height releases without signals drop
  out instead of receiving blocks they reject.
- A peer is checked against the rules at **its own** tip (`start_height` in VERSION,
  `peer_consensus_rules_fingerprint_acceptable`): a peer below the local tip must show exactly the
  fingerprint the local history gives its height, a peer above it one this binary can reach (its
  active upgrades, any of its known upgrades, signal rules on). Without this, a node below an
  activation (syncing from genesis, back from downtime) is refused by every peer above it and never
  syncs past it (found 2026-11-12, `test_cluster_fresh_node_syncs_past_an_active_upgrade`). The
  fingerprint only filters peers; blocks are validated regardless.

### 3.6 Old binaries

Old binaries cannot know a future upgrade's rules, but they can parse `UpgradeSignal` and `UPG:`
state if the format ships before the first upgrade, at mainnet genesis. An old node that sees an
unknown upgrade reach `LOCKED_IN`:

- logs `UPGRADE REQUIRED name=<id> activates_at=<h>`, repeated each summary;
- reports `halt_reason=upgrade_required` with the activation height in `get_status`;
- stops signing at `activation_height`, so it cannot help finalize a fork. It cannot anyway: it is
  outside committee(A).

## 4. Safety and liveness

- **Safety.** It does not change. Activation is a deterministic function of finalized state, so all
  honest nodes switch at the same height. A node that does not switch is outside the committees that
  finalize new-rules blocks.
- **Liveness.** It is guaranteed at the switch as long as the signalers stay online, since every
  committee seat at and after A belongs to a signaler. Signalers going offline later is the same
  risk as any offline validator today.
- **The upgrade never gets enough support.** It ends `FAILED` at its window's end and the chain
  never stopped. A new release can redefine it with new heights.
- **Signal then downgrade.** That validator is offline for the new rules, the same as an offline
  validator.

## 5. Parameters (proposed)

| Parameter | Mainnet | Testnet |
|---|---|---|
| Operator threshold | ⌈⅔⌉ of active operators | same |
| Committee threshold | quorum of committee(L+1) | same |
| Activation delay | 2 epochs after lock-in | same |
| Signal window (`upgrade_signal_window_blocks`, from the first signal) | 14 400 blocks (~30 days at 180 s) | 1 440 (~3 days) |
| Open signals per operator (`kMaxOpenUpgradeSignalsPerOperator`) | 2 | same |

## 6. Rollout

- **Mainnet:** in the launch binary, the `UpgradeSignal` kind, `UPG:` state, eligibility rule and
  height-aware fingerprint, with an empty upgrade table. Every post-launch consensus change then
  uses it.
- **Testnet-3:** one last flag day to add the mechanism, or ship it with a testnet-4 reset.
- Existing constant activation heights stay as they are (history replay depends on them; see
  INVARIANTS D10).

## 7. Tests and verification

- Unit tests: state machine (lock-in only when both thresholds hold; FAILED at timeout; one signal
  per operator; invalid outside the window).
- Integration: a 4-node cluster where 3 upgrade and 1 does not → activates, the chain does not stop,
  and the laggard gets no committee seat until it signals. Also 2 of 4 → never activates, the chain
  keeps running, FAILED at timeout.
- Replay from genesis reproduces the same activation height.
- Chaos scenario: a laggard holding exactly ⅓ of a committee.
- TLA+: small model of lock-in → activation, checking "no committee at or after A contains a
  non-signaler" and "no height finalizes under two rule sets".
- `docs/INVARIANTS.md` entry.

## 8. Decisions

1. **Signal carrier — APPROVED: on-chain tx.** An on-chain `UpgradeSignal` tx (recommended; no change to vote or certificate
   formats), or a bit in finality votes (no fee, but it changes the signed message and the
   certificate format).
2. **Thresholds — APPROVED: ⅔ of operators plus a ready committee quorum.** ⅔ of operators plus a ready quorum in the next committee (recommended), or a
   higher operator threshold such as 90% (safer for the ecosystem, but easier for a few idle
   operators to block).
3. **Laggard rule — APPROVED: excluded until they signal.** Excluded from committees until they signal (recommended; needed for
   liveness), or kept and risk a stop.
4. **Signal window — APPROVED: 30 days mainnet, 3 days testnet.**
5. **Testnet rollout — OPEN.** A flag day on testnet-3, or testnet-4?
6. **Interaction with open finality.** If finality moves to "everyone votes" with BLS aggregates,
   the committee threshold becomes "⅔ of voting weight is ready" and the laggard rule becomes
   "excluded from the voter set". The mechanism stays the same, so the two designs can proceed
   independently.
7. **Fee source — DECIDED 2026-11-11: no fee.** The signal is a transaction without inputs (§3.2), so
   the node signals with its validator key and nobody funds anything. Rejected: a fee from the
   validator key's address (operators must fund it), the funding keystore on the validator host (more
   key material there), a signal inside block proposals (block format change; validators that never
   propose could not signal).
8. **Support lost, or no signaler left — DECIDED 2026-11-11: liveness and determinism first.**
   a) Before activation: support is checked again at the last epoch end; without it the upgrade
   does not proceed (§3.3). b) After activation: with no signaler left, the committee is derived
   by the old rule rather than halting (§3.4.2).

## 9. Installing releases: updater and release signing

The on-chain mechanism decides **when** rules switch. This section covers **what code** nodes run.
Rule: no node runs code that one person or one compromised account could produce alone.

### 9.1 Release integrity

1. Reviewed source: protected `main`, a required review, signed tags, CI from scratch with pinned
   dependencies.
2. Reproducible builds: independent builders build the tag and sign the resulting hashes. A release
   is valid only when k-of-n builders report the same hash.
3. Release manifest (`version`, sha256 per artifact, Docker image digests, rules fingerprint,
   upgrade ids), signed by k-of-n maintainer keys on hardware tokens, never stored on GitHub or CI.

Today there is one maintainer and one builder, so items 2 and 3 start at 1-of-1. That is why
auto-install stays off (9.3).

Implemented: the manifest (`src/common/release_manifest.hpp`, canonical text), signatures in
`manifest.sig`, and the operator's trust policy `/etc/finalis/release-trust.txt` (`threshold` and
`key` lines). The format is m-of-n from the start, so more maintainers only change the policy.

### 9.2 `finalis-updater`

- A separate process (systemd timer, scheduled task, or a sidecar container). The node runs
  unprivileged and cannot write its own binaries.
- Install method recorded at install time in `/etc/finalis/install.json` (`source`, `tarball`,
  `deb`, `docker`, `windows`), not guessed.
- Verification before install: manifest signatures, artifact hash, or for Docker `cosign verify`
  of the pinned digest (never `:latest`); for source builds, `git tag -v` and a binary hash
  matching the manifest.
- Install into a new versioned directory, back up the DB, switch a symlink, and restart after a
  random delay derived from the node key (hours, not seconds). Health check: if the node does not
  follow the tip within N minutes, switch back. Safe before activation, because both versions run
  the same rules. Never roll back below an ACTIVE upgrade.

### 9.3 Modes

`--auto-update=off|notify|install`, default `notify`: verify and tell the operator, install nothing.
`install` additionally requires the on-chain early-adopter gate: at least ⅓ of operators run this
exact manifest (`UpgradeSignal` carries the manifest hash). `install` is not recommended until at
least 3 independent builders sign releases.

## 10. Implementation steps

1. DONE: `consensus/upgrade_activation`: definitions, state machine, threshold evaluation as pure
   functions plus unit tests. No wiring.
2. DONE: `SCUPGSIG` output (2a: codec, stateless validation, activation height; 2b: stateful
   admission in derivation, mempool and lightserver, `upgrade_records` in state, commitment once
   non-empty, `UPG:` rows, snapshot). The known-upgrade table is empty, so nothing changes yet.
   2c (A1 fix, 2026-11-11): admission and state no longer read the binary's table; any id is
   admissible up to 2 open signals per operator, and the window runs from the first signal
   (`upgrade_signal_window_blocks`).
3. DONE: lock-in evaluation at epoch end in canonical derivation, after committee(L+1) is derived
   (`advance_upgrade_records_at_epoch_end`); `canonical_upgrade_active(state, id, h)`. States move only
   at epoch ends, so a record created by the first signal stays `DEFINED` until the next one. The
   minimum-eligible condition of §3.4.1 applies when committee(L+1) derived NORMAL; in FALLBACK the
   operator threshold alone keeps the candidate set non-empty.
4. DONE: candidate filtering and emergency-recovery skip (§3.4.1); CHECKPOINT_DERIVATION_SPEC §6.4.
   Excluded operators are also left out of `qualified_depth`, the eligible-operator count and the
   empty-active-set escape, so they cannot steer mode or committee size. Availability state does
   not depend on committees or upgrade records, so a late upgrader's score is affected only by the
   time its old binary could not follow the chain; after its signal the next checkpoint is the one
   an on-time signal gives (test above).
5. DONE: height-aware rules fingerprint (`consensus_rules_fingerprint` covers the upgrades active at
   the next height that the binary implements; with none it is unchanged, so releases without the
   mechanism keep connecting), `upg=` handshake tag (the binary's table, diagnostics), and for a
   locked-in upgrade the binary does not implement: `UPGRADE REQUIRED name=<id> activates_at=<h>`
   every summary, `halt_reason=upgrade_required` and `quorum.upgrade_required` in `get_status` from
   the activation height, and no proposal, vote or timeout vote from that height (the node's abstain
   gate). The lightserver relay handshake uses the same fingerprint. 2026-11-12: the signal rules
   enter the fingerprint from `upgrade_signal_activation_height` on (below it the fingerprint is
   v2.2.14's), and peers are checked at their own height (§3.5).
6. DONE: fee-free signal (§3.2, decision 7): no inputs, signed expiry at most one epoch ahead, no
   UTXO; relay-fee and hashcash exemption with one pending signal per (validator, upgrade); node
   auto-signal after each finalized height (`--no-upgrade-signal`); lightserver `get_upgrades`, CLI
   `upgrade-status` and `upgrade-signal` (validator key only).
7. PARTLY DONE (2026-11-12): TLA+ model and INVARIANTS U1-U7 are in. 4-node cluster tests: 3 of 4
   upgraded → auto-signal, lock-in, activation, laggard `upgrade_required`, abstaining and unseated
   from A on, chain keeps finalizing, laggard seated again after it installs the release
   (`test_cluster_three_of_four_upgrade_activates_excludes_laggard_and_readmits_it`); 2 of 4 → window
   closes without lock-in, chain keeps finalizing, nobody reports `upgrade_required`
   (`test_cluster_two_of_four_upgrade_window_fails_and_chain_continues`); laggards holding exactly ⅓
   of a 6-seat committee (4 ready seats, quorum 5) → no lock-in, chain keeps finalizing; a fifth
   upgrader → activation and the last laggard unseated
   (`test_cluster_laggards_holding_one_third_block_lock_in_until_one_more_upgrades`). Chaos:
   `scripts/chaos_devnet.py --upgrade NAME --laggards K [--expect-activation yes|no]` (chaos build,
   `FINALIS_CHAOS_KNOWN_UPGRADE`) runs activation under crashes, partitions and latency, checks every
   committee from A for a laggard, then installs the release on the laggards and needs them back on
   the tip with their signals recorded.
8. PARTLY DONE (2026-11-11): release manifests signed with Ed25519 release keys, checked against an
   operator trust policy (`threshold` plus keys; 1-of-1, the maintainer, for now; raising it is a
   policy edit), `finalis-cli release-keygen|release-manifest|release-sign`, `finalis-updater
   verify|check` (notify mode, nothing installed). [docs/operations/UPDATER.md](../operations/UPDATER.md).
   Open: install mode (§9.2), the early-adopter gate (§9.3), reproducible builds (§9.1).
