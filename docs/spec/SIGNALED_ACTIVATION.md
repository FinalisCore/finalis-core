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
  signal_start  : height   // signals before this are invalid
  signal_timeout: height   // not locked in by here -> FAILED, never activates
}
```

Rule code keeps both paths behind `upgrade_active(id, height)` instead of
`height >= cfg.network.X_activation_height`. This is the pattern already used for the current
activation heights. Only the source of the height changes, from a constant to chain state.

### 3.2 Readiness signal (on-chain)

Carried as a zero-value `SCUPGSIG` output in an ordinary transaction, like `SCONBREG`: prefix(8) |
validator_pubkey(32) | upgrade_id(32) | sig(64). No new transaction kind. It is accepted from the
network's `upgrade_signal_activation_height` (mainnet 0; testnet-3 set at its flag day), so releases
without the mechanism never see one in a block they validate. Rules (stateless ones in step 2a,
stateful ones in 2b):

- The validator key signs `upgrade_signal_message(chain_domain, upgrade_id, validator_pubkey)`; the operator is the validator's canonical operator id.
- It is valid only if `operator` is an active operator, `upgrade_id` is defined, the height is in
  `[signal_start, signal_timeout)`, and this operator has no earlier signal for this id. One per
  operator per upgrade, so the total is bounded by the operator count.
- The fee is paid like `onboarding-register`, from the operator's funding wallet.
- A node whose binary knows the upgrade submits the signal automatically once it is synced (opt out
  with `--no-upgrade-signal`). Upgrading the binary is the vote.

Stored in state as `UPG:<id> -> {state, signalers, lock_in_epoch, activation_height}` and included
in the state commitment, so light clients can prove the schedule.

A validator's own state changes only through an on-chain transaction. That makes the signal
deterministic and auditable without changing the vote or certificate formats.

### 3.3 Lock-in and activation

States: `DEFINED → SIGNALING → LOCKED_IN → ACTIVE`, or `FAILED` once `signal_timeout` passes.

Evaluated at each epoch end L, on finalized state:

- **Operator threshold:** signalers ≥ ⌈⅔ × active operators⌉ (one operator, one vote, as in
  committee selection today).
- **Committee threshold:** the committee for L+1, derived at that same boundary, has at least a
  quorum of signalers.

If both hold, the upgrade is `LOCKED_IN` at L and becomes active at the start of epoch A = L+2.

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

### 3.5 Handshake

`consensus_rules_fingerprint` becomes a function of the rules **active at the local finalized
tip**, plus the binary's known upgrade ids advertised separately (`upg=<id,...>`):

- Before activation, old and new binaries share the same active rules, so they connect and keep
  one network.
- After activation, the fingerprints differ and peers disconnect, as today. The point-1 diagnostic
  (`halt_reason=other_consensus_rules`) already reports this.

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
- **The upgrade never gets enough support.** It ends `FAILED` at `signal_timeout` and the chain
  never stopped. A new release can redefine it with new heights.
- **Signal then downgrade.** That validator is offline for the new rules, the same as an offline
  validator.

## 5. Parameters (proposed)

| Parameter | Mainnet | Testnet |
|---|---|---|
| Operator threshold | ⌈⅔⌉ of active operators | same |
| Committee threshold | quorum of committee(L+1) | same |
| Activation delay | 2 epochs after lock-in | same |
| Signal window (`signal_timeout − signal_start`) | ~30 days of blocks | ~3 days |

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
5. Height-aware rules fingerprint, `upg=` handshake tag, old-binary `upgrade_required`, `get_status`.
6. Node auto-signal, CLI `upgrade_status`.
7. Integration and chaos tests, TLA+ model, INVARIANTS entry.
8. Updater (notify mode) and release-manifest signing (§9); separate PRs, not consensus code.
