# LIGHT_CLIENT

Status: implemented. Code: [src/consensus/light_client.hpp](../../src/consensus/light_client.hpp),
[src/wallet/light_verifier.hpp](../../src/wallet/light_verifier.hpp),
[src/wallet/verified_balance.hpp](../../src/wallet/verified_balance.hpp).

## 1. Problem

A wallet without its own node asks a lightserver for its coins and believes the answer. A dishonest
server can show coins that do not exist (a merchant ships goods for a payment that never happened) or
hide coins that do. This document defines how a client checks lightserver answers against validator
signatures instead, so that:

- no server can make the client accept a coin that is not in the finalized UTXO set;
- one honest server among those the client asks is enough to reveal every coin.

## 2. Trust anchor

The client trusts only the genesis document compiled into its binary
(`genesis::embedded_genesis_for`). From it, it derives the epoch-1 committee checkpoint exactly as
every node does (`build_genesis_canonical_state` with `network_canonical_derivation_config`, the
network's parameters without test overrides). Mainnet's embedded genesis names no validators until
launch (it then names the bootstrap validator); until then mainnet clients report "not verified".

## 3. What is signed

- A finality certificate is a quorum (`floor(2N/3) + 1`) of precommits from the committee of the
  height's epoch, over `vote_signing_message(chain_domain, height, round, transition_id)`. The chain
  domain binds network id and genesis hash, so certificates of another chain never verify.
- The transition signs `next_state_root` (the UTXO commitment tree root) and
  `next_state_commitment = sha256d(post_state_preimage)`.
- The preimage has a fixed prefix (`kPostStatePreimage*Offset`):
  `tag(16) height(8) frontier(8) utxo_root(32) validator_root(32) randomness(32) reward_root(32)
  reserve(8) checkpoint_root(32) …`.
- `checkpoint_root` is a sparse Merkle tree of committee checkpoints: key
  `sha256("SC-CHK" || u64le(epoch_start))`, value `checkpoint_commitment_value(checkpoint)`.
- At an epoch's last height `H`, the state already holds the checkpoint of the next epoch `H + 1`.

## 4. Committee handoff

`CommitteeHandoff` proves the checkpoint of epoch `H + 1` to a client that trusts the committee of
the epoch ending at `H`:

| Field | Content |
|---|---|
| `transition` | serialized finalized transition at `H` |
| `certificate` | its finality certificate |
| `post_state_preimage` | preimage of `transition.next_state_commitment` |
| `next_checkpoint` | `checkpoint_commitment_value` of epoch `H + 1` |
| `next_checkpoint_proof` | its membership proof under `checkpoint_root` |

Serialization: `u8 version(1)`, then each field as `varbytes`; the certificate as
`FinalityCertificate::serialize`, the proof in the compact form below.

Verification (`verify_committee_handoff`):

1. `H + 1` starts an epoch, and `H` lies in the trusted checkpoint's epoch.
2. The certificate is for this transition and carries a quorum of the trusted committee
   (`checkpoint_committee_for_round`; the committee comes from the trusted checkpoint, never from
   the certificate).
3. `sha256d(post_state_preimage) == transition.next_state_commitment`.
4. The proof places `next_checkpoint` under the preimage's `checkpoint_root`, at the key of `H + 1`.
5. `next_checkpoint` parses, is for `H + 1`, and names at least one member.

Only the state at `H` holds everything the preimage covers, so a node builds the handoff when it
finalizes `H` (`build_committee_handoff`) and stores it under `LCH:<u64le(H + 1)>`. A node started on
a database without them rebuilds the missing ones once by replay (`backfill_committee_handoffs`).
Snapshots carry them. Handoffs are self-verifying, so their source does not matter.

Compact SMT proof: a 32-byte bitmap (bit `i` set: `siblings[i]` is not the empty-subtree hash of
height `i`), followed by the set siblings, leaf to root.

## 5. Lightserver RPCs

- `get_committee_handoffs {from_epoch_start, limit≤64}` →
  `{epoch_blocks, handoffs:[{next_epoch_start, handoff_hex}]}`: consecutive handoffs after
  `from_epoch_start`, stopping at the first missing one.
- `get_utxo_proofs {outpoints:[{txid, vout}] (≤256)}` →
  `{height, transition_hex, certificate_hex, proofs:[{txid, vout, value_hex|null, proof_hex}]}`:
  all proofs at the finalized tip, with that tip's transition and certificate. `value_hex` is the
  leaf (`utxo_commitment_value`); `null` with a non-membership proof means absent.

## 6. Client rules

`LightVerifier` keeps the last 16 proven checkpoints and saves them locally, so it resumes instead
of walking from genesis. It never steps back, and it never accepts saved state from a server.

To check coins, the client:

1. Gets each coin's expected leaf: for a transparent coin from its value and script, for a
   confidential coin from its transaction's output. Any server's copy of the transaction will do;
   the proof decides whether it is real.
2. Asks a server for `get_utxo_proofs` and advances its committees to the returned height.
3. Verifies the certificate against the proven committee, then each proof against `next_state_root`.
4. Classifies each coin: `Unspent` (the leaf matches), `Spent` (provably absent) or `Different` (a
   different leaf: the reporting server misdescribed it).

Any invalid handoff, certificate or proof means the server lied or is broken. The client tries the
next server.

Combining servers (`verify_claimed_balance`):

- The client asks every configured server and checks the union of all coins they report. A coin
  counts only when proven `Unspent`.
- It flags a server that sent an invalid proof or described a coin differently.
- At the proven height it also flags a server that left out a proven coin or listed an absent one.
  A server behind that height is not flagged.

## 7. Limits

- A server can still refuse to answer or lag. The client then shows the balance as unverified with
  the reason, and never as verified.
- Hiding is defeated only when at least one server the client asks is honest and current.
- Transaction history and `get_tx_status` are not proven; the verified quantity is the coin set. A
  payment is credited when its output is a proven `Unspent` coin.
- Confidential payments are discovered by scanning up to two servers. A coin found in one refresh is
  proven on the next; until then the wallet shows it as not yet verified.
