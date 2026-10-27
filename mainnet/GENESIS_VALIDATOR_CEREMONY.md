# Genesis Validator Ceremony (v2)

Genesis validators earn all early emission (rewards come only from validation), so who gets a
genesis slot is the launch's fairness question. v1 selected the first `N` public keys in
lexicographic order; anyone could grind keys with small prefixes and take every slot. v2 ranks keys
by a value nobody knows until submissions are closed.

## Announcement (before submissions open)

Publish, and do not change afterwards:

- `N`, the number of genesis validators, and the submission cutoff (UTC).
- The beacon: a Bitcoin block height `H` that will be mined after the cutoff (for example, the
  cutoff height plus 6). Its block hash is the randomness. Nobody, including the maintainer, can
  choose it in advance.
- The maintainer's own key(s) and the cap below.

## Submission

- One Ed25519 public key (32-byte hex) per operator, with a contact or public handle, posted
  publicly before the cutoff (for example, in a pinned GitHub Discussion). Submissions are public
  and timestamped.
- Each submission is signed by the submitted key over the announcement text, which proves control
  of the key.
- Each submission also carries the operator's BLS time-signature key and its proof of possession,
  printed by `finalis-cli validator_bls --file validator.json` (derived from the same keystore;
  public output only). Genesis rejects a validator without a valid, distinct BLS key.

## Deterministic selection

1. Collect valid, unique, signed submissions made before the cutoff.
2. When block `H` is mined, take its hash `B` (as displayed by block explorers, hex).
3. Score each key: `score = SHA-256(B || pubkey)`. Sort by score ascending, ties by pubkey.
4. Select the first `N`. `initial_active_set_size = N`, all ACTIVE at height 0.
5. Maintainer cap: at most `f = floor((N - 1) / 3)` selected keys may be the maintainer's. If more
   score in, the extra ones are skipped and the next keys by score take their places. The other
   `N - f` validators then form a quorum without the maintainer.

Anyone can recompute the selection from the public submissions and `B`.

## What this does not solve

- Sybil: one person submitting many keys gets slots in proportion to their keys. Without identity,
  a ceremony cannot prevent that; publishing every submission with its handle lets the community
  see and object before genesis is frozen.
- The beacon only removes grinding against the ranking. A miner of block `H` could withhold a block
  to change `B`, at the cost of a block reward. That is far beyond the value of a genesis slot here.

## Publication workflow

1. Publish the candidate list, `B`, every score and the selected set.
2. Publish final `mainnet/genesis.json`.
3. Publish canonical `mainnet/genesis.bin` and `genesis_hash`.
4. Regenerate `src/genesis/embedded_mainnet.cpp` from `mainnet/genesis.bin`.
5. Independent operators reproduce the selection and the hash with the CLI verification command.

Critical launch check:

- each bootstrap validator must confirm its local `validator.json`
  `pubkey_hex` is present in the published genesis validator set
- if the local pubkey is absent, that node cannot produce block `1`
