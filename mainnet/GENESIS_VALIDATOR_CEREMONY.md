# Genesis Validator Ceremony (v1)

## Submission
- Validators submit one Ed25519 public key (32-byte hex).
- Submissions are public and timestamped.

## Deterministic selection
- Collect valid, unique submissions before cutoff.
- Sort pubkeys lexicographically ascending.
- Select first `N` (published in ceremony announcement).
- `initial_active_set_size = N` and all selected validators are ACTIVE at height 0.

## Publication workflow
1. Publish candidate validator list and hashes.
2. Publish final `mainnet/genesis.json`.
3. Publish canonical `mainnet/genesis.bin` and `genesis_hash`.
4. Regenerate `src/genesis/embedded_mainnet.cpp` from `mainnet/genesis.bin`.
5. Independent operators reproduce hash with CLI verification command.

Critical launch check:

- each bootstrap validator must confirm its local `validator.json`
  `pubkey_hex` is present in the published genesis validator set
- if the local pubkey is absent, that node cannot produce block `1`
