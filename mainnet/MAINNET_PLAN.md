# Finalis Mainnet Plan

This file is the short launch sequence. The operational go/no-go validation now
lives in [THREAT_MODEL_AND_LAUNCH_CHECKLIST.md](THREAT_MODEL_AND_LAUNCH_CHECKLIST.md).

## Principles

- deterministic published genesis artifacts
- no hidden consensus backdoors
- finalized-state-only settlement semantics for clients and exchanges
- no bootstrap launch while `chain_id_ok=false` anywhere in the trusted path

## Launch model

Mainnet starts the way the testnet did: one bootstrap validator, run by the maintainer, and
everyone else joins through the ordinary on-chain registration. There is no genesis validator set
besides it, no ceremony, no reserved or promised slots and no premine.

- **Genesis:** `mainnet/genesis.json` names exactly one validator, the maintainer's published
  bootstrap key (Ed25519 key, BLS key and proof of possession).
- **Joining:** anyone registers a validator with `finalis-cli validator-register`, bonding FLS like
  every later validator. FLS exist only as block rewards. Joins beyond the protocol's limit of 64
  per 1,000 blocks are not lost: they wait in a public queue and are admitted oldest first.
- **Faucet:** it pays bonds out of the bootstrap validator's rewards, on these rules only:
  - **The first 128 grants, then never again.** A grant is the minimum bond at that moment plus
    1 FLS for fees.
  - **One grant per Discord account and per address,** for a validator key that is not yet
    registered.
  - **In queue order:** requests are served strictly in the order they were made, as the faucet earns
    the coins; the queue and every payment are public.
  - **After the 128th grant,** validators buy FLS or receive them from someone else; the protocol
    treats every bond the same, wherever its coins came from.
- **What this means while it is the only validator:** the bootstrap key alone finalizes every block,
  and the bootstrap validator earns all emission until others join. Both are public, visible on the
  explorer, and end as validators join.
- **Becoming independent of the maintainer:** quorum is `floor(2n/3) + 1` validators. With 2
  validators the maintainer can no longer finalize alone; from 4 independent validators the chain
  keeps finalizing while the bootstrap node is down; from `3f + 1` the maintainer holds no more than
  `f`. The maintainer runs one validator, never more, and may unbond it once the others carry the
  chain: the network then runs without its creator.

## Milestones

- [ ] Pass the consensus readiness gate (section 0 of the checklist): external BFT review, chaos
      campaign and fuzzing on the release binaries. Until then the network is a testnet.
- [ ] Freeze `mainnet/genesis.json` and publish the intended `genesis_hash`.
- [ ] Rebuild `mainnet/genesis.bin` and regenerate `src/genesis/embedded_mainnet.cpp`.
- [ ] Rebuild release binaries from the same canonical genesis artifacts.
- [ ] Publish the bootstrap validator's key (Ed25519, BLS key and proof) and the faucet rules.
- [ ] Start bootstrap validator and verify:
      - `chain_id_ok=true`
      - `network_name="mainnet"`
      - local validator pubkey is actually present in the intended genesis validator set
      - intended local operator is recognized
- [ ] Bring up monitored lightserver endpoints and verify finalized identity
      agreement.
- [ ] Validate desktop wallet, mobile wallet, explorer, and exchange sanity
      checks against the live RPC contract.
- [ ] Verify confidential-capable surfaces do not invent transparent amount or
      address semantics on public explorer/RPC paths.
- [ ] Publish operator-facing and exchange-facing connection details.
- [ ] Declare bootstrap launch healthy only after the checklist passes end to
      end.
