# Finalis Mainnet Plan

This file is the short launch sequence. The operational go/no-go validation now
lives in [THREAT_MODEL_AND_LAUNCH_CHECKLIST.md](THREAT_MODEL_AND_LAUNCH_CHECKLIST.md).

## Principles

- deterministic published genesis artifacts
- no hidden consensus backdoors
- finalized-state-only settlement semantics for clients and exchanges
- no bootstrap launch while `chain_id_ok=false` anywhere in the trusted path

## Milestones

- [ ] Freeze `mainnet/genesis.json` and publish the intended `genesis_hash`.
- [ ] Rebuild `mainnet/genesis.bin` and regenerate `src/genesis/embedded_mainnet.cpp`.
- [ ] Rebuild release binaries from the same canonical genesis artifacts.
- [ ] Wipe old chain DBs before first startup on the fresh-genesis network.
- [ ] Run validator ceremony and publish the initial validator list.
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
