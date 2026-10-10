# Reviewing Finalis

A guide for protocol researchers, cryptographers and auditors. It lists what we
claim, where each claim is specified and implemented, and how to test it.
Report findings as described in [SECURITY.md](../SECURITY.md).

Finalis is pre-launch: there is no live chain and no compatibility constraint,
so a finding can still change the protocol itself.

## 1. Claims we want broken

| # | Claim | Spec | Code |
|---|---|---|---|
| C1 | At most one transition finalizes per height, with `f < n/3` Byzantine committee members and an asynchronous network | [spec/TWO_PHASE_FINALITY.md](spec/TWO_PHASE_FINALITY.md) §2–4 | `src/node/node_consensus.cpp`, `src/consensus/canonical_derivation.*` |
| C2 | Progress after GST with an honest leader | [spec/TWO_PHASE_FINALITY.md](spec/TWO_PHASE_FINALITY.md) §4 | same |
| C3 | Confidential transactions cannot create value (commitment balance, range proofs, excess authorization) | [spec/CONFIDENTIAL_UTXO_SPEC.md](spec/CONFIDENTIAL_UTXO_SPEC.md) §3, §4, §7, §15 | `src/crypto/confidential.*`, `src/utxo/validate.*`, `src/consensus/confidential_supply.*` |
| C4 | Confidential outputs hide amount and recipient; one-time keys of distinct receive requests are unlinkable, and the account secrets recover them all | [spec/CONFIDENTIAL_UTXO_SPEC.md](spec/CONFIDENTIAL_UTXO_SPEC.md) §3.2, §15 | `src/wallet/confidential_keys.*`, `src/wallet/confidential_builder.*` |
| C5 | Every honest node derives the same state, committee and rewards from finalized history | [spec/CHECKPOINT_DERIVATION_SPEC.md](spec/CHECKPOINT_DERIVATION_SPEC.md), [COMMITTEE-SELECTION.md](COMMITTEE-SELECTION.md), [ECONOMICS.md](ECONOMICS.md) | `src/consensus/`, `src/storage/` |
| C6 | A remote peer cannot crash a node or isolate honest validators | [ADVERSARIAL_MODEL.md](ADVERSARIAL_MODEL.md) §4.2 | `src/p2p/`, `src/node/node_network.cpp` |

## 2. Reading order

1. [ADVERSARIAL_MODEL.md](ADVERSARIAL_MODEL.md): the attacker we design against.
2. [CONSENSUS.md](CONSENSUS.md), then [spec/TWO_PHASE_FINALITY.md](spec/TWO_PHASE_FINALITY.md).
   §5 maps every rule to the function that implements it.
3. [spec/CONFIDENTIAL_UTXO_SPEC.md](spec/CONFIDENTIAL_UTXO_SPEC.md): encoding (§5),
   validation pipeline (§7), security notes (§15).
4. [CODEBASE_MAP.md](CODEBASE_MAP.md) to find anything else.

Cryptographers can go straight to step 3 and `src/crypto/confidential.cpp`, the
only file that calls secp256k1-zkp.

## 3. Running things

Build and test (about 15 min for the full suite):

```bash
cmake -S . -B build -G Ninja && cmake --build build -j
ctest --test-dir build --output-on-failure
```

Run a subset of the unit tests by name:

```bash
./build/finalis-tests --list
FINALIS_TEST_FILTER=confidential ./build/finalis-tests
```

Formal model of the two-phase finality voting rules (TLA+, needs Java and
`tla2tools.jar`; see [formal/README.md](../formal/README.md) for every config and
what it must show):

```bash
./scripts/run_tlc.sh --spec formal/two_phase_finality_abstract.tla \
  --config formal/two_phase_finality_abstract.cfg
```

Local devnet with Byzantine validators, partitions, crashes and payment
traffic. Every node's finalized transitions are compared, and a fork fails the
run:

```bash
cmake -S . -B build-chaos -G Ninja -DFINALIS_CHAOS_BYZANTINE=ON
cmake --build build-chaos -j
scripts/chaos_devnet.py --nodes 7 --byzantine 2 --build-dir build-chaos \
  --tx-interval 1 --duration 600 --seed 1
```

Output goes to `<workdir>/report.md`.

## 4. Known open items

- The two-phase finality design has not had an external review yet
  ([spec/TWO_PHASE_FINALITY.md](spec/TWO_PHASE_FINALITY.md) §8.5).
- There is no reusable stealth address: receiving is per request (spec §3.2), and a restored
  wallet still needs the txids of received payments (no chain scan yet).
