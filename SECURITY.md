# Security Policy

## Project status

Finalis is **pre-launch**. Mainnet has not launched, so no live funds are at
risk yet. That is exactly why we want findings now: anything found before
genesis is frozen can be fixed without a hard fork or migration.

## Reporting a vulnerability

Report privately through GitHub:
**[Report a vulnerability](https://github.com/FinalisCore/finalis-core/security/advisories/new)**
(repository *Security* tab → *Report a vulnerability*).

Please do **not** open a public issue, pull request or discussion for anything
that could break consensus safety, inflate supply, forge or replay
authorization, or deanonymize confidential amounts or recipients.

Include what you can of:

- affected component and file(s), commit hash
- impact (what an attacker gains) and required attacker capabilities
  (e.g. number of Byzantine validators, network position)
- reproduction steps, a failing test, or a proof sketch

We aim to acknowledge reports within 3 days and to give an initial assessment
within 10 days. We will credit reporters in the fix commit and release notes
unless you ask us not to.

Non-sensitive bugs (crashes on malformed local config, docs errors, build
problems) can go to normal GitHub issues.

## Scope

Highest priority:

| Area | What we care about | Where |
|---|---|---|
| BFT consensus safety | two conflicting finalized transitions at one height with ≤ f Byzantine validators; lock / proof-of-lock / round rules | [docs/spec/TWO_PHASE_FINALITY.md](docs/spec/TWO_PHASE_FINALITY.md), [formal/](formal/), `src/consensus/`, `src/node/node_consensus.cpp` |
| Confidential transactions | inflation via commitments or range proofs, balance-proof forgery, amount or recipient leakage, stealth-address linkability | [docs/spec/CONFIDENTIAL_UTXO_SPEC.md](docs/spec/CONFIDENTIAL_UTXO_SPEC.md), `src/crypto/confidential.*`, `src/crypto/stealth_address.*`, `src/utxo/validate.*` |
| Transaction and state validation | double spends, signature bypass, non-deterministic validation between nodes, state-root mismatch | `src/utxo/`, `src/consensus/`, `src/storage/` |
| Committee and economics | committee-selection bias, validator-lifecycle bypass, supply cap or reward-settlement errors | [docs/COMMITTEE-SELECTION.md](docs/COMMITTEE-SELECTION.md), [docs/ECONOMICS.md](docs/ECONOMICS.md) |
| P2P | remote crash, memory exhaustion, peer-scoring abuse that isolates honest validators | `src/p2p/`, `src/node/node_network.cpp` |

Also in scope: wallet key handling (`src/wallet/`, `src/crypto/secure_memory.*`)
and the lightserver RPC (`src/lightserver/`).

Out of scope: denial of service that needs more than f Byzantine validators,
attacks requiring a compromised validator key beyond the fault bound, social
engineering, and third-party infrastructure.

## Cryptographic dependencies

- Ed25519 signatures (OpenSSL EVP)
- secp256k1-zkp (Pedersen commitments, generators, range proofs, BIP-340
  Schnorr signatures), pinned in `CMakeLists.txt`
- SHA-256 and RIPEMD-160 via OpenSSL

A finding in how Finalis *uses* these libraries is in scope; a vulnerability in
the library itself should also be reported upstream.

## Reviewer guide

[docs/REVIEWING.md](docs/REVIEWING.md) lists the reading order, the safety
claims we make, and how to run the tests and the Byzantine chaos harness.
