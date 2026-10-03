# Recommended Pre-Genesis Roadmap

Source: genesis pre-launch static audit (2026-10-03).

**Process:** items are resolved one at a time, in order. Each item is marked `[x]`
only after its change is applied **and** the project builds clean. An item that is
applied but not yet build-verified is marked `[ ]` with status `applied — pending build`.

---

## A. Network & deployment blockers

- [ ] **1. Commit real bootstrap seeds into the binary**
  - `src/common/network.cpp`: `.default_seeds = {"85.217.171.168:19440", "64.23.244.126:19440"}`
  - Status: **applied — pending build verification**
  - Follow-ups:
    - Reconcile `mainnet/SEEDS.md` (still lists `212.58.103.170`, `seed1.gotdns.ch`) with `SEEDS.json`.
    - Move to DNS seeds operated by ≥2 independent organizations before public launch.
    - Default seeds are used whenever `--seeds` is empty (even with `--no-dns-seeds`), so
      in-process tests and the `docker-compose.yml` devnet will now also dial these hosts
      unless they pass `--seeds`/`--disable-p2p`.

- [ ] **2. Make the Docker image boot**
  - `Dockerfile` CMD: added `--allow-unsafe-genesis-override` (required by `parse_args` when `--genesis` is set).
  - Status: **applied — pending build verification**
  - Follow-ups:
    - Alternative: drop `--genesis` entirely; the embedded genesis has the same hash
      (`eaae655a…b78a`) and avoids the "unsafe" flag.
    - Runtime image does not contain `finalis-lightserver`, yet CMD passes `--with-lightserver`.

## B. Consensus parameter correctness

- [ ] **3. Decide activation heights and bond figures**
  - 3a. Activation heights — Status: **applied — pending build verification**
    - `src/common/network.cpp`: `deferred_exit`, `bootstrap_penalty_exit_protection`,
      `empty_active_set_epoch_escape` changed from `10017 / 10145 / 10145` to `0`.
    - All three predicates use `height >= activation`, so `0` means active from genesis. The
      deferred-exit startup migration hook (`maybe_reactivate_single_exiting_validator_for_startup_migration`)
      becomes a no-op, which is intended for a fresh chain.
    - ⚠ **Consensus rule change without a genesis change.** `genesis.bin` and its hash are unchanged,
      so nodes with the old heights still pass the handshake with nodes that have the new ones,
      but the two can diverge before height 10145. Any network already running on this genesis
      (the seed hosts, `snapshot.bin`) must be wiped and restarted with the new binary, or genesis regenerated.
  - 3b. Bond figures — Status: **applied — pending build verification**
    - Finding: the "min exceeds max → lock-up" risk from the audit **cannot occur**.
      - Every max-bond consumer already clamps upward: `max(validator_bond_max_amount, min_bond)`
        (`canonical_derivation.cpp:1468`, `node.cpp` `effective_validator_bond_max_for_height`,
        `lightserver/server.cpp:2586,3068`).
      - The adaptive min (`validator_min_bond_units`) = `clamp(1000 FLS × sqrt(16 / active), 1000, ceiling)`,
        so it peaks at 4,000 FLS. The old 10,000 FLS ceiling was unreachable.
    - Change (`src/common/network.cpp`) — no change to current consensus outcomes:
      - `min_bond_ceiling` set from 10,000 FLS to `validator_bond_max_amount` (5,000 FLS).
      - Named constants plus `static_assert`s added: floor ≤ ceiling, ceiling ≤ bond max, and the
        adaptive peak ≤ ceiling. The build now fails if the economics are retuned into an inconsistent state.
    - Not changed: `BOND_AMOUNT` (50 FLS). It is the exact required `SCVALREG` output value
      (`utxo/validate.cpp:142`), the "no override" sentinel in `canonical_derivation.cpp:403`, and the
      bond used for legacy DB records. The effective minimum is already `max(50, adaptive ≥ 1,000)`.
      Retiring it is a separate consensus change.

- [ ] **4. Lock consensus params against CLI override on mainnet**
  - Status: **applied — pending build verification**
  - `src/node/node.cpp` `parse_args`: when `cfg.network.name == "mainnet"`, these flags are rejected
    with an error message and `parse_args` returns `nullopt`. That is the existing error path:
    `main` prints usage and exits 1. Throwing was avoided because `main` has no try/catch.
    - `--max-committee`, `--validator-min-bond`, `--validator-warmup-blocks`, `--validator-cooldown-blocks`,
      `--validator-join-limit-window-blocks`, `--validator-join-limit-max-new`, `--liveness-window-blocks`,
      `--miss-rate-suspend-threshold-percent`, `--miss-rate-exit-threshold-percent`,
      `--suspend-duration-blocks`, `--deferred-exit-activation-height`, `--deferred-exit-activation-epoch-start`
  - Not locked: `--round-timeout-ms`, `--min-block-interval-ms`. These only set local
    proposer/round pacing and don't affect block validity.
  - Follow-ups:
    - `scripts/start.sh:821-838` auto-injects `--deferred-exit-activation-height` when
      `SYNC_TURBO_MODE=extreme` and `AUTO_DEFERRED_EXIT_ACTIVATION_EXTREME=1`; nodes launched that way
      now fail to start. Remove that block.
    - `finalis-lightserver` has its own `--max-committee` flag; review whether it needs the same lock.
    - Override paths in `Node::init` (lines ~3122-3143) stay for tests that set `NodeConfig` directly.

## C. Node boot robustness

- [ ] **5. Harden `parse_args`**
  - Status: **partially applied — pending build verification**
  - Done (`src/node/node.cpp`):
    - The body moved to `parse_args_unchecked`. The public `parse_args` catches `std::invalid_argument` /
      `std::out_of_range`, prints `error: invalid numeric value for <flag>`, and returns `nullopt`.
      `main` then prints usage and exits 1 instead of hitting `std::terminate`.
    - `--port` / `--lightserver-port` use `parse_port_arg`, which rejects trailing characters and
      values outside `[1, 65535]`. `--port abc`, `--port 70000` and `--port 80x` are all rejected.
  - Remaining:
    - Other `static_cast<uint32_t>(std::stoul(...))` flags still truncate values above 2^32 silently
      (timeouts, hashcash bits, and similar).
    - Install SIGINT/SIGTERM handlers before `init()` (`apps/finalis-node/main.cpp`).
    - The same pattern exists in `finalis-lightserver`, `finalis-explorer` and `finalis-cli` argument parsing.

## D. State bootstrap safety

- [ ] **6. Snapshot import safety**
  - `scripts/start.sh`: default `AUTO_FAST_SYNC=0`.
  - `import_snapshot_bundle`: verify manifest genesis hash against the embedded `MAINNET_GENESIS_HASH`.
  - Remove the tracked `snapshot.bin` from the repo.

## E. Public interface

- [ ] **7. Fix dead SDK methods**
  - Status: **applied — pending SDK typecheck / vitest run**
  - Removed from `LightServerClient.ts`: `getHeaders`, `getHeaderRange`, `getBlock`. They called
    `get_headers` / `get_header_range` / `get_block`, which the lightserver does not implement.
    The `HeaderEntry` type was removed, along with the duplicate `FinalitySig` in `src/types/index.ts`
    (the canonical one is in `src/proofs/finality.ts`; both were re-exported via `export *`).
  - All 9 RPC methods the SDK still calls exist in `src/lightserver/server.cpp`:
    `get_status`, `get_tip`, `get_tx`, `get_utxos`, `get_committee`, `get_roots`,
    `get_utxo_proof`, `get_validator_proof`, `broadcast_tx`.
  - `FinalisWallet.getBalanceTrustless` depended on `getHeaderRange`, so it was broken at runtime.
    It now **fails closed** with `TRUSTLESS_NOT_SUPPORTED`. It could not simply be pointed at a renamed method:
    - The SDK's `verifyFinalityProof` checks Ed25519 signatures over a raw 32-byte block hash.
      Validators sign `vote_signing_message(height, round, transition_id)` (`src/utxo/validate.hpp:79`).
    - `get_finality_certificate` returns no `utxo_root`, and `get_roots` is not bound to the signed transition.
  - `test/lightserver-e2e-tamper.test.ts` was rewritten to assert the fail-closed behavior. SMT and finality
    tamper cases remain covered by `smt-proof.test.ts` and `finality-proof.test.ts`. README method list updated.
  - **Breaking public API change** (SDK `1.0.0`): bump the version or note it in the changelog.
  - Follow-ups to restore trustless balance:
    1. Lightserver: expose a finality-bound `utxo_root`, either in `get_finality_certificate` or via a proof
       that `utxo_root` is committed in the transition.
    2. SDK: port `vote_signing_message` and verify the certificate against it; add test vectors generated from C++.
    3. Publish a lightserver JSON-RPC spec. `openapi/finalis-partner-v1.yaml` covers only explorer REST.
       `/api/v1/audit/auth` is implemented in the explorer but undocumented.

---

## Status summary

| # | Item | Status |
|---|---|---|
| 1 | Bootstrap seeds | applied — pending build |
| 2 | Docker CMD | applied — pending build |
| 3a | Activation heights → 0 | applied — pending build (requires wiping any chain already on this genesis) |
| 3b | Bond ceiling invariant | applied — pending build |
| 4 | Mainnet consensus-flag lock | applied — pending build (`start.sh:821-838` must be removed) |
| 5 | `parse_args` hardening | partial — pending build (u32 truncation, signal ordering, other apps) |
| 6 | Snapshot import safety | **open** |
| 7 | SDK dead methods | applied — pending SDK typecheck/tests |

No item is `[x]` yet: none of the changes have been compiled or tested in this pass.
Verify with `cmake --build build -j`, `ctest --test-dir build --output-on-failure`, and
`npm test` / `npx tsc --noEmit` in `sdk/finalis-wallet-js`.
