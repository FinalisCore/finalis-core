# Fuzz targets

Each `fuzz/<target>.cpp` builds two ways (`FINALIS_BUILD_FUZZ=ON`, the default):

- **standalone smoke binary** (`build/<target>`): a fixed-seed random run with no arguments, or a replay of
  the input files given as arguments. The Linux CI release job runs every smoke binary and replays the
  committed seed corpora (`scripts/fuzz_replay_corpus.sh build`).
- **libFuzzer target** (`-DFINALIS_LIB_FUZZING_ENGINE=...`, see `.clusterfuzzlite/build.sh`): fuzzed by
  ClusterFuzzLite on pull requests (`cflite-pr.yml`, 10 min) and nightly (`cflite-batch.yml`, 1 h), starting
  from `seed_corpus/<target>.zip`. That build has no RocksDB (storage uses its file backend).

## fuzz_timed_execution

Stateful time-lock (TxTimed) execution fuzzer: a chain of blocks through `execute_frontier_slice` with a
`TimedExecutionContext`, carrying UTXOs, escrows and long-lock key sets as the derivation does
(`apply_timed_escrows`); committees alternate per 8-block epoch. Scripts mix new envelopes (short/long
locks; transfer, reveal, non-plain, undecryptable and fee-coin-spending bodies; low fee or bond),
plain transfers racing a body's inputs, replays (of envelopes, and of sealed bodies as plain records),
garbage, missing or wrong-height parent time signatures, withheld or forged long openings, and jumps past
the long-lock grace period. Oracles (top of the source): value conservation, every escrow settles once
at its height or expires on time, refund iff applied/expired, no body applies without a valid time
signature, valid unspent transfer bodies apply, a sealed transfer is never a standalone record, forged
openings invalidate the block, deterministic re-execution.

```sh
./build/fuzz_timed_execution                                  # smoke (40 scripts, ~2 s)
FINALIS_FUZZ_SEED=7 FINALIS_FUZZ_ITERS=400 ./build/fuzz_timed_execution
```

## fuzz_consensus_persistence

Stateful consensus + storage-fault fuzzer for the vote-persistence paths (tests/KNOWN_DEFECTS.md). One
validator node (4-validator genesis, no P2P, timers parked) runs a script of operations:

| op | effect |
|---|---|
| propose / repropose | a proposal in a round the node leads (optionally equivocated by the leader), or a known transition re-proposed in the current round with a POL and TC |
| prevote, polka, precommit, commit-quorum | votes of the other committee members, any round, duplicated and reordered freely |
| tc, advance | a timeout certificate (round change) or a direct round reset / catch-up |
| redeliver | the last proposal or vote again (proposal re-delivery re-enters `on_candidate_body_locked`) |
| fault | arm a WAL fault (write EIO, write ENOSPC, sync EIO, sync-then-EIO) until the next restart |
| restart | crash + restart over the same database (disk healthy again) |
| rebroadcast-probe | reads the stall-rebroadcast precommit set (what the node would re-send) |

Fault model: `keys[3]` is Byzantine; `keys[1]`, `keys[2]` never equivocate and never vote for a transition
below its own round. `FINALIS_FUZZ_BYZANTINE_MAJORITY=1` drops that (beyond f: three arbitrary signers can
certify anything, see test `test_pf_finalized_state_must_reload_after_restart`).

Oracles (checked after every op, across restarts): `double-precommit`, `double-prevote`, `lock-rule`,
`precommit-durable`, `prevote-durable`, `finality` (a finalized height changes or rolls back), `restart`
(the node cannot start over its own database). The exact definitions are at the top of the source.
`prevote-durable` counts every in-memory prevote record as sent, because the stall rebroadcast sends them
(shown on a live node by `test_pf_prevote_write_failure_rebroadcast_must_not_send_prevote`); the harness
itself never runs that rebroadcast (timers parked).

Every byte the script reader returns (including zero padding past the end) is logged, so the history since
the fixture started is one exact input. On a violation the binary prints the oracle and the last operations,
writes `crash-<oracle>-<hash>.bin` to `$FINALIS_FUZZ_ARTIFACT_DIR` (default: current directory) and exits 1.

### Commands

```sh
# smoke, faults off: must stay clean (CI gate, release job "Fuzz smoke")
FINALIS_FUZZ_FAULTS=0 FINALIS_FUZZ_ITERS=16 ./build/fuzz_consensus_persistence
# smoke, faults on: finds the open defects within seconds
FINALIS_FUZZ_SEED=1 FINALIS_FUZZ_ITERS=80 ./build/fuzz_consensus_persistence
# past the open D7 rollback (counted as skipped_d7_rollbacks), checking every other oracle
FINALIS_FUZZ_SKIP_D7=1 FINALIS_FUZZ_SEED=1 FINALIS_FUZZ_ITERS=80 ./build/fuzz_consensus_persistence
# replay inputs (each against a fresh node)
./build/fuzz_consensus_persistence crash-*.bin
# shrink a reproducer (deterministic delta debugging; every step re-run twice)
fuzz/minimize_input.py build/fuzz_consensus_persistence crash-X.bin min.bin --expect oracle=precommit-durable
# open-defect reproducers: exit 1 while any still reproduces (CI: non-blocking, in the step summary)
fuzz/replay_known_defects.sh build
```

### Longer campaigns

Not run in CI. Measured here: the standalone binary runs about 45 operations per second including
restarts (16 scripts, 789 operations in 17 s); the libFuzzer build builds a fresh node per input and
managed 43 inputs in 94 s under ASan, so prefer long standalone runs over many seeds, and treat
libFuzzer / ClusterFuzzLite time on this target as a supplement.

```sh
# standalone, many seeds, faults on (stops at the first violation per seed)
for s in $(seq 1 200); do FINALIS_FUZZ_SEED=$s FINALIS_FUZZ_ITERS=400 ./build/fuzz_consensus_persistence || break; done
# libFuzzer (clang): a fresh node per input; storage faults need a RocksDB build, so build with RocksDB
cmake -S . -B build-lf -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer-no-link,address" -DFINALIS_LIB_FUZZING_ENGINE=-fsanitize=fuzzer
cmake --build build-lf --target fuzz_consensus_persistence
./build-lf/fuzz_consensus_persistence -max_len=512 -timeout=60 corpus/
```

Limitations: one node under test (the others are scripted signers, not nodes); no peer-loss / reconnect
reseed (no P2P: covered by `test_pf_lock_write_failure_peer_loss_reseed_must_not_record_precommit`);
storage faults only on Linux with RocksDB (fault ops are no-ops in the ClusterFuzzLite build); with faults on,
an ENOSPC op can abort the process inside the system librocksdb (E1 in tests/KNOWN_DEFECTS.md: a crash
with a RocksDB assertion, not an oracle violation, and no reproducer file is written); no seed
corpus yet (inputs with fault ops would trip the open defects in `scripts/fuzz_replay_corpus.sh`).

`known_defects/<target>/` holds the minimized reproducers of open defects; once a defect is fixed its
reproducer passes and moves into the target's seed corpus as a regression case.
