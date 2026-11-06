# finalis-nodetest

Sends random test transactions on the Finalis **testnet** from its own throwaway wallet, logs each
one, and at the end returns the coins to the wallet's first address. Validators run it on their own
machine, next to their node, during a shared test window.

## Quick start

```bash
finalis-nodetest address          # creates the wallet on first use and prints its addresses
# send 5 testnet FLS to address #0 (from your own wallet), wait until the payment is final
finalis-nodetest                  # 30 minutes at 0.1 tx/s, then waits, sweeps and prints a summary
```

It talks to the lightserver at `http://127.0.0.1:19544/rpc` (the testnet default). Pass `--rpc URL`
to use another one.

## Shared test window: `--start-at`

To make every participant start at the same moment, whatever their time zone, everyone runs the same
command with the start time in UTC:

```bash
finalis-nodetest --start-at 2026-11-14T08:00:00Z
```

Start it at least 15 minutes early:

1. It checks the network and the node right away, prepares its coins (the setup split), and counts down.
2. At the start time it checks the node again. Each node waits a further 0 to 30 random seconds, so
   that not all of them send in the same second.
3. Then it runs as usual.

The time must be exactly `YYYY-MM-DDTHH:MM:SSZ` in UTC. A start more than 14 days ahead is refused as
a likely typo. If you start the tool more than 10 minutes after the start time, it exits with code 4
rather than run alone. `--allow-late` overrides that. Your machine's clock must be right, which a
validator's clock already needs to be.

## What it does

- **Its own wallet.** The first run creates a random seed and 8 addresses in `~/.finalis-nodetest/wallet.txt`
  (mode 0600, plain text; testnet coins only). It never reads `validator.json`, a node keystore or a bond.
- **All 10 transaction types**, chosen at random: `std`, `hlock`, `inherit`, `shield`, `c2c`,
  `unshield`, `timed`, `timed-long`, `seal`, `seal-long`. `--types std,c2c` picks a subset.
  Time locks each hold a 0.1 FLS bond until they open, so they are rarer and at most 10 are open at once.
- **Work coins.** When fewer than 40 coins of 0.24 FLS are left, it splits a larger coin (logged as `split`).
- **Recipients** are its own addresses, plus with `--peers FILE` the addresses of other participants.
- **End of run:** waits up to `--drain` seconds (default 600) for open transactions, then sends every
  spendable coin, confidential ones included, back to address #0. Only fees are spent.

## `--peers`: transfers between participants

The file lists other participants' addresses, one `tsc1…` address per line (`#` starts a comment).
Everyone shares their address #0 (`finalis-nodetest address`). Some transparent payments then go to
other participants, and theirs come to you.

**Your coins then partly end up with other participants, and some of theirs end up with you.** The
sweep only returns what your wallet holds at the end. Coins stay within the group. Use `--peers`
only for testnet coins you don't mind trading.

## Safety limits

- **Testnet only.** It checks the server's network id and genesis hash against this build's testnet
  and refuses mainnet and every other chain. It checks again every 15 seconds.
- **Bounded.** The default is 0.1 tx/s for 30 minutes. The hard limits are 1 tx/s and 4 hours, and
  higher values are refused rather than reduced.
- **Stops** on Ctrl-C, or when a file named `STOP` appears in the wallet directory. It still waits and
  sweeps. A second Ctrl-C skips the wait.
- **Backs off** when the node is busy. Retryable rejects (`relay_unavailable`, mempool full, fee too
  low) pause sending for 5, 10, 20 … up to 300 seconds. 25 non-retryable rejects in a row stop the run.
- **Preflight.** It won't start while the node is syncing, is more than 2 blocks behind, or has fewer
  than `--min-peers` (default 2) established peers.
- **Uploads nothing.** The log stays local. You can paste the summary if you want to share it.

## Output

Each transaction gets one tab-separated line on stdout, also written to `~/.finalis-nodetest/txlog.tsv`:

```
2026-11-07T10:00:00Z  send     std    <txid>  http://127.0.0.1:19544/rpc  accepted
2026-11-07T10:03:31Z  final    std    <txid>  height=3512  seconds=211
2026-11-07T10:00:05Z  send     c2c    <txid>  http://127.0.0.1:19544/rpc  rejected  relay_unavailable: …
```

At the end it prints a summary with counts by type, rejects by reason, transactions that never became
final, slots that had no coin to spend, and the time to finality (p50, p95, max).

## Commands

| command   | what it does                                                     |
|-----------|------------------------------------------------------------------|
| `run`     | default: send, wait, sweep, summary                              |
| `sweep`   | only wait for open transactions and return coins to address #0  |
| `status`  | spendable transparent and confidential coins, and height-locked coins |
| `address` | the wallet's addresses                                           |

Height locks and time locks open some blocks after they are sent, and a `timed-long` lock opens only
in the next committee epoch. Coins still locked at the end are swept by a later `finalis-nodetest sweep`.
Run that sweep after the locks have opened. A sweep started by a new process doesn't know which
coins a still-pending time lock will spend, and spending them first forfeits that lock's bond.

Code: `nodetest_core.*` has the parts that need no network (tests in `tests/test_nodetest.cpp`).
`main.cpp` runs them against the lightserver.
