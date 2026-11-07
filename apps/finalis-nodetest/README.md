# finalis-nodetest

Sends random test transactions on the Finalis **testnet** from its own throwaway wallet, logs each
one, and at the end returns the coins to the wallet's first address. Validators run it on their own
machine, next to their node, during shared test windows.

## Quick start: leave it running

```bash
finalis-nodetest address          # creates the wallet on first use and prints its addresses
# send 5-10 testnet FLS to address #0 (from your own wallet)
finalis-nodetest auto             # keeps running and joins every shared test window by itself
```

`auto` needs nothing else from you:

1. It waits until the wallet holds at least 1 FLS (it prints address #0 while it waits).
2. Every hour it reads the published schedule, [testnet/NODETEST_SCHEDULE.json](../../testnet/NODETEST_SCHEDULE.json)
   (downloaded read-only from GitHub; nothing is uploaded).
3. 20 minutes before a window it prepares its coins, then starts with everyone else at the window's
   start (plus 0 to 30 random seconds).
4. After the window it waits for open transactions, returns the coins to address #0 and saves the
   summary as `summary-<start>.txt` in the wallet directory.
5. Coins that unlock later (height locks, time-lock bodies and bonds) are returned to address #0 once
   they unlock. Because the same process keeps running, it knows which coins pending time locks will
   spend and never spends them early.

To run it as a service that survives reboots, see [Always on](#always-on) below.

It joins a window that started less than 10 minutes ago; later ones are skipped, as with
`--start-at`. `--rate` and `--duration` are ceilings on each window in `auto`. `--schedule FILE`
reads the windows from a local file instead (same format), `--schedule-url URL` from another place.

A single run without the schedule:

```bash
finalis-nodetest                  # 30 minutes at 0.1 tx/s, then waits, sweeps and prints a summary
```

It talks to the lightserver at `http://127.0.0.1:19544/rpc` (the testnet default). Pass `--rpc URL`
to use another one.

## Where the wallet lives

Every command prints `Wallet: <path>` first. Keep using the same path: a different one is a new,
empty wallet, and the coins stay in the old one.

| setup | default wallet directory |
|-------|--------------------------|
| Linux / macOS | `~/.finalis-nodetest` (from `HOME`, else the account's home directory) |
| Windows | `%APPDATA%\.finalis-nodetest` (or `%HOME%\.finalis-nodetest` when `HOME` is set, e.g. Git Bash) |
| Docker | `/var/lib/finalis/.finalis-nodetest` in the node's data volume, with `docker exec` into the node container or the `auto` container below. A `docker run --rm` without that volume loses the wallet when the container exits. |
| `sudo` | the wallet of root, not yours: run it as your own user |

`--dir DIR` picks another directory. A relative path is made absolute against the directory the tool
is started from.

## Always on

**Linux (systemd).** Create `/etc/systemd/system/finalis-nodetest.service`, with `User=` set to the
account that owns the wallet (run `finalis-nodetest address` as that user first) and the path of your
binary (`/opt/finalis-core/bin/finalis-nodetest` from install.sh, or `<checkout>/build/finalis-nodetest`):

```ini
[Unit]
Description=finalis-nodetest auto (shared testnet test windows)
After=network-online.target
Wants=network-online.target

[Service]
User=YOUR_USER
ExecStart=/opt/finalis-core/bin/finalis-nodetest auto
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now finalis-nodetest
journalctl -u finalis-nodetest -f        # what it does; the summaries appear here too
```

**Docker.** A second container from the same image, on the host network (it reaches the node's
lightserver at `127.0.0.1:19544`, published by the node's `docker run`) and with the node's data
volume (the wallet stays there):

```bash
docker run -d --name finalis-nodetest --restart unless-stopped --network host \
  -v finalis-data:/var/lib/finalis --entrypoint finalis-nodetest \
  ghcr.io/finaliscore/finalis-core:latest auto
docker logs -f finalis-nodetest
```

To update it, `docker pull` the image, then `docker rm -f finalis-nodetest` and run the line again.

**Windows.** Leave `finalis-nodetest.exe auto` running in a PowerShell window, or add it to Task
Scheduler ("At log on"). The PC must be awake during the windows.

**Stopping:** `touch <wallet dir>/STOP` (or stop the service / container). A stop during a window
still waits for open transactions and returns the coins first.

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
  Time locks each hold a 0.1 FLS bond until they open, so they are rarer: at most one per two blocks
  and at most 10 open at once. Unlock heights are spread at random (a block can open at most 16 time
  locks), and no short lock is sent in the last 3 blocks of a committee epoch.
- **Work coins.** When fewer than 40 coins of 0.125 FLS are left, it splits a larger coin (logged as
  `split`). 5 FLS makes the 40 a run needs.
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
| `auto`    | keep running: wait for funds, join every scheduled window, sweep after each and later |
| `sweep`   | only wait for open transactions and return coins to address #0  |
| `status`  | spendable transparent and confidential coins, and height-locked coins |
| `address` | the wallet's addresses                                           |

Height locks and time locks open some blocks after they are sent, and a `timed-long` lock opens only
in the next committee epoch. `auto` sweeps them home when they unlock. After `run`, coins still locked
at the end are swept by a later `finalis-nodetest sweep`.
Run that sweep after the locks have opened. A sweep started by a new process doesn't know which
coins a still-pending time lock will spend, and spending them first forfeits that lock's bond.

Code: `nodetest_core.*` has the parts that need no network (tests in `tests/test_nodetest.cpp`).
`main.cpp` runs them against the lightserver.
