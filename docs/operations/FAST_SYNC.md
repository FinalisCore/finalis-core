# Fast sync from a snapshot

A new node normally replays the chain from block 0. A snapshot lets it start at a recent height
instead, and then sync the rest from peers. Use it for a new node, a node that has fallen far behind,
or to restore after database corruption.

A snapshot holds every finalized transition and finality certificate since genesis, plus the derived
state at its height. It holds no keys: `keystore/` and `logs/` in your data directory are never touched.

Measured with the testnet-3 snapshot at height 5,173 (192 MB, 301,266 rows): import 4 s, node
start 2 s (`startup-fast-start status=ok`). Full verification from genesis (below) took about
10 minutes for the same height.

## 1. Get a snapshot

Either download one published with a release, together with its height, transition hash and
sha256, or export one from a node you run yourself (section 4).

Check the file before using it:

```bash
sha256sum testnet3-snapshot-<height>.bin   # must match the published sha256
```

## 2. Restore

The node must be stopped: `fast_sync` writes to its database. `--force` clears existing chain state
and keeps `keystore/` and `logs/`. Try `--dry-run` first; it validates the file and changes nothing.

| install (see [testnet/JOIN.md](../../testnet/JOIN.md)) | commands |
|---|---|
| A. prebuilt | `sudo systemctl stop finalis-testnet`<br>`sudo -u finalis -H finalis-cli --testnet fast_sync --snapshot /path/snap.bin --dry-run`<br>`sudo -u finalis -H finalis-cli --testnet fast_sync --snapshot /path/snap.bin --force`<br>`sudo systemctl start finalis-testnet` |
| B. Docker | `docker stop finalis`<br>`docker run --rm --entrypoint finalis-cli -v finalis-data:/var/lib/finalis -v "$PWD":/snap:ro ghcr.io/finaliscore/finalis-core:latest --testnet fast_sync --snapshot /snap/snap.bin --force`<br>`docker start finalis` |
| C. source | `sudo systemctl stop finalis-testnet`<br>`./build/finalis-cli --testnet fast_sync --snapshot /path/snap.bin --force`<br>`sudo systemctl start finalis-testnet` |

For A, the file must be readable by the `finalis` user. Without `--db`, `finalis-cli` uses the same
data directory as the node.

`fast_sync` prints `fast_sync_applied=yes` with the snapshot's `finalized_height` and
`finalized_transition_hash`. After the start, the node log shows:

```
startup-fast-start status=ok finalized_height=<height> transition=<first 8 hex of the hash>
```

Then the node follows the tip from its peers as usual.

## 3. What a snapshot lets you verify

When importing, `finalis-cli` checks that:

- the file is well-formed (format version, sorted rows, row counts, required records);
- it belongs to this network: its genesis must equal the network's built-in genesis, otherwise
  `snapshot genesis mismatch; reject import`;
- its tip, state roots and genesis markers agree with each other.

When starting (default fast start), the node checks that:

- the derived state matches the state commitment signed in the tip transition;
- the tip's finality certificate holds a quorum of the committee recorded in the snapshot.

Fast start does **not** re-execute history. Whoever made the snapshot chose that history, and the
node checks it against itself and against the committee the snapshot names. Two ways to close that
gap:

1. **Compare the tip with an independent source.** The `finalized_transition_hash` that `fast_sync`
   prints must match what other nodes report at that height, for example the explorer or `get_status`
   from a seed you did not get the snapshot from.
2. **Verify everything once.** Start the node one time with `--no-fast-start`. It ignores the
   imported state and re-derives it by replaying every transition in the snapshot from genesis, as
   syncing from block 0 would, without the download.
   When it is done the log shows `availability-state-ready source=canonical-replay`. Later starts
   can use fast start again.

If fast start finds anything inconsistent, the node does not use the imported state. It logs the
reason (for example `checkpoint-post-state-commitment-mismatch`) and replays from genesis instead,
which is slow but correct.

## 4. Export and publish a snapshot

`snapshot_export` opens the database read-only, so the node may keep running:

```bash
finalis-cli --testnet snapshot_export --out snap.bin   # add --db <dir> for a non-default data directory
sha256sum snap.bin
```

It prints `finalized_height`, `finalized_transition_hash` and `entry_count`. Publish all three with
the sha256. Export with the current release: exporters before v2.2.14 left out rows, so their
snapshots always fall back to replay from genesis.

With each release, publish a fresh snapshot as a release asset, named
`<network>-snapshot-<height>.bin` with a `.sha256` file next to it, and list height and transition
hash in the release notes.

## 5. Troubleshooting

| message | meaning |
|---|---|
| `snapshot genesis mismatch; reject import` | snapshot from another network or chain |
| `fast_sync: existing chain state detected` | the data directory already has a chain: add `--force` |
| `snapshot import requires an empty db` | `snapshot_import` (low level) needs an empty directory; use `fast_sync` |
| `startup-fast-start` missing, `checkpoint-...-mismatch` in the log | imported state not usable; the node replays from genesis by itself |
