| Several nodes of one network on one host | `--lightserver-admin-socket <path>` per node | Mainnet and testnet already use separate default paths. `--with-lightserver` passes the network's default path unless| Docker image | `/run/finalis/<network>/admin.sock` inside the container | The image pre-creates `/run/finalis` for the `finalis` user; the lightserver creates `<network>` under it.| `/run/finalis/<network>/admin.sock` | `RuntimeDirectory=finalis/<network>` creates `/run/finalis/<network>` (0700, owned by the service user) on each start and removes only that directory on stop, so a mainnet and a testnet service on one host keep separate sockets. `/var/run` is a symlink to `/run`. |# Lightserver and Node Operations

Operator reference for the lightserver RPC surfaces (public TCP and admin Unix socket), its rate
limits, and the node's fail-stop states. Applies to `finalis-lightserver` whether started
standalone or as the `finalis-node --with-lightserver` child process.

## 1. RPC surfaces

| Surface | Listener | Methods |
|---|---|---|
| Public | TCP `--bind <ipv4>` / `--port` (default 19444) | read methods, `broadcast_tx` |
| Admin | Unix socket `--admin-socket <path>` (default `/var/run/finalis/<network>/admin.sock`, `<network>` = `mainnet` or `testnet`) | everything above| everything above, plus `validator_onboarding_start`, `validator_onboarding_status` |

Admin methods called over TCP return JSON-RPC `-32601 method not found`. They unlock the
validator keystore with a passphrase, which is why they are never served over the network.

## 2. Admin socket

### 2.1 Access control

- The socket is created with mode `0600`. Its parent directory is created `0700` if it does not exist.
- On Linux, every connection is also checked with `SO_PEERCRED`. Only the lightserver's own uid
  and root are served; anyone else is disconnected without a response.
- On startup, a leftover socket file is removed only if it is a socket and nothing is listening on
  it. A path held by a live server, or a non-socket file, is never removed. Admin RPC is then
  disabled for this process.
- If the socket cannot be created, the lightserver keeps serving the public surface and logs
  `admin socket unavailable at <path>; admin RPC (...) disabled` to stderr. Check for this line
  after every deployment change.

### 2.2 Deployment

| Deployment | Socket | Notes |
|---|---|---|
| systemd (`packaging/linux/finalis-node.service`, `scripts/start.sh`) | `/run/finalis/<network>/admin.sock` | `RuntimeDirectory=finalis/<network>` creates `/run/finalis/<network>` (0700, owned by the service user) on each start and removes only that directory on stop, so a mainnet and a testnet service on one host keep separate sockets. `/var/run` is a symlink to `/run`. |
| Docker image | `/run/finalis/<network>/admin.sock` inside the container | The image pre-creates `/run/finalis` for the `finalis` user; the lightserver creates `<network>` under it. Use it with `docker exec`. |
| Windows | none | Unix sockets are not supported. Admin RPC is unavailable (see 2.4). |
| Several nodes of one network on one host | `--lightserver-admin-socket <path>` per node | Mainnet and testnet already use separate default paths. `--with-lightserver` passes the network's default path unless the node gets `--lightserver-admin-socket <path>` (empty disables it); without it only the first child binds the socket. Point clients at the matching path with `--admin-rpc unix://<path>`. |

`--no-admin-socket` disables the admin surface on purpose.

### 2.3 Validator onboarding through the admin socket

Run the CLI as the service user so the uid check passes:

```bash
sudo -u finalis finalis-cli validator-register \
  --db /var/lib/finalis/mainnet \
  --file /var/lib/finalis/mainnet/keystore/validator.json \
  --admin-rpc unix:///run/finalis/mainnet/admin.sock
```

Notes:

- The keystore must be passphrase-encrypted and must be inside `<db>/keystore`. Other paths are
  rejected.
- Without `--rpc-only`, the CLI falls back to local DB access when the admin RPC is unavailable.
  That needs exclusive DB access, so stop the node first.
- `validator-register-status` and `validator-register-cancel` take the same `--admin-rpc` flag.

Docker:

```bash
docker exec -it finalis-node1 finalis-cli validator-register \
  --db /var/lib/finalis/db --file /var/lib/finalis/keystore/validator.json \
  --admin-rpc unix:///run/finalis/mainnet/admin.sock
```

### 2.4 Known limitation: desktop wallet

The desktop wallet always connects to `unix:///var/run/finalis/<network>/admin.sock` (the
network it is switched to) for validator onboarding. It only works when the wallet runs as the same user as the lightserver (or as root),
on Linux or macOS. It does not work on Windows, or when the wallet user differs from a systemd
`finalis` service user. Use the CLI procedure in 2.3 in those cases.

## 3. Public rate limits

Token buckets, refilled continuously, each starting full:

| Bucket | Limit |
|---|---|
| Per IP, read (every method except `broadcast_tx`, plus malformed requests) | 100 / min |
| Per IP, `broadcast_tx` | 10 / min (one token per 6 s) |
| Global, all public requests | 1000 / min |

Behaviour:

- Every public request is charged after it is read and before dispatch, including malformed
  requests and requests to unknown endpoints.
- The per-IP bucket is checked before the global one. A request refused by the global bucket has
  still used its per-IP token.
- Over the limit: HTTP `429`, JSON-RPC error `-32029 rate limited`, `Retry-After: <seconds>`.
- At most 65,536 client IPs are tracked; IPs idle for more than 2 minutes are dropped. When the
  table is full of active IPs, new IPs get `429` with `Retry-After: 60` (fail closed).
- The public listener is IPv4 only.

### 3.1 Loopback exemption and reverse proxies

Clients connecting from `127.0.0.0/8` (local explorer, local wallet) are exempt by
default. Behind a same-host reverse proxy every client appears as `127.0.0.1`, so the limits would
never apply. In that case start the lightserver with `--trusted-proxy 127.0.0.1/32`
(`finalis-node --lightserver-trusted-proxy 127.0.0.1/32` with `--with-lightserver`;
`BEHIND_PROXY=1 scripts/start.sh` does this):

- a request from a trusted peer carrying `X-Real-IP` is limited by that address and never
  exempt, so every public client gets its own buckets;
- a request from a trusted peer without `X-Real-IP` (the local explorer, a local wallet) is still
  exempt;
- `X-Real-IP` from any other peer is ignored;
- an IPv6 client is limited as its /64.

The proxy must set `X-Real-IP` itself (overwriting the client's), as `packaging/nginx/finalis.conf.in`
does. Behind a Cloudflare tunnel, which passes client headers through, use
`--client-ip-header CF-Connecting-IP` (node: `--lightserver-client-ip-header`; start.sh:
`CLIENT_IP_HEADER`): the edge overwrites that header. The older alternative, `--rate-limit-loopback`, puts every public client in one shared bucket;
`--with-lightserver` does not forward it.

### 3.2 Capacity

- Connections are handled by a worker pool of `clamp(hardware_concurrency, 4, 8)` threads with a
  queue of 64. When the queue is full, the accept thread answers HTTP `503`, JSON-RPC `-32005 server busy`,
  `Retry-After: 1`.
- Each worker waits up to 15 s on a slow client. The admin socket shares this pool, so a public
  flood can delay admin calls.
- The 1000/min global bucket is shared by all clients, so a set of IPs at their per-IP limit can
  use it up. Public operators should put a proxy or CDN with its own per-client limits in front.

## 4. Node fail-stop states

Some states need an operator decision. Restarting unchanged cannot fix them, so the shipped
service definitions do not restart on them. A failed safety-state write also stops the node, but a
restart is the recovery, so that exit code is restarted.

| State | Signal | Exit | Restart policy |
|---|---|---|---|
| Next committee derived by the emergency prior-committee rule ([CHECKPOINT_DERIVATION_SPEC §11.1](../spec/CHECKPOINT_DERIVATION_SPEC.md)) and the node was not started with `--acknowledge-emergency-fallback` | `CRITICAL emergency-fallback-committee-active` in the log, stderr explains | `78` | systemd `RestartPreventExitStatus=78` |
| RocksDB reports corruption on a read or prefix scan | `finalized-state-invariant-violation source=db-read-corruption` (or `db-scan-corruption`) | `SIGABRT` | systemd `RestartPreventExitStatus=SIGABRT` |
| A durable write of consensus safety state (vote lock, prevote record, valid polka) failed (disk full, I/O error) | `CRITICAL safety-storage-failure operation=... reason=...`; the node signs nothing further and stops | `75` | restarts (reloads the safety state from disk); with the disk still failing it fails again and systemd stops after `StartLimitBurst` |

Other failures restart after 5 s. systemd stops trying after 5 failed starts in 300 s
(`StartLimitBurst=5`, `StartLimitIntervalSec=300`); clear it with `systemctl reset-failed finalis-node`.
docker-compose uses `restart: on-failure:5`. Docker cannot exclude particular exit codes from restarts.

### 4.1 Emergency fallback committee

The emergency committee has at most 4 members. They come from the two previous committees and
must still be bonded and not `BANNED`, `ONBOARDING` or `EXITING`. Before acknowledging:

1. Confirm in the logs (`CRITICAL emergency-fallback-committee epoch=... members=...`) that the
   listed members are operators you expect to be online. If none of them comes back, the chain
   cannot finalize.
2. Coordinate with the other operators. Every node must accept the same checkpoint.
3. Restart with `--acknowledge-emergency-fallback`. Remove the flag once a normal checkpoint has
   been finalized.

### 4.2 Database corruption

Do not restart the node on the same data directory. Keep a copy of it for analysis, then resync
or restore from a snapshot (`finalis-cli snapshot_import --db <new-dir> --in <snapshot.bin>`). The node aborts on corruption on
purpose: if a corrupted record were read as missing, the node's derived state would silently
diverge.

## 5. Light-client proofs

Wallets check this server's answers against validator signatures
([LIGHT_CLIENT.md](../spec/LIGHT_CLIENT.md)). They need one committee handoff per epoch, which the
node writes when it finalizes an epoch's last height.

- A node whose database predates handoffs rebuilds the missing ones once, at startup, by replaying
  the stored chain: `committee-handoff-backfill-start missing=<n>`, then
  `committee-handoff-backfill-done written=<n>`. Startup takes longer while it runs.
- A node fast-synced from a snapshot gets the handoffs with the snapshot.
- Without handoffs or proofs (an old node), wallets show the balance as `NOT VERIFIED`. They never
  show it as verified.
