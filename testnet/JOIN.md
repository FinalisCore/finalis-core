# Join the Finalis testnet

Finalis is a blockchain where every block is final the moment validators sign it: no waiting for
confirmations and no reorgs, with confidential (amount-hiding) transactions built in from genesis.
**testnet-3** starts on 28 October 2026 at 17:00 UTC. It uses mainnet's rules with its own identity,
and its coins (FLS) **have no value**. (It replaces testnet-2; if you ran a testnet-2 node, see
[README.md](README.md#genesis-testnet-3).)

We are looking for people to run nodes and, if they want, to become validators. Today the testnet
has **one** validator, so every block depends on a single machine. Four independent validators is
the first size that survives one going down. You can help get there.

Running a node takes about 5 minutes with the prebuilt package or Docker.

- **Run a node** (steps 1–3): syncs and relays the chain. No coins or keys needed.
- **Become a validator** (step 4): your node signs blocks. You need a bond in testnet FLS, which we
  send you for free.

Questions at any point: **[Discord](https://discord.gg/8rKfKc7QR9)**.

---

## What you need

- Linux on x86_64 or ARM64 (Oracle Ampere, Raspberry Pi 4/5, Graviton). A small VPS is fine; so is
  a home machine.
- 1 CPU core and 1 GB RAM for a node. Building from source wants 2 GB (or swap).
- About 10 GB free disk. The chain itself is small for now.
- A normal user account with `sudo`.
- For a validator: a machine that stays on. Validators that miss too many blocks are suspended.

Windows can run a plain node; see [README.md](README.md#windows). This guide covers Linux.

---

## 1. Install and start the node

Pick one. All three start a node that syncs the testnet and starts again after a reboot.

**A. Prebuilt package** (Ubuntu 24.04+, Debian 13+, Fedora 40+, Arch):

```bash
curl -fsSL https://raw.githubusercontent.com/FinalisCore/finalis-core/main/scripts/install.sh | bash
```

It checks the download's checksum, installs to `/opt/finalis-core`, and runs the node as the
`finalis-testnet` service under its own `finalis` user, with data in `/var/lib/finalis`. Read the
[script](../scripts/install.sh) first if you like; re-running it upgrades the node.

**B. Docker** (any Linux with Docker, including older distros):

```bash
docker run -d --name finalis --restart on-failure:5 \
  -p 19540:19540 -p 127.0.0.1:19544:19544 \
  -v finalis-data:/var/lib/finalis \
  ghcr.io/finaliscore/finalis-core:latest
```

Data and keys live in the `finalis-data` volume. Watch it with `docker logs -f finalis`.

**C. Build from source** (also installs a local block explorer):

```bash
git clone https://github.com/FinalisCore/finalis-core.git
cd finalis-core
FINALIS_NETWORK=testnet SERVICE_NAME=finalis-testnet ./scripts/start.sh
```

Run it as your normal user; it asks for `sudo` where it needs it. It installs the build tools,
compiles everything into `build/` (about 30 minutes), and starts two services, `finalis-testnet`
(the node) and `finalis-testnet-explorer` (an explorer at `http://127.0.0.1:18080`).

The later steps run `finalis-cli`. Type it the way that matches your install:

| install | `finalis-cli` means |
|---|---|
| A. prebuilt | `sudo -u finalis -H finalis-cli` |
| B. Docker | `docker exec finalis finalis-cli` |
| C. source | `./build/finalis-cli` (from the `finalis-core` folder) |

## 2. Check that it is syncing

```bash
sudo journalctl -u finalis-testnet -f     # A and C
docker logs -f finalis                    # B
```

Lines like `testnet h=1650 ... peers=1` mean it is working; `h` is the block height it has reached.
Press `Ctrl+C` to stop watching (the node keeps running).

Confirm you are on the right chain:

```bash
curl -s http://127.0.0.1:19544/rpc -d '{"jsonrpc":"2.0","id":1,"method":"get_status","params":{}}'
```

Look for `"network_name":"testnet"`, `"chain_id_ok":true` and a `genesis_hash` starting with
`887c5294`.

## 3. Let other nodes connect to you (recommended)

Your node works without this: it connects out and syncs. Opening **TCP port 19540** lets other nodes
connect in, which makes the network sturdier.

- **Firewall on the machine:** `start.sh` opens it with `ufw` or `firewalld` when one is installed.
  With the prebuilt package or Docker, open it yourself, for example `sudo ufw allow 19540/tcp`.
- **Cloud VPS:** also add an inbound rule for TCP 19540 in the provider's console (security group /
  firewall).
- **Home connection:** the node asks your router to forward the port by itself. If the log shows
  `upnp-igd-refresh status=failed`, forward 19540 in your router by hand.

Step-by-step instructions for Oracle Cloud, AWS, Google Cloud, Azure, home routers and testing the
port: [README.md → Open ports](README.md#open-ports).

**You are now running a Finalis node. Thank you!** Stop here, or continue to become a validator.

---

## 4. Become a validator

### 4.1 Find your validator address

On first start the node created a validator key for this machine at
`~/.finalis/testnet/keystore/validator.json` in the node's home folder (`/var/lib/finalis` for the
prebuilt package and Docker). With `finalis-cli` as in step 1:

```bash
finalis-cli --testnet getBalance
```

It prints the key's `address=tsc1…` (where your bond goes) and its `balance`, in units:
1 FLS = 100,000,000 units.

> This testnet key is stored unencrypted, which is acceptable only because testnet coins are
> worthless. Never use it for mainnet, and never copy it to a second machine: two nodes signing with
> one key is double-signing, for which a validator's bond can be slashed.

### 4.2 Ask for testnet FLS

In the faucet channel on **[Discord](https://discord.gg/8rKfKc7QR9)**, type:

```
/faucet address:tsc1…
```

The faucet bot sends the bond plus 1 FLS for fees, one grant per Discord account and per address.
The bond depends on how many validators are active:

| active validators | bond |
|---|---|
| 1 (now) | 4,000 FLS |
| 4 | 2,000 FLS |
| 16 or more | 1,000 FLS |

Testnet FLS exist only as block rewards (there is no premine, also on testnet), so bonds are paid
as the faucet earns them, in request order. The bot tells you your place in the queue and an
estimated time, and pings you when the coins are sent and again when they are final. Meanwhile your
node keeps running and syncing as a plain node.

When the bot says the payment is final, run `getBalance` again to see the coins.

### 4.3 Register

```bash
finalis-cli --testnet validator-register
```

This builds your bond and registration transactions from the key's own coins, sends them, and
follows them until they are final. It includes a short proof-of-work, so it can take a few minutes.
If you close the terminal, check on it later with:

```bash
finalis-cli --testnet validator-register-status
```

### 4.4 Wait for your first block

Your node already holds the key, so there is nothing to restart. After registration:

1. **Warm-up:** 100 blocks, about 5 hours at the current pace of roughly one block every 3 minutes.
2. **Committee:** you join the signing committee at the next epoch boundary (every 32 blocks).

When `get_status` (step 2) reports `"validator_registry_status":"ACTIVE"`, your node is a
validator and starts proposing and voting. Welcome aboard.

---

## Day to day

```bash
sudo systemctl status finalis-testnet      # is it running?
sudo journalctl -u finalis-testnet -f      # live log
sudo systemctl restart finalis-testnet
```

(Docker: `docker ps`, `docker logs -f finalis`, `docker restart finalis`.)

**Updating:** when we announce a new release on Discord:

- **A. prebuilt:** run the `curl … install.sh | bash` line again.
- **B. Docker:** `docker pull ghcr.io/finaliscore/finalis-core:latest`, then `docker rm -f finalis` and
  the `docker run` line again (the volume keeps your data).
- **C. source:** `cd finalis-core && git pull && FINALIS_NETWORK=testnet SERVICE_NAME=finalis-testnet ./scripts/start.sh`

Your chain data and key are kept. After an update that adds features, the
first start can take a little longer while the node prepares data for them.

**Stopping for good:** `sudo systemctl disable --now finalis-testnet` (C: also
`finalis-testnet-explorer`; Docker: `docker rm -f finalis`). If you
were a validator, tell us on Discord so we know to expect it.

## Something not working?

| you see | what it means |
|---|---|
| `peer-connect-failed ... reason=tcp-connect-failed` | the node cannot reach a seed; check outbound firewall rules |
| `upnp-igd-refresh status=failed` | harmless on a VPS; at home, forward port 19540 by hand |
| `genesis-fingerprint-mismatch` | the data folder belongs to another chain; see [README.md → Troubleshooting](README.md#troubleshooting) |
| the build stops with a memory error | add 2 GB of swap and run `start.sh` again, or use the prebuilt package |
| `install.sh`: glibc is older than 2.39 | your distro is too old for the package; use Docker |

Still stuck? Ask in **[Discord](https://discord.gg/8rKfKc7QR9)** with the last 50 log lines
(`sudo journalctl -u finalis-testnet -n 50`). Bugs are welcome as GitHub issues; security problems go
privately through [SECURITY.md](../SECURITY.md).

## A few ground rules

- Testnet coins are worthless and the testnet may be reset. Do not buy, sell or trade them.
- Keep testnet and mainnet keys separate.
- Running a node is the most useful thing you can do; reporting what breaks is the second.
