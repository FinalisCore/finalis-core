# Join the Finalis testnet

Finalis is a blockchain where every block is final the moment validators sign it: no waiting for
confirmations and no reorgs, with confidential (amount-hiding) transactions built in from genesis.
**testnet-1** has been running since 19 October 2026. It uses mainnet's rules with its own identity,
and its coins (FLS) **have no value**.

We are looking for people to run nodes and, if they want, to become validators. Today the testnet
has **one** validator, so every block depends on a single machine. Four independent validators is
the first size that survives one going down. You can help get there.

This guide takes about 30 minutes, most of it waiting for the build.

- **Run a node** (steps 1–3): syncs and relays the chain. No coins or keys needed.
- **Become a validator** (step 4): your node signs blocks. You need a bond in testnet FLS, which we
  send you for free.

Questions at any point: **[Discord](https://discord.gg/8rKfKc7QR9)**.

---

## What you need

- Linux: Ubuntu, Debian, Fedora or Arch. A small VPS is fine; so is a home machine.
- 2 CPU cores and 2 GB RAM recommended (compiling uses the most memory; on 1 GB add swap first).
- About 10 GB free disk. The chain itself is small for now.
- A normal user account with `sudo`.
- For a validator: a machine that stays on. Validators that miss too many blocks are suspended.

Windows can run a plain node; see [README.md](README.md#windows). This guide covers Linux.

---

## 1. Install and start the node

```bash
git clone https://github.com/FinalisCore/finalis-core.git
cd finalis-core
FINALIS_NETWORK=testnet SERVICE_NAME=finalis-testnet ./scripts/start.sh
```

Run it as your normal user; it asks for `sudo` where it needs it. The script:

- installs the build tools and compiles everything into `build/` (this is the slow part);
- starts two background services, `finalis-testnet` (the node) and `finalis-testnet-explorer` (a
  block explorer for your own use), which also start again after a reboot;
- connects to the testnet and begins syncing.

## 2. Check that it is syncing

```bash
sudo journalctl -u finalis-testnet -f
```

Lines like `testnet h=1650 ... peers=1` mean it is working; `h` is the block height it has reached.
Press `Ctrl+C` to stop watching (the node keeps running).

Confirm you are on the right chain:

```bash
curl -s http://127.0.0.1:19544/rpc -d '{"jsonrpc":"2.0","id":1,"method":"get_status","params":{}}'
```

Look for `"network_name":"testnet"`, `"chain_id_ok":true` and a `genesis_hash` starting with
`5cabf22b`. You can also open your own explorer at `http://127.0.0.1:18080` on that machine.

## 3. Let other nodes connect to you (recommended)

Your node works without this: it connects out and syncs. Opening **TCP port 19540** lets other nodes
connect in, which makes the network sturdier.

- **Firewall on the machine:** `start.sh` opens it with `ufw` or `firewalld` when one is installed.
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
`~/.finalis/testnet/keystore/validator.json`. From the `finalis-core` folder:

```bash
./build/finalis-cli --testnet getBalance
```

It prints the key's `address=tsc1…` (where your bond goes) and its `balance`, in units:
1 FLS = 100,000,000 units.

> This testnet key is stored unencrypted, which is acceptable only because testnet coins are
> worthless. Never use it for mainnet, and never copy it to a second machine: two nodes signing with
> one key is double-signing, for which a validator's bond can be slashed.

### 4.2 Ask for testnet FLS

Post your `tsc1…` address in **[Discord](https://discord.gg/8rKfKc7QR9)** and ask for validator
funds. You need the bond plus a small fee:

| active validators | bond |
|---|---|
| 1 (now) | 4,000 FLS |
| 4 | 2,000 FLS |
| 16 or more | 1,000 FLS |

The bond shrinks as the validator set grows, so early validators need more. We send a little extra
for fees.

Once we confirm, run `getBalance` again to see the coins arrive.

### 4.3 Register

```bash
./build/finalis-cli --testnet validator-register
```

This builds your bond and registration transactions from the key's own coins, sends them, and
follows them until they are final. It includes a short proof-of-work, so it can take a few minutes.
If you close the terminal, check on it later with:

```bash
./build/finalis-cli --testnet validator-register-status
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

**Updating:** when we announce a new release on Discord:

```bash
cd finalis-core
git pull
FINALIS_NETWORK=testnet SERVICE_NAME=finalis-testnet ./scripts/start.sh
```

It rebuilds and restarts; your chain data and key are kept. After an update that adds features, the
first start can take a little longer while the node prepares data for them.

**Stopping for good:** `sudo systemctl disable --now finalis-testnet finalis-testnet-explorer`. If you
were a validator, tell us on Discord so we know to expect it.

## Something not working?

| you see | what it means |
|---|---|
| `peer-connect-failed ... reason=tcp-connect-failed` | the node cannot reach a seed; check outbound firewall rules |
| `upnp-igd-refresh status=failed` | harmless on a VPS; at home, forward port 19540 by hand |
| `genesis-fingerprint-mismatch` | the data folder belongs to another chain; see [README.md → Troubleshooting](README.md#troubleshooting) |
| the build stops with a memory error | add 2 GB of swap and run `start.sh` again |

Still stuck? Ask in **[Discord](https://discord.gg/8rKfKc7QR9)** with the last 50 log lines
(`sudo journalctl -u finalis-testnet -n 50`). Bugs are welcome as GitHub issues; security problems go
privately through [SECURITY.md](../SECURITY.md).

## A few ground rules

- Testnet coins are worthless and the testnet may be reset. Do not buy, sell or trade them.
- Keep testnet and mainnet keys separate.
- Running a node is the most useful thing you can do; reporting what breaks is the second.
