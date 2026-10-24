# Finalis Testnet

New here? **[Join the testnet](JOIN.md)**: run a node and become a validator, step by step.

A public network with mainnet's consensus and economic parameters and its own identity, so it can
rehearse mainnet without being mistaken for it:

| | mainnet | testnet |
|---|---|---|
| flag | (default) | `--testnet` on `finalis-node`, `finalis-lightserver`, `finalis-cli` |
| addresses | `sc1…` | `tsc1…` |
| P2P / RPC ports | 19440 / 19444 | 19540 / 19544 |
| data directory | `~/.finalis/mainnet` | `~/.finalis/testnet` |
| network id, magic | see `mainnet/genesis.json` | `sha256("finalis:testnet")[:16]`, `0x54534331` |

Every signature commits to the chain domain `sha256d("SC-CHAIN-DOMAIN-V1" || network_id ||
genesis_hash)`: transaction inputs, unbonds, confidential spends and balance proofs, as well as votes,
proposals and timeout votes. A transaction or vote signed for one network is therefore invalid on
every other one, and the different P2P magic keeps their nodes from connecting. Still, keep testnet
and mainnet keys separate. Testnet coins have no value.

## Genesis (testnet-2)

One bootstrap validator, run by the maintainer ([pubkeys.txt](pubkeys.txt)). Others join after
launch (see "Join as a validator" below), funded with testnet FLS from the bootstrap validator's
block rewards. The mainnet ceremony
([../mainnet/GENESIS_VALIDATOR_CEREMONY.md](../mainnet/GENESIS_VALIDATOR_CEREMONY.md)) is not used.

Until more validators are active the chain has no fault tolerance: the bootstrap validator alone
finalizes every block, and the chain stops while it is down. Quorum with 2 validators is 2 (either
one stopping halts it); 4 is the first size that survives a failure, so grow from 1 straight to 4,
each on its own machine.

### 1. Keys: on each validator machine, never copied elsewhere

```bash
finalis-cli --testnet wallet_create --out ~/.finalis/testnet/keystore/validator.json --pass "<passphrase>"
```

Keep the passphrase off the machine's shell history (for example, read it from a file with
`--validator-passphrase-env` later). Record only the printed `pubkey_hex`.

### 2. genesis.json and genesis.bin: on the release commit

Put the genesis `pubkey_hex` values in `testnet/pubkeys.txt`, one per line, then:

```bash
scripts/make_genesis_json.py --network testnet --pubkeys testnet/pubkeys.txt \
    --genesis-time <UTC, a few hours after the freeze> --out testnet/genesis.json
finalis-cli genesis_build  --in testnet/genesis.json --out testnet/genesis.bin
finalis-cli genesis_verify --json testnet/genesis.json --bin testnet/genesis.bin
scripts/genesis_to_cpp.py --network testnet --in testnet/genesis.bin --out src/genesis/embedded_testnet.cpp
```

Commit `pubkeys.txt`, `genesis.json`, `genesis.bin` and `embedded_testnet.cpp` together, tag the
commit, and publish the `genesis_hash`. Anyone can reproduce it from the committed files.

testnet-2 is embedded (`genesis_hash` `4faa7e1b8e79509c767f7f51f711eba7c75e9e9e4d9ea105fa020dd15cdd9d0c`,
check with `finalis-cli --testnet genesis_print_embedded`), so nodes need no `--genesis` flag. Its
`genesis_time_unix` is 1792861200 (2026-10-24 17:00 UTC); the code freeze is release v2.1.0.

testnet-2 replaced testnet-1 (genesis `5cabf22b…`, 2026-10-19) when the leader VRF became RFC 9381
ECVRF-EDWARDS25519-SHA512-TAI: testnet-1's VRF depended on the libsodium build, so nodes could
disagree on leader proofs. A node that ran testnet-1 exits with `genesis mismatch against existing
database`: delete its data directory (`~/.finalis/testnet`, keeping `keystore/` if you want the same
validator key) and start it again.

### 3. Seeds

[SEEDS.json](SEEDS.json). Seeds are meant to be plain nodes (not validators), so validator addresses
are never published. Each runs:

```bash
finalis-node --testnet --public --with-lightserver --lightserver-bind 0.0.0.0
```

A node loads `<data dir>/keystore/validator.json` whenever that file exists, with or without
`--validator-key-file`, so a seed must not have one. The testnet launched with a single host,
130.61.126.39, which is both the seed and the bootstrap validator; a separate plain seed replaces it
in SEEDS.json before more validators join.

### 4. Launch

1. Build release binaries from the tagged commit; publish their hashes.
2. Start the seeds, then the bootstrap validator, before `genesis_time_unix`:

   ```bash
   finalis-node --testnet --listen --with-lightserver \
       --validator-key-file ~/.finalis/testnet/keystore/validator.json \
       --validator-passphrase-env FINALIS_VALIDATOR_PASSPHRASE
   ```

3. Check every node: `get_status` on its lightserver (`finalis-cli --testnet rpc_status`) reports
   `network_name = "testnet"` and `chain_id_ok = true`, and all agree on `finalized_height` and
   `finalized_transition_hash`.
4. Point the explorer at a seed's lightserver, with the testnet banner on.

## Run a node

A plain node syncs the chain, relays blocks and transactions, and (optionally) serves a public
lightserver and explorer. It needs no keys and no coins. To validate, run a node first, then follow
"Join as a validator" below.

### Linux (Ubuntu/Debian, Fedora, Arch): one command

```bash
git clone https://github.com/FinalisCore/finalis-core.git
cd finalis-core
FINALIS_NETWORK=testnet SERVICE_NAME=finalis-testnet ./scripts/start.sh
```

Run it as your normal user; it calls `sudo` where needed. The script:

1. installs build dependencies and builds the binaries into `build/`,
2. installs and starts the systemd services `finalis-testnet` (node and lightserver) and
   `finalis-testnet-explorer`,
3. opens the P2P and lightserver ports with `ufw` or `firewalld` if one is installed (see "Open
   ports" for cloud firewalls, Oracle images and home routers),
4. connects to the seeds in [SEEDS.json](SEEDS.json) and syncs.

`SERVICE_NAME=finalis-testnet` keeps the service apart from a mainnet node (`finalis`) on the same
machine; the two use different ports and data directories, so both can run side by side.

Optional settings, given the same way (`NAME=value ... ./scripts/start.sh`):

| variable | default | |
|---|---|---|
| `PUBLIC_NODE` | `1` | accept inbound peers on 19540 (`0`: outbound only) |
| `WITH_LIGHTSERVER` | `1` | run the lightserver on 19544 |
| `LIGHTSERVER_BIND` | `0.0.0.0` | `127.0.0.1` keeps the RPC local to this machine |
| `WITH_EXPLORER` | `1` | run the block explorer |
| `EXPLORER_PORT` | `18080` | explorer port |
| `OPEN_FIREWALL_PORTS` | `1` | `0`: leave the firewall alone |
| `INSTALL_DEPS` | `1` | `0`: skip package installation |
| `DB_DIR` | `~/.finalis/testnet` | data directory |
| `RESET_CHAIN_DATA` | `0` | `1`: wipe **all of `~/.finalis`** (every network, mainnet included) except this network's `keystore/validator.json`, then resync. Not for machines that also run mainnet |

Day to day:

```bash
sudo systemctl status finalis-testnet            # running?
sudo journalctl -u finalis-testnet -f            # live log; "testnet h=<height> ... peers=<n>"
sudo systemctl restart finalis-testnet
sudo systemctl stop finalis-testnet finalis-testnet-explorer

# identity and sync state from the local lightserver
curl -s http://127.0.0.1:19544/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_status","params":{}}'
```

`get_status` must report `network_name` `testnet`, `chain_id_ok` `true` and `genesis_hash`
`4faa7e1b…9d0c`; `finalized_height` should match the explorer's.

Update to a new release: `git pull`, then run the same `start.sh` command again; it rebuilds and
restarts the services. Chain data is kept.

### Windows

The installer's `Start-Finalis.ps1` starts mainnet only. For testnet, run the node from the install
folder (default `C:\Program Files\Finalis Core`) in PowerShell:

```powershell
cd "C:\Program Files\Finalis Core"
.\finalis-node.exe --testnet --public --with-lightserver --lightserver-bind 127.0.0.1 `
    --db "$env:APPDATA\.finalis\testnet"
```

Keep the window open (or register it with Task Scheduler "At startup"). Check it with:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:19544/rpc -Method Post `
    -Body '{"jsonrpc":"2.0","id":1,"method":"get_status","params":{}}'
```

### Open ports

| port | | open it when |
|---|---|---|
| 19540/tcp | P2P | always for a public node; other nodes connect to you here |
| 19544/tcp | lightserver RPC | you serve wallets/explorers to others (keep it closed otherwise) |
| 18080/tcp | explorer | you want the explorer reachable from outside |

A node with all ports closed still works: it connects out to the seeds and syncs. Opening 19540 lets
it accept peers and helps the network. Opening a port takes up to three layers, depending on where
the machine runs.

**1. The machine's own firewall.**

```bash
# ufw (Ubuntu, Debian)
sudo ufw allow 19540/tcp
sudo ufw allow 19544/tcp

# firewalld (Fedora, RHEL, Rocky, Alma)
sudo firewall-cmd --permanent --add-port=19540/tcp --add-port=19544/tcp
sudo firewall-cmd --reload
```

Oracle Cloud Ubuntu images use plain iptables with a `REJECT` rule; `ufw` is not active there. The
`ACCEPT` rules must go *above* that `REJECT` line:

```bash
sudo iptables -L INPUT -n --line-numbers                  # note the REJECT line number, e.g. 5
sudo iptables -I INPUT 5 -p tcp --dport 19540 -j ACCEPT
sudo iptables -I INPUT 5 -p tcp --dport 19544 -j ACCEPT
sudo iptables -L INPUT -n --line-numbers                  # REJECT must now be last
sudo netfilter-persistent save                            # keep after reboot
```

Windows (PowerShell as Administrator):

```powershell
New-NetFirewallRule -DisplayName "Finalis testnet P2P" -Direction Inbound -Protocol TCP -LocalPort 19540 -Action Allow
New-NetFirewallRule -DisplayName "Finalis testnet RPC" -Direction Inbound -Protocol TCP -LocalPort 19544 -Action Allow
```

**2. The cloud provider's firewall** (VPS only). Add an inbound rule for TCP 19540 (and 19544 if
public) from `0.0.0.0/0`:

| provider | where |
|---|---|
| Oracle Cloud | Instance → Subnet → Security Lists → Add Ingress Rules (or the instance's NSG) |
| AWS EC2 / Lightsail | Security Group → Inbound rules / Networking → IPv4 Firewall |
| Google Cloud | VPC network → Firewall → Create rule (target: the instance's network tag) |
| Azure | VM → Networking → Add inbound port rule |
| Hetzner, DigitalOcean, Vultr | Firewalls in the console (only if a cloud firewall is attached) |

**3. Your home router** (home connection only). The node asks the router to forward 19540 by itself
over UPnP / NAT-PMP; the log shows `upnp-igd-refresh status=ok` when that worked. If it shows
`status=failed`, forward the port by hand:

1. Give the computer a fixed LAN address (a DHCP reservation in the router, or a static IP).
2. In the router's admin page (often `http://192.168.1.1` or `http://192.168.0.1`), find "Port
   Forwarding" / "Virtual Server" / "NAT".
3. Add: external port 19540, protocol TCP, internal IP = the computer's LAN address, internal port
   19540.
4. If your ISP uses carrier-grade NAT (the router's WAN address starts with `100.64.`–`100.127.`, or
   differs from what https://ifconfig.me shows), forwarding cannot work; run outbound-only
   (`PUBLIC_NODE=0`) or use a VPS.

**Check from another machine.** A machine cannot reliably test its own public address (cloud
providers do not route it back), so test from your laptop or phone hotspot:

```bash
nc -vz <your public IP> 19540      # "succeeded" / "open" = reachable
```

On Windows: `Test-NetConnection <your public IP> -Port 19540`. Or use an online port checker.

### Troubleshooting

| log line | meaning |
|---|---|
| `h=0 ... state=SYNCING` before 2026-10-19 09:00 UTC | normal: no blocks exist before genesis time |
| `peer-connect-failed ... reason=tcp-connect-failed` for a seed | the seed is unreachable from here; check your outbound firewall. A seed dialing its own public IP always logs this |
| `upnp-igd-refresh status=failed` / `nat-pmp-refresh status=failed` | harmless on a VPS; at home, forward 19540 by hand |
| `genesis-fingerprint-mismatch` | the data directory belongs to another chain: `sudo systemctl stop finalis-testnet`, move `~/.finalis/testnet` aside, put back its `keystore/` if you have a validator key, start again |
| `systemctl restart` asks for a password | use `sudo systemctl ...` |

## Join as a validator

1. Run a node with a local lightserver (localhost only; the CLI talks to it) and let it sync. It
   finds the seeds by itself:

   ```bash
   finalis-node --testnet --listen --with-lightserver
   ```

2. Create a validator key on that machine and note its `address` (`tsc1…`):

   ```bash
   finalis-cli --testnet wallet_create --out ~/.finalis/testnet/keystore/validator.json --pass "<passphrase>"
   ```

3. Get testnet FLS to that address: the bond (1,000 to 4,000 FLS, depending on the number of
   validators) plus fees. The maintainer sends it from the bootstrap validator's rewards:

   ```bash
   finalis-cli --testnet send --to <tsc1 address> --amount-units <units> \
       --file <bootstrap validator.json> --pass "<passphrase>" --db <wallet dir>
   ```

   (1 FLS = 100,000,000 units.)

4. Register. This builds the bond and join transactions from the key's own coins and follows them
   to finality:

   ```bash
   finalis-cli --testnet validator-register --file ~/.finalis/testnet/keystore/validator.json --pass "<passphrase>"
   ```

5. Restart the node with the key so it validates:

   ```bash
   finalis-node --testnet --listen --with-lightserver \
       --validator-key-file ~/.finalis/testnet/keystore/validator.json \
       --validator-passphrase-env FINALIS_VALIDATOR_PASSPHRASE
   ```

   The validator becomes active after the 100-block warmup (about 5 hours at 3-minute blocks) and
   joins the committee at the next epoch boundary (every 32 blocks).
