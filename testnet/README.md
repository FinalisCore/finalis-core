# Finalis Testnet

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

## Genesis (testnet-1)

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

testnet-1 is embedded (`genesis_hash` `358d09d637194c673fe85b1fc5a6b06089915793327595c0b6d1b1a12696418b`,
check with `finalis-cli --testnet genesis_print_embedded`), so nodes need no `--genesis` flag.

### 3. Seeds

[SEEDS.json](SEEDS.json): two plain nodes (not validators) on the VPS hosts, so validator
addresses are never published. Each runs:

```bash
finalis-node --testnet --public --with-lightserver --lightserver-bind 0.0.0.0
```

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
