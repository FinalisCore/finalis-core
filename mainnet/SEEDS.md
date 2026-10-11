# Finalis Mainnet Seeds

Mainnet has not launched, so there are no mainnet seeds. At launch they are published in
[SEEDS.json](SEEDS.json) and compiled into the release (`default_seeds` in
`src/common/network.cpp`); changing them afterwards needs a new release.

Seed requirements:
- P2P endpoints (`host:19440`), not lightserver HTTP (`19444`)
- plain nodes, not validators, so validator addresses stay private
- DNS names where possible, so a seed can move without a release
- at least 2, run by independent operators, with health monitoring

Operator run example:
```bash
./build/finalis-node --public
```

Default data dir: `~/.finalis/mainnet`. Testnet seeds: [../testnet/SEEDS.json](../testnet/SEEDS.json).
