# Finalis Mainnet Seeds

Initial placeholders:
- `212.58.103.170:19440` (temporary raw IP seed)
- `seed1.gotdns.ch:19440` (active dynamic DNS seed)
- `seed1.mainnet.finalis.example:19440`
- `seed2.mainnet.finalis.example:19440`
- format to publish: `seedX.domain:19440`

Operator expectations:
- at least 2 independent organizations
- static DNS + health monitoring
- public uptime targets and incident contact

Operator run example:
```bash
./build/finalis-node --public
```

Default data dir:
- `~/.finalis/mainnet`

Transition note:
- the restarted network is branded as `Finalis` with ticker `FLS`
- binaries now use the `finalis-*` prefix
- old-network peers will correctly fail handshake with
  `genesis-fingerprint-mismatch` and must not be treated as healthy seeds

Port sanity:
- Seeds must be P2P endpoints (`19440`), not lightserver HTTP (`19444`).
- Publish lightservers separately as RPC URLs (`http://host:19444/rpc`).
- Do not place TLS/HTTP reverse proxies in front of the P2P port.
