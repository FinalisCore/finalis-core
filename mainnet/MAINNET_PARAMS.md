# Mainnet Parameters

Current fixed-runtime mainnet defaults:
- `network_name`: `mainnet`
- `magic`: `0x499602D2` (`1234567890`)
- `network_id`: explicit runtime constant
- `network_id_hex`: `fe561911730912cced1e83bc273fab13`
- `protocol_version`: `1`
- `feature_flags`: `1` (strict version/network handshake)
- `p2p_default_port`: `19440`
- `lightserver_default_port`: `19444`

Consensus/limits (unchanged rules):
- `MAX_COMMITTEE`: `128`
- `ROUND_TIMEOUT_MS`: `30000`
- `MIN_BLOCK_INTERVAL_MS`: `180000`
- `MAX_PAYLOAD_LEN`: `8 MiB`
- `BOND_AMOUNT`: `5,000,000,000` units
- `WARMUP_BLOCKS`: `100`
- `UNBOND_DELAY_BLOCKS`: `3360` (7 days at 180 s per block; slash evidence can still ban an exiting validator, which forfeits its bond)
- `COMMITTEE_EPOCH_BLOCKS`: finalized-artifact epoch window used for persisted committee snapshots
- hardened networking defaults remain identical to current node defaults.

Monetary alignment note:
- `MIN_BLOCK_INTERVAL_MS = 180000` matches the consensus monetary target of `180` seconds per block.
- This keeps the fixed mainnet emission schedule aligned with the live `12`-year
  declining issuance horizon and deterministic reserve accrual schedule.

Parser/runtime note:
- node, lightserver and CLI default to this mainnet profile; `--testnet` selects the testnet

Alignment rule:
- these values are the mainnet identity and must stay aligned, at launch, with:
  - `mainnet/genesis.json`
  - `mainnet/genesis.bin`
  - `src/genesis/embedded_mainnet.cpp`
