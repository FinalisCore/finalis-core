# Mainnet Parameters

Current fixed-runtime mainnet defaults:
- `network_name`: `mainnet`
- `magic`: `0x9797412A` (`2543272234`)
- `network_id`: explicit runtime constant
- `network_id_hex`: `258038c123a1c9b08475216e5f53a503`
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
- `UNBOND_DELAY_BLOCKS`: `100`
- `COMMITTEE_EPOCH_BLOCKS`: finalized-artifact epoch window used for persisted committee snapshots
- hardened networking defaults remain identical to current node defaults.

Monetary alignment note:
- `MIN_BLOCK_INTERVAL_MS = 180000` matches the consensus monetary target of `180` seconds per block.
- This keeps the fixed mainnet emission schedule aligned with the live `12`-year
  declining issuance horizon and deterministic reserve accrual schedule.

Parser/runtime note:
- the current node and lightserver parsers already default to this mainnet profile
- `--mainnet` is not needed for the node in this build

Fresh-genesis note:
- these values are the current post-reset mainnet identity and must stay aligned
  with:
  - `mainnet/genesis.json`
  - `mainnet/genesis.bin`
  - `src/genesis/embedded_mainnet.cpp`
