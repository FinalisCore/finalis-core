# Genesis Spec

## Genesis JSON schema (`mainnet/genesis.json`)
Fields:
- `version` (u32)
- `network_name` (`"mainnet"`)
- `protocol_version` (u32)
- `network_id_hex` (16-byte hex)
- `magic` (u32)
- `genesis_time_unix` (u64)
- `initial_height` (u64, must be `0`)
- `initial_validators` (array of 32-byte Ed25519 pubkey hex)
- `initial_active_set_size` (u32, must equal validator count)
- `initial_committee_params`: `{min_committee,max_committee,sizing_rule,C}`
- `monetary_params_ref` (string)
- `seeds` (array of `host:port`)
- `note` (string)

## Canonical binary (`genesis.bin`)
Deterministic field order, LE integers, ULEB128 lengths:
1. prefix bytes `"SCGENV1"` (7 bytes)
2. `version` u32le
3. `network_name` varbytes
4. `protocol_version` u32le
5. `network_id` fixed 16 bytes
6. `magic` u32le
7. `genesis_time_unix` u64le
8. `initial_height` u64le
9. validator count varint
10. validators fixed 32 bytes each
11. `initial_active_set_size` u32le
12. `min_committee` u32le
13. `max_committee` u32le
14. `sizing_rule` varbytes
15. `C` u32le
16. `monetary_params_ref` varbytes
17. seed count varint
18. seeds varbytes each
19. `note` varbytes

## Identifiers
- `genesis_hash = sha256d(genesis.bin)`
- `genesis_block_id` is a deterministic bootstrap header id retained for
  genesis compatibility and snapshot anchoring. It is not the live frontier
  consensus identity in frontier mode.
- It is built from genesis data:
  - prev hash = 32 zero bytes
  - height = 0
  - timestamp = `genesis_time_unix`
  - merkle = `sha256d("SC-GENESIS-HDR-V1" || genesis_hash)`
  - leader pubkey = lexicographically smallest initial validator pubkey
  - round = 0
  - block id = normal `sha256d("SC-BLOCK-V0" || header_bytes)`

## Reproducibility
```bash
./build/finalis-cli genesis_build --in mainnet/genesis.json --out mainnet/genesis.bin
./build/finalis-cli genesis_hash --in mainnet/genesis.bin
./build/finalis-cli genesis_verify --json mainnet/genesis.json --bin mainnet/genesis.bin
```
