# Privacy Component

This directory holds no code. Confidential transaction support lives in:

- `src/crypto/confidential.*`: Pedersen commitments, range proofs and balance
  proofs (the only wrapper around secp256k1-zkp)
- `src/wallet/confidential_keys.*`: deterministic per-request receive keys
- `src/utxo/confidential_tx.*`: `TxV2` and `AnyTx` encoding
- `src/consensus/confidential_supply.*`: supply accounting
- `src/wallet/confidential_builder.*`: wallet-side transaction building

Specification: [docs/spec/CONFIDENTIAL_UTXO_SPEC.md](../../docs/spec/CONFIDENTIAL_UTXO_SPEC.md).
