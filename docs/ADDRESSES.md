# Addresses, Keys, And Script Identity

This document describes the live `finalis-core` key and address model.

It is intentionally practical:

- what a private key is in this codebase
- how a public key is derived
- how an address is generated
- what cryptographic primitives are used
- what script/address types are currently live

## 1. Private Key

In the live codebase, a wallet / validator private key is an Ed25519 raw
32-byte private seed.

Current implementation:

- [src/crypto/ed25519.hpp](/home/greendragon/Desktop/selfcoin-core-clean/src/crypto/ed25519.hpp)
- [src/crypto/ed25519.cpp](/home/greendragon/Desktop/selfcoin-core-clean/src/crypto/ed25519.cpp)

Important detail:

- the code stores and signs with the raw 32-byte Ed25519 private input
- it is not a WIF string
- it is not a secp256k1 scalar
- it is not a BIP32/BIP39 HD wallet path

So, in `finalis-core`, a “private key” means:

```text
Ed25519 raw private key material, 32 bytes
```

## 2. Public Key

The public key is the 32-byte Ed25519 raw public key derived from that private
seed.

Live type:

```text
PubKey32 = bytes[32]
```

The live keypair flow is:

```text
private_key_32 -> Ed25519 keypair -> public_key_32
```

## 3. Signature Technology

The live signature primitive is:

```text
Ed25519
```

Used for:

- transaction signatures
- vote signatures
- proposal signatures
- validator join proof-of-possession
- availability/BPoAR operator-signed records where applicable

The implementation uses OpenSSL Ed25519 raw-key APIs.

## 4. Address Type

The currently live user-facing address type is:

```text
P2PKH
```

That means the address identifies:

```text
HASH160(pubkey)
```

where:

```text
HASH160(x) = RIPEMD160(SHA256(x))
```

Current hash helpers:

- [src/crypto/hash.hpp](/home/greendragon/Desktop/selfcoin-core-clean/src/crypto/hash.hpp)
- [src/crypto/hash.cpp](/home/greendragon/Desktop/selfcoin-core-clean/src/crypto/hash.cpp)

## 5. Address Derivation

The live address derivation path is:

```text
private_key_32
  -> public_key_32
  -> pubkey_hash_20 = HASH160(public_key_32)
  -> address = encode_p2pkh(hrp, pubkey_hash_20)
```

This is exactly how the validator keystore and CLI derive addresses.

## 6. Human-Readable Prefix

The current supported address HRPs are:

- `sc` for mainnet-style addresses
- `tsc` for test/dev-style addresses

Any other HRP is currently rejected by the live address encoder/validator.

## 7. Address Encoding Format

The live address format is a custom Bech32-like text form, but it is not
standard SegWit Bech32.

Structure:

```text
<hrp> "1" <base32(data)>
```

where `data` is:

```text
payload || checksum[0..3]
```

and:

```text
payload = addr_type_byte || pubkey_hash_20
```

Current live values:

- `addr_type_byte = 0x00` for P2PKH
- `payload` length = 21 bytes
- checksum length = 4 bytes
- total pre-base32 data length = 25 bytes

The base32 alphabet is:

```text
abcdefghijklmnopqrstuvwxyz234567
```

Important boundary:

- this is not Bitcoin Base58Check
- this is not standard Bech32 witness-version encoding
- integrators should use the repository encoder/validator rather than assuming
  compatibility with external wallet libraries

## 8. Checksum

The live address checksum is:

```text
checksum = first_4_bytes( SHA256d( hrp || 0x00 || payload ) )
```

where:

```text
SHA256d(x) = SHA256(SHA256(x))
```

So checksum verification is deterministic and tied to both:

- the HRP
- the payload bytes

## 9. Current ScriptPubKey

The live P2PKH output script is:

```text
OP_DUP
OP_HASH160
PUSH20 <pubkey_hash_20>
OP_EQUALVERIFY
OP_CHECKSIG
```

Byte form:

```text
76 a9 14 <20-byte pubkey hash> 88 ac
```

Current helper:

- [src/address/address.cpp](/home/greendragon/Desktop/selfcoin-core-clean/src/address/address.cpp)

## 10. What Exchanges / Wallets Should Rely On

Exchanges and wallet integrations should rely on:

- `validate_address`
- `normalized_address`
- `script_pubkey_hex`
- `scripthash_hex`

from the live lightserver surface.

Do not reimplement address parsing with generic assumptions if you can avoid it.

The correct integration rule is:

```text
address string
  -> validate_address
  -> normalized_address + script_pubkey_hex + scripthash_hex
```

## 11. `scripthash_hex`

The lightserver uses `scripthash_hex` for history and UTXO lookups.

Current live derivation is:

```text
scripthash_hex = SHA256(script_pubkey)
```

This is what exchanges should use with:

- `get_history_page`
- `get_utxos`

## 12. What Is Not In The Live Address Model

The current live model does not provide:

- Base58 legacy addresses
- secp256k1 account addresses
- EVM-style `keccak(pubkey)` addresses
- HD derivation standardization in the protocol itself
- multisig address encoding
- Taproot / SegWit witness versioning

There are other script forms in the chain for validator registration and mint
flows, but ordinary user-facing addresses are currently P2PKH only.

## 13. Security Notes

Private keys:

- must be treated as raw signing authority
- are sufficient to spend ordinary P2PKH outputs controlled by that key
- also matter for validator/operator actions where the same key material is used

Operationally:

- never expose raw private key bytes in logs
- never assume a generic wallet import/export format is compatible
- always normalize and validate addresses before use
- always derive exchange or operator wallet history from finalized
  `scripthash_hex` lookups, not from string comparison alone

## 14. Practical Summary

Live `finalis-core` address identity is:

```text
Ed25519 keypair
-> HASH160(pubkey)
-> custom hrp + separator + base32(payload || 4-byte sha256d checksum)
-> P2PKH script
```

If you need to integrate safely:

- generate Ed25519 keys
- derive address from `HASH160(pubkey)`
- validate with live RPC
- use `script_pubkey_hex` / `scripthash_hex` for finalized accounting
