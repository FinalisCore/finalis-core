# CONFIDENTIAL_UTXO_SPEC

## 1. Scope

This document defines a concrete repository-facing implementation plan for
confidential UTXOs in Finalis Core.

It is not yet a live consensus change. It specifies:

- header and source file layout
- exact C++ struct placement by file
- parser and serializer signatures
- validator pipeline integration points
- mempool scoring and admission changes
- wallet and explorer integration boundaries
- activation-height ownership

This specification is written against the current repository layout:

- [src/utxo/tx.hpp](../../src/utxo/tx.hpp)
- [src/utxo/tx.cpp](../../src/utxo/tx.cpp)
- [src/utxo/validate.hpp](../../src/utxo/validate.hpp)
- [src/utxo/validate.cpp](../../src/utxo/validate.cpp)
- [src/mempool/mempool.hpp](../../src/mempool/mempool.hpp)
- [src/mempool/mempool.cpp](../../src/mempool/mempool.cpp)
- [src/node/node.cpp](../../src/node/node.cpp)
- [apps/finalis-wallet/](../../apps/finalis-wallet/)
- [apps/finalis-explorer/main.cpp](../../apps/finalis-explorer/main.cpp)

The design goal is:

- confidential output amounts
- stealth recipients
- deterministic replay
- bounded validator cost
- no trusted setup

Non-goals for v1:

- sender anonymity
- ring signatures
- nullifier-based shielded pools
- recursive proofs

## 2. New File Layout

### 2.1 Crypto

Add:

- [src/crypto/confidential.hpp](../../src/crypto/confidential.hpp)
- [src/crypto/confidential.cpp](../../src/crypto/confidential.cpp)
- [src/crypto/stealth_address.hpp](../../src/crypto/stealth_address.hpp)
- [src/crypto/stealth_address.cpp](../../src/crypto/stealth_address.cpp)

Do not introduce separate `pedersen.hpp` and `bulletproof.hpp` public entry
points in v1. The consensus-facing code should consume one repository-owned
wrapper API that hides the external proof library boundary and keeps the
consensus interface narrow.

Rationale:

- avoids leaking proof-library details into validation code
- keeps activation- and transcript-relevant rules centralized
- reduces future migration surface if Bulletproof+ replaces Bulletproof

### 2.2 UTXO

Add:

- [src/utxo/confidential_tx.hpp](../../src/utxo/confidential_tx.hpp)
- [src/utxo/confidential_tx.cpp](../../src/utxo/confidential_tx.cpp)

Modify:

- [src/utxo/tx.hpp](../../src/utxo/tx.hpp)
- [src/utxo/tx.cpp](../../src/utxo/tx.cpp)
- [src/utxo/validate.hpp](../../src/utxo/validate.hpp)
- [src/utxo/validate.cpp](../../src/utxo/validate.cpp)
- [src/utxo/signing.hpp](../../src/utxo/signing.hpp)
- [src/utxo/signing.cpp](../../src/utxo/signing.cpp)

### 2.3 Mempool

Modify:

- [src/mempool/mempool.hpp](../../src/mempool/mempool.hpp)
- [src/mempool/mempool.cpp](../../src/mempool/mempool.cpp)

### 2.4 Node / Runtime

Modify:

- [src/node/node.hpp](../../src/node/node.hpp)
- [src/node/node.cpp](../../src/node/node.cpp)
- [src/common/network.hpp](../../src/common/network.hpp)
- [src/common/network.cpp](../../src/common/network.cpp)

### 2.5 Wallet / Explorer

Add:

- [apps/finalis-wallet/confidential_wallet.hpp](../../apps/finalis-wallet/confidential_wallet.hpp)
- [apps/finalis-wallet/confidential_wallet.cpp](../../apps/finalis-wallet/confidential_wallet.cpp)

Modify:

- [apps/finalis-wallet/wallet_store.hpp](../../apps/finalis-wallet/wallet_store.hpp)
- [apps/finalis-wallet/wallet_store.cpp](../../apps/finalis-wallet/wallet_store.cpp)
- [apps/finalis-wallet/widgets/send_page.hpp](../../apps/finalis-wallet/widgets/send_page.hpp)
- [apps/finalis-wallet/widgets/send_page.cpp](../../apps/finalis-wallet/widgets/send_page.cpp)
- [apps/finalis-wallet/widgets/receive_page.hpp](../../apps/finalis-wallet/widgets/receive_page.hpp)
- [apps/finalis-wallet/widgets/receive_page.cpp](../../apps/finalis-wallet/widgets/receive_page.cpp)
- [apps/finalis-explorer/main.cpp](../../apps/finalis-explorer/main.cpp)

### 2.6 Tests

Add:

- [tests/test_confidential_tx.cpp](../../tests/test_confidential_tx.cpp)
- [tests/test_confidential_validation.cpp](../../tests/test_confidential_validation.cpp)
- [tests/test_stealth_address.cpp](../../tests/test_stealth_address.cpp)
- [tests/test_mempool_confidential.cpp](../../tests/test_mempool_confidential.cpp)

Modify:

- [tests/test_codec.cpp](../../tests/test_codec.cpp)
- [tests/test_protocol_scope.cpp](../../tests/test_protocol_scope.cpp)
- [tests/test_frontier_replay.cpp](../../tests/test_frontier_replay.cpp)

## 3. Consensus-Owned Crypto Wrapper

### 3.1 File: `src/crypto/confidential.hpp`

This file owns the consensus-visible cryptographic objects.

```cpp
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "common/types.hpp"

namespace finalis::crypto {

struct Commitment33 {
  std::array<std::uint8_t, 33> bytes{};
  bool operator==(const Commitment33&) const = default;
};

struct ProofBytes {
  Bytes bytes;
  bool operator==(const ProofBytes&) const = default;
};

struct ScanTag {
  std::uint8_t value{0};
  bool operator==(const ScanTag&) const = default;
};

struct Blind32 {
  std::array<std::uint8_t, 32> bytes{};
  bool operator==(const Blind32&) const = default;
};

struct ConfidentialOutputSecrets {
  std::uint64_t amount{0};
  Blind32 value_blind{};
};

bool confidential_crypto_init();
bool commitment_is_canonical(const Commitment33& commitment);
Commitment33 transparent_amount_commitment(std::uint64_t amount);
std::optional<Commitment33> add_commitments(std::span<const Commitment33> commitments);
std::optional<Commitment33> subtract_commitments(const Commitment33& lhs, const Commitment33& rhs);

bool verify_output_range_proof(const Commitment33& commitment, const ProofBytes& proof);
bool verify_output_range_proofs_batch(std::span<const Commitment33> commitments,
                                      std::span<const ProofBytes> proofs);

std::size_t range_proof_verify_weight(const ProofBytes& proof);

}  // namespace finalis::crypto
```

### 3.2 File: `src/crypto/stealth_address.hpp`

```cpp
#pragma once

#include <array>
#include <optional>

#include "common/types.hpp"

namespace finalis::crypto {

struct StealthAddress {
  PubKey33 view_pubkey{};
  PubKey33 spend_pubkey{};
  bool operator==(const StealthAddress&) const = default;
};

struct StealthScanResult {
  PubKey33 one_time_pubkey{};
  bool mine{false};
};

bool stealth_address_is_canonical(const StealthAddress& addr);
std::optional<StealthScanResult> scan_stealth_output(const PubKey33& ephemeral_pubkey,
                                                     std::uint8_t scan_tag,
                                                     const Bytes& wallet_view_key_material);

}  // namespace finalis::crypto
```

Implementation note:

- `PubKey33` does not exist today. Add it in [common/types.hpp](../../src/common/types.hpp)
  as a compressed secp256k1 point type.
- `PubKey32` must remain untouched because it is already consensus-critical in
  validator/finality code.

## 4. Transaction Types

The current live type [Tx](../../src/utxo/tx.hpp) is v1-only and must remain
byte-stable.

Do not mutate `Tx` into a variant container. That would create unnecessary
risk in existing parser, txid, explorer, mempool, and ingress paths.

Instead:

- keep `Tx` as the transparent v1 object
- add a new v2 object alongside it
- add a small discriminated wrapper for generic parsing where needed

### 4.1 File: `src/utxo/confidential_tx.hpp`

```cpp
#pragma once

#include <optional>
#include <variant>

#include "crypto/confidential.hpp"
#include "crypto/stealth_address.hpp"
#include "utxo/tx.hpp"

namespace finalis {

enum class TxVersionKind : std::uint32_t {
  TRANSPARENT_V1 = 1,
  CONFIDENTIAL_V2 = 2,
};

enum class TxInputKind : std::uint8_t {
  TRANSPARENT = 0,
  CONFIDENTIAL = 1,
};

enum class TxOutputKind : std::uint8_t {
  TRANSPARENT = 0,
  CONFIDENTIAL = 1,
};

struct TransparentInputWitnessV2 {
  Bytes script_sig;
  bool operator==(const TransparentInputWitnessV2&) const = default;
};

struct ConfidentialInputWitnessV2 {
  PubKey33 one_time_pubkey{};
  Sig64 spend_sig{};
  bool operator==(const ConfidentialInputWitnessV2&) const = default;
};

struct TxInV2 {
  Hash32 prev_txid{};
  std::uint32_t prev_index{0};
  std::uint32_t sequence{0xFFFFFFFF};
  TxInputKind kind{TxInputKind::TRANSPARENT};
  std::variant<TransparentInputWitnessV2, ConfidentialInputWitnessV2> witness;
  bool operator==(const TxInV2&) const = default;
};

struct TransparentTxOutV2 {
  std::uint64_t value{0};
  Bytes script_pubkey;
  bool operator==(const TransparentTxOutV2&) const = default;
};

struct ConfidentialTxOutV2 {
  crypto::Commitment33 value_commitment{};
  PubKey33 one_time_pubkey{};
  PubKey33 ephemeral_pubkey{};
  crypto::ScanTag scan_tag{};
  crypto::ProofBytes range_proof;
  Bytes memo;
  bool operator==(const ConfidentialTxOutV2&) const = default;
};

struct TxOutV2 {
  TxOutputKind kind{TxOutputKind::TRANSPARENT};
  std::variant<TransparentTxOutV2, ConfidentialTxOutV2> body;
  bool operator==(const TxOutV2&) const = default;
};

struct TxBalanceProofV2 {
  crypto::Commitment33 excess_commitment{};
  Sig64 excess_sig{};
  bool operator==(const TxBalanceProofV2&) const = default;
};

struct TxV2 {
  std::uint32_t version{2};
  std::vector<TxInV2> inputs;
  std::vector<TxOutV2> outputs;
  std::uint32_t lock_time{0};
  std::uint64_t fee{0};
  TxBalanceProofV2 balance_proof;

  Bytes serialize() const;
  static std::optional<TxV2> parse(const Bytes& b);
  Hash32 txid() const;
};

using AnyTx = std::variant<Tx, TxV2>;

std::optional<AnyTx> parse_any_tx(const Bytes& b);
Bytes serialize_any_tx(const AnyTx& tx);
Hash32 txid_any(const AnyTx& tx);

}  // namespace finalis
```

### 4.2 Why `AnyTx` Exists

Current code assumes:

- `Tx::parse(raw)`
- `tx.serialize()`
- `tx.txid()`

That is too widespread to replace in one unsafe patch.

`AnyTx` gives a narrow migration seam for:

- node ingress
- finalized frontier replay
- explorer rendering
- wallet send/receive code

while preserving legacy `Tx` handling intact.

## 5. Parser and Serializer Signatures

### 5.1 Existing Files To Modify

#### `src/utxo/tx.hpp`

Add:

```cpp
struct PubKey33 {
  std::array<std::uint8_t, 33> bytes{};
  bool operator==(const PubKey33&) const = default;
};
```

Do not add confidential parsing to `Tx::parse`.
Keep:

```cpp
static std::optional<Tx> parse(const Bytes& b);
```

strictly v1.

#### `src/utxo/tx.cpp`

No behavioral change to `Tx::parse` except:

- reject `version == 2` in the v1 parser
- keep `Tx::txid()` semantics unchanged for v1

#### `src/utxo/confidential_tx.cpp`

Implement:

```cpp
Bytes TxV2::serialize() const;
std::optional<TxV2> TxV2::parse(const Bytes& b);
Hash32 TxV2::txid() const;

std::optional<AnyTx> parse_any_tx(const Bytes& b);
Bytes serialize_any_tx(const AnyTx& tx);
Hash32 txid_any(const AnyTx& tx);
```

### 5.2 Exact Encoding Rules

`TxV2` wire encoding:

```text
u32 version
varint input_count
repeat input_count:
  bytes32 prev_txid
  u32 prev_index
  u32 sequence
  u8 input_kind
  if transparent:
    varbytes script_sig
  if confidential:
    bytes33 one_time_pubkey
    bytes64 spend_sig
varint output_count
repeat output_count:
  u8 output_kind
  if transparent:
    u64 value
    varbytes script_pubkey
  if confidential:
    bytes33 value_commitment
    bytes33 one_time_pubkey
    bytes33 ephemeral_pubkey
    u8 scan_tag
    varbytes range_proof
    varbytes memo
u32 lock_time
u64 fee
bytes33 excess_commitment
bytes64 excess_sig
```

Consensus parser rules:

- no trailing bytes
- all tags must be recognized
- all compressed points must parse successfully under the chosen curve library
- all lengths bounded by consensus constants

## 6. UTXO Set Changes

Current code uses `UtxoEntry{TxOut out}` semantics through
[utxo/validate.hpp](../../src/utxo/validate.hpp) and related code paths.

This must expand into an output-kind-aware UTXO record.

### 6.1 New Structs

In [src/utxo/validate.hpp](../../src/utxo/validate.hpp):

```cpp
enum class UtxoOutputKind : std::uint8_t {
  TRANSPARENT = 0,
  CONFIDENTIAL = 1,
};

struct UtxoTransparentData {
  TxOut out;
  bool operator==(const UtxoTransparentData&) const = default;
};

struct UtxoConfidentialData {
  crypto::Commitment33 value_commitment{};
  PubKey33 one_time_pubkey{};
  PubKey33 ephemeral_pubkey{};
  crypto::ScanTag scan_tag{};
  Bytes memo;
  bool operator==(const UtxoConfidentialData&) const = default;
};

struct UtxoEntryV2 {
  UtxoOutputKind kind{UtxoOutputKind::TRANSPARENT};
  std::variant<UtxoTransparentData, UtxoConfidentialData> body;
  bool operator==(const UtxoEntryV2&) const = default;
};

using UtxoSetV2 = std::map<OutPoint, UtxoEntryV2>;
```

Migration rule:

- keep legacy `UtxoSet` type during the first patch only if necessary
- otherwise replace it directly and add helper accessors

Preferred helper API:

```cpp
bool utxo_is_transparent(const UtxoEntryV2& e);
bool utxo_is_confidential(const UtxoEntryV2& e);
const TxOut* utxo_transparent_out(const UtxoEntryV2& e);
const UtxoConfidentialData* utxo_confidential_out(const UtxoEntryV2& e);
```

## 7. Validation API Changes

### 7.1 `src/utxo/validate.hpp`

Add:

```cpp
struct ConfidentialPolicy {
  std::uint64_t activation_height{std::numeric_limits<std::uint64_t>::max()};
  std::uint32_t max_inputs_per_tx{64};
  std::uint32_t max_outputs_per_tx{32};
  std::uint32_t max_confidential_inputs_per_tx{16};
  std::uint32_t max_confidential_outputs_per_tx{16};
  std::uint32_t max_memo_bytes{128};
  std::uint32_t max_range_proof_bytes{1024};
  std::uint32_t max_total_proof_bytes_per_tx{16384};
  std::uint64_t max_fee{MAX_MONEY};
  std::uint64_t max_block_confidential_verify_weight{2'000'000};
};

struct TxValidationCost {
  std::uint64_t fee{0};
  std::uint64_t confidential_verify_weight{0};
  std::size_t serialized_size{0};
};

struct AnyTxValidationResult {
  bool ok{false};
  std::string error;
  TxValidationCost cost;
};

AnyTxValidationResult validate_any_tx(const AnyTx& tx, size_t tx_index_in_block, const UtxoSetV2& utxos,
                                      const SpecialValidationContext* ctx = nullptr);
AnyTxValidationResult validate_tx_v2(const TxV2& tx, size_t tx_index_in_block, const UtxoSetV2& utxos,
                                     const SpecialValidationContext* ctx = nullptr);
void apply_any_tx_to_utxo(const AnyTx& tx, UtxoSetV2& utxos);
```

Extend `SpecialValidationContext`:

```cpp
const ConfidentialPolicy* confidential_policy{nullptr};
```

### 7.2 Validation Pipeline Integration

Modify [src/utxo/validate.cpp](../../src/utxo/validate.cpp):

- keep `validate_tx(const Tx&, ...)` as the strict v1 implementation
- add `validate_tx_v2(const TxV2&, ...)`
- add `validate_any_tx(const AnyTx&, ...)`

`validate_tx_v2` must perform, in order:

1. activation-height check
2. shape bounds
3. canonical point/proof length prechecks
4. input existence and kind match
5. transparent witness checks
6. confidential witness checks
7. range proof verification
8. commitment balance verification
9. fee and verify-weight accounting

## 8. Node Pipeline Integration Points

### 8.1 Current Entry Points

Current node path in [src/node/node.cpp](../../src/node/node.cpp):

- `handle_tx_msg`
- mempool admission via `mempool_.accept_tx(tx, utxos_, ...)`
- finalized frontier ordered record parsing via `Tx::parse(raw)`

### 8.2 Required Changes

Replace:

```cpp
auto tx = Tx::parse(raw);
```

with:

```cpp
auto tx = parse_any_tx(raw);
```

in:

- inbound p2p tx handling
- lightserver submission handling
- explorer tx decoding paths
- finalized frontier ordered record replay paths where transactions are decoded

Update stored transaction bytes:

- storage stays raw-bytes-based
- no DB schema change is required for raw tx storage
- parsing becomes version-aware at read time

### 8.3 Current Critical Locations

Patch these specific seams first:

- [src/node/node.cpp:3351](../../src/node/node.cpp)
- [src/node/node.cpp:3406](../../src/node/node.cpp)
- [src/node/node.cpp:5413](../../src/node/node.cpp)
- [src/node/node.cpp:6763](../../src/node/node.cpp)
- [src/lightserver/server.cpp:322](../../src/lightserver/server.cpp)
- [src/lightserver/server.cpp:339](../../src/lightserver/server.cpp)
- [src/lightserver/server.cpp:489](../../src/lightserver/server.cpp)
- [src/lightserver/server.cpp:2680](../../src/lightserver/server.cpp)
- [apps/finalis-explorer/main.cpp:1662](../../apps/finalis-explorer/main.cpp)

These are the places currently assuming `Tx::parse`.

## 9. Mempool Scoring Patch Plan

Current mempool admission and eviction are fee-per-byte only.

That is insufficient for confidential transactions because proof verification
cost is not proportional to raw size alone.

### 9.1 `src/mempool/mempool.hpp`

Extend `MempoolEntry`:

```cpp
struct MempoolEntry {
  AnyTx tx;
  Hash32 txid;
  std::uint64_t fee{0};
  std::size_t size_bytes{0};
  std::uint64_t confidential_verify_weight{0};
  std::uint64_t mempool_score_weight{0};
};
```

Add to `MempoolPolicyStats`:

```cpp
std::optional<double> min_score_rate_to_enter_when_full;
std::uint64_t total_confidential_verify_weight{0};
```

Add pool-wide limit:

```cpp
static constexpr std::uint64_t kMaxPoolConfidentialVerifyWeight = 20'000'000;
```

### 9.2 Scoring Formula

Define:

```cpp
mempool_score_weight(tx) =
    serialized_size
  + (32 * confidential_input_count)
  + (64 * confidential_output_count)
  + (4 * total_range_proof_bytes)
  + confidential_verify_weight;
```

Define score rate:

```cpp
score_rate = fee / max<uint64_t>(1, mempool_score_weight)
```

Use score rate, not pure byte rate, in:

- admission replacement checks
- eviction ordering
- block template selection preference

### 9.3 `src/mempool/mempool.cpp`

Replace:

- `compare_fee_rate(...)`

with:

- `compare_score_rate(fee_a, weight_a, fee_b, weight_b)`

Update:

- `compare_entry_score`
- `EvictionKey`
- `meets_full_replacement_margin`

Admission rules:

1. parse `AnyTx`
2. validate via `validate_any_tx`
3. reject if pool-wide confidential verify weight would exceed cap
4. score and evict based on score weight

### 9.4 Block Selection

Current selection path:

```cpp
select_for_block(std::size_t max_txs, std::size_t max_bytes, const UtxoView& view, ...)
```

Change to:

```cpp
select_for_block(std::size_t max_txs, std::size_t max_bytes,
                 std::uint64_t max_confidential_verify_weight,
                 const UtxoSetV2& view, ...)
```

Track:

- cumulative serialized bytes
- cumulative confidential verify weight

Skip any tx that would overflow either bound.

## 10. Wallet Patch Plan

### 10.1 New Wallet State

In [apps/finalis-wallet/wallet_store.hpp](../../apps/finalis-wallet/wallet_store.hpp):

```cpp
struct WalletConfidentialCoin {
  OutPoint outpoint;
  crypto::Commitment33 value_commitment{};
  PubKey33 one_time_pubkey{};
  PubKey33 ephemeral_pubkey{};
  crypto::ScanTag scan_tag{};
  std::uint64_t amount{0};
  crypto::Blind32 value_blind{};
  bool spent{false};
};
```

Add:

```cpp
std::vector<WalletConfidentialCoin> confidential_coins_;
Bytes view_key_material_;
Bytes spend_key_material_;
```

### 10.2 New Wallet API

In [apps/finalis-wallet/confidential_wallet.hpp](../../apps/finalis-wallet/confidential_wallet.hpp):

```cpp
class ConfidentialWallet {
 public:
  bool init_from_seed(const Bytes& seed);
  std::optional<crypto::StealthAddress> default_stealth_address() const;
  bool scan_tx(const AnyTx& tx, const Hash32& txid);
  std::optional<TxV2> build_private_send(const crypto::StealthAddress& to, std::uint64_t amount,
                                         std::uint64_t fee);
};
```

This is intentionally separate from the existing transparent send path.

### 10.3 UI Changes

Receive page:

- show stealth receive address
- add copy/export view key flow

Send page:

- add output mode selector:
  - transparent
  - confidential

Do not mix transparent and confidential send UX in one hidden checkbox.
Make the privacy mode explicit.

## 11. Explorer Patch Plan

In [apps/finalis-explorer/main.cpp](../../apps/finalis-explorer/main.cpp):

Replace tx decoding with `parse_any_tx`.

Display policy:

- transparent output:
  - show value and script type
- confidential output:
  - show `type=confidential`
  - show commitment
  - show memo length
  - never show amount

Add tx summary fields:

- `confidential_inputs`
- `confidential_outputs`
- `range_proof_bytes`
- `verify_weight`

Explorer must remain finalized-only.

## 12. Network and Activation

In [src/common/network.hpp](../../src/common/network.hpp), add:

```cpp
struct ConfidentialPolicy {
  std::uint64_t activation_height{std::numeric_limits<std::uint64_t>::max()};
  std::uint32_t max_inputs_per_tx{64};
  std::uint32_t max_outputs_per_tx{32};
  std::uint32_t max_confidential_inputs_per_tx{16};
  std::uint32_t max_confidential_outputs_per_tx{16};
  std::uint32_t max_memo_bytes{128};
  std::uint32_t max_range_proof_bytes{1024};
  std::uint32_t max_total_proof_bytes_per_tx{16384};
  std::uint64_t max_fee{MAX_MONEY};
  std::uint64_t max_block_confidential_verify_weight{2'000'000};
};
```

And in `NetworkConfig`:

```cpp
ConfidentialPolicy confidential_policy{};
```

Activation rule:

- `TxV2` is invalid if `height < confidential_policy.activation_height`

This must be replay-stable and fail closed.

## 13. Minimal Implementation Order

Implement in this order:

1. add `PubKey33` and crypto wrapper files
2. add `TxV2`, `AnyTx`, and parsing/serialization
3. add `UtxoEntryV2`
4. add `validate_tx_v2` and `validate_any_tx`
5. update node/lightserver/explorer parsing to `parse_any_tx`
6. update mempool scoring and verify-weight limits
7. add wallet confidential receive/send support
8. add activation height
9. add block-level confidential verify-weight enforcement

Do not invert this order. In particular:

- do not land wallet UX before parser and validator support
- do not land mempool support before a consensus verify-weight model exists
- do not activate before replay and codec tests are complete

## 14. Required Tests

Minimum acceptance tests:

- codec roundtrip for `TxV2`
- parser rejects malformed tags and overlong proofs
- v1 parser remains byte-stable
- `AnyTx` dispatches correctly
- balance equation rejects inflation
- range-proof batch verification determinism
- mempool score replacement favors higher confidential score-rate, not raw fee-per-byte
- pre-activation `TxV2` rejection
- post-activation `TxV2` acceptance
- replay of old history unchanged when no `TxV2` exists

## 15. Security Notes

Hard constraints:

- no bespoke Bulletproof math in consensus code
- no mixed-curve stealth construction
- no witness design that reveals confidential output blinds on-chain
- no parser ambiguity between v1 and v2
- no unbounded proof verification path in mempool or block validation

Finalis-specific requirement:

every confidential validation rule must be replay-equivalent under finalized
frontier derivation. No wallet-side convenience rule may leak into consensus.
