// SPDX-License-Identifier: MIT

#pragma once

#include <functional>
#include <limits>
#include <optional>
#include <string>

#include "common/network.hpp"
#include "consensus/monetary.hpp"
#include "consensus/validator_registry.hpp"
#include "utxo/confidential_tx.hpp"
#include "utxo/tx.hpp"

namespace finalis {

struct ChainId;

struct TxValidationResult {
  bool ok{false};
  std::string error;
  std::uint64_t fee{0};
};

struct SpecialValidationContext {
  const NetworkConfig* network{nullptr};
  const ChainId* chain_id{nullptr};
  const consensus::ValidatorRegistry* validators{nullptr};
  std::uint64_t current_height{0};
  bool enforce_variable_bond_range{false};
  std::uint64_t min_bond_amount{BOND_AMOUNT};
  std::uint64_t max_bond_amount{BOND_AMOUNT};
  std::uint64_t unbond_delay_blocks{UNBOND_DELAY_BLOCKS};
  std::function<bool(const PubKey32&, std::uint64_t, std::uint32_t)> is_committee_member;
  // Height-indexed finalized identity witness. This remains generic because the
  // anchor may come from legacy block history or frontier transition history.
  std::function<std::optional<Hash32>(std::uint64_t)> finalized_hash_at_height;
  const struct ConfidentialPolicy* confidential_policy{nullptr};
  // True while (validator pubkey, height) holds a bond a pending long time lock names
  // (consensus::timed_bond_lien): the bond cannot be withdrawn yet. Unset: no lien.
  std::function<bool(const PubKey32&, std::uint64_t)> timed_bond_lien;
};

struct SlashEvidence {
  SlashVoteKind kind{SlashVoteKind::Precommit};
  Vote a;
  Vote b;
  Bytes raw_blob;
};

inline constexpr std::size_t kMaxTxInputs = 512;
inline constexpr std::size_t kMaxTxEd25519Verifies = 1024;
// A BLS proof-of-possession check (two pairings) in units of the Ed25519 verify budget.
inline constexpr std::size_t kBlsPopVerifyCost = 32;

TxValidationResult validate_tx(const Tx& tx, size_t tx_index_in_block, const UtxoSet& utxos,
                               const SpecialValidationContext* ctx = nullptr);
// Transaction signatures cover the chain domain (consensus_chain_domain: network id and genesis
// hash), like consensus signatures, so a transaction signed for one network is invalid on every other
// one even when it spends an outpoint that exists on both (genesis bonds).
std::optional<Bytes> signing_message_for_input(const Hash32& chain_domain, const Tx& tx, std::uint32_t input_index);
std::optional<Bytes> signing_message_for_input_v2(const Hash32& chain_domain, const TxV2& tx,
                                                  std::uint32_t input_index);
std::optional<Hash32> balance_proof_message_v2(const Hash32& chain_domain, const TxV2& tx);
std::optional<Bytes> unbond_message_for_input(const Hash32& chain_domain, const Tx& tx, std::uint32_t input_index);
// The fee input's signature of a TxTimed: covers every field (the SWE ciphertext, proof and the
// sealed body included) except the script_sig itself.
Bytes signing_message_for_timed_fee_input(const Hash32& chain_domain, const TxTimed& tx);
// The chain domain transaction signatures are checked under; empty when ctx lacks chain identity.
std::optional<Hash32> tx_chain_domain(const SpecialValidationContext* ctx);
// The Ed25519 proof of a registration covers the validator's BLS key: a script that pairs a
// validator with someone else's BLS key does not verify.
Bytes onboarding_registration_pop_message(const PubKey32& validator_pubkey, const PubKey32& payout_pubkey,
                                          const crypto::BlsPublicKey& bls_pubkey);
Bytes validator_join_request_pop_message(const PubKey32& validator_pubkey, const PubKey32& payout_pubkey,
                                         const crypto::BlsPublicKey& bls_pubkey);
Hash32 admission_pow_chain_id_hash(const ChainId& chain_id);
Hash32 onboarding_registration_commitment(const PubKey32& validator_pubkey, const PubKey32& payout_pubkey);
Hash32 join_request_input_commitment(const std::vector<OutPoint>& inputs);
Hash32 bond_commitment_for_join_request(const PubKey32& operator_id, const PubKey32& payout_pubkey,
                                        std::uint64_t bond_amount, const std::vector<OutPoint>& inputs);
std::uint64_t admission_pow_epoch_for_height(std::uint64_t height, std::uint64_t epoch_blocks);
std::optional<Hash32> admission_pow_epoch_anchor_hash(std::uint64_t admission_pow_epoch, std::uint64_t epoch_blocks,
                                                      const std::function<std::optional<Hash32>(std::uint64_t)>&
                                                          finalized_hash_at_height);
Hash32 admission_pow_challenge(const Hash32& chain_id_hash, std::uint64_t admission_pow_epoch,
                               const Hash32& finalized_epoch_anchor_hash, const PubKey32& operator_id,
                               const Hash32& bond_commitment);
Hash32 admission_pow_work_hash(const Hash32& challenge, std::uint64_t nonce);
std::uint32_t leading_zero_bits(const Hash32& hash);
bool validate_admission_pow(const ValidatorJoinRequestScriptData& req, const std::vector<OutPoint>& inputs,
                            std::uint64_t bond_amount, const SpecialValidationContext& ctx, std::string* err = nullptr);
bool validate_onboarding_admission_pow(const OnboardingRegistrationScriptData& req, const SpecialValidationContext& ctx,
                                       std::string* err = nullptr);
// Every consensus signature covers the chain domain sha256d("SC-CHAIN-DOMAIN-V1" || network_id ||
// genesis_hash). A key reused on another network (testnet, a devnet) signs different bytes there, so
// its votes can neither be replayed onto this chain nor used as slash evidence on it.
Hash32 consensus_chain_domain(const NetworkConfig& network, const ChainId& chain_id);
Hash32 chain_domain_from_ids(const std::array<std::uint8_t, 16>& network_id, const Hash32& genesis_hash);
// From the hex ids a lightserver reports (get_status network_id, genesis_hash); empty if malformed.
std::optional<Hash32> chain_domain_from_hex(const std::string& network_id_hex, const std::string& genesis_hash_hex);
// Precommit: a quorum of these for one (height, round, transition_id) is finality.
Bytes vote_signing_message(const Hash32& chain_domain, std::uint64_t height, std::uint32_t round,
                           const Hash32& transition_id);
// Prevote: a quorum of these (a polka) lets a validator lock on transition_id and precommit it.
Bytes prevote_signing_message(const Hash32& chain_domain, std::uint64_t height, std::uint32_t round,
                              const Hash32& transition_id);
// Signed by the leader of (height, round). pol_round is the round of the attached prevote quorum
// when the leader re-proposes its valid value.
Bytes propose_signing_message(const Hash32& chain_domain, std::uint64_t height, std::uint32_t round,
                              const Hash32& transition_id, std::optional<std::uint32_t> pol_round);
Bytes timeout_vote_signing_message(const Hash32& chain_domain, std::uint64_t height, std::uint32_t round);
// The McFly time-signature message T of a height: what every committee member signs with its BLS key
// (crypto::kBlsTimeSignatureDst) once it holds that height's finality certificate, and what a
// TxTimed with that unlock_height is SWE-encrypted to. No round or transition: it must be known in
// advance.
Bytes time_signature_message(const Hash32& chain_domain, std::uint64_t height);
bool is_p2pkh_script_pubkey(const Bytes& script_pubkey, std::array<std::uint8_t, 20>* out_hash = nullptr);
bool is_p2pkh_script_sig(const Bytes& script_sig, Sig64* out_sig = nullptr, PubKey32* out_pub = nullptr);
bool is_supported_base_layer_output_script(const Bytes& script_pubkey);

// --- Height-locked outputs (transparent, Tx v1) ---
//
// SCHLOCK1 "locked":      "SCHLOCK1" | u64le unlock_height | pkh(20)
//   spendable by pkh in a block at height >= unlock_height.
// SCHLOCK2 "inheritance": "SCHLOCK2" | u64le unlock_height | owner_pkh(20) | heir_pkh(20)
//   spendable by the owner at any height, and by the heir at height >= unlock_height.
// The script_sig is the P2PKH one (sig, pubkey) and signs signing_message_for_input. The rule needs
// nothing but the block height, so a lock holds for any horizon whoever validates then.
inline constexpr std::size_t kHeightLockScriptBytes = 8 + 8 + 20;
inline constexpr std::size_t kInheritanceLockScriptBytes = 8 + 8 + 20 + 20;
struct HeightLockScript {
  std::uint64_t unlock_height{0};
  std::array<std::uint8_t, 20> beneficiary_pkh{};        // spends from unlock_height
  std::optional<std::array<std::uint8_t, 20>> owner_pkh;  // inheritance form: spends at any height
};
std::optional<HeightLockScript> parse_height_lock_script(const Bytes& script_pubkey);
Bytes height_lock_script_pubkey(std::uint64_t unlock_height, const std::array<std::uint8_t, 20>& pkh);
Bytes inheritance_lock_script_pubkey(std::uint64_t unlock_height, const std::array<std::uint8_t, 20>& owner_pkh,
                                     const std::array<std::uint8_t, 20>& heir_pkh);
// --- Data outputs ---
//
// SCDATA01: "SCDATA01" | data (1..kDataOutputMaxBytes bytes). Value 0, never spendable: it is not
// added to the UTXO set, only to address history. Indexed under sha256(script_pubkey) and, when the
// data is longer than kDataOutputTopicBytes, under the data output script of its first
// kDataOutputTopicBytes bytes (a topic, such as an auction id, shared by all outputs that start with it).
inline constexpr std::size_t kDataOutputMaxBytes = 80;
inline constexpr std::size_t kDataOutputTopicBytes = 32;
bool is_data_output_script(const Bytes& script_pubkey, Bytes* out_data = nullptr);
std::optional<Bytes> data_output_script_pubkey(const Bytes& data);

// Whether the key with hash `pkh` may spend an output with `script_pubkey` in a block at `height`:
// P2PKH to pkh, or a height lock's permitted branch. Wallets use it to pick spendable coins.
bool script_spendable_by(const Bytes& script_pubkey, const std::array<std::uint8_t, 20>& pkh, std::uint64_t height);
// Address-index keys of a transparent output: sha256(script_pubkey), plus for a height lock the P2PKH
// scripthash of each key that may spend it, so the beneficiary's (and owner's) wallet finds it, and
// for a data output its topic's scripthash.
std::vector<Hash32> script_index_hashes(const Bytes& script_pubkey);
bool script_indexed_under(const Bytes& script_pubkey, const Hash32& scripthash);
bool parse_slash_script_sig(const Bytes& script_sig, SlashEvidence* out);

struct ConfidentialPolicy {
  std::uint32_t max_inputs_per_tx{kTxV2MaxInputs};
  std::uint32_t max_outputs_per_tx{kTxV2MaxOutputs};
  std::uint32_t max_confidential_inputs_per_tx{16};
  // 12 canonical range proofs (<= 5134 bytes each) fit max_total_proof_bytes_per_tx; 13 do not.
  std::uint32_t max_confidential_outputs_per_tx{12};
  std::uint32_t max_memo_bytes{kTxV2MaxMemoBytes};
  std::uint32_t max_range_proof_bytes{kTxV2MaxRangeProofBytes};
  std::uint32_t max_total_proof_bytes_per_tx{65536};
  std::uint64_t max_fee{std::numeric_limits<std::uint64_t>::max()};
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

AnyTxValidationResult validate_tx_v2(const TxV2& tx, size_t tx_index_in_block, const UtxoSetV2& utxos,
                                     const SpecialValidationContext* ctx = nullptr);
AnyTxValidationResult validate_any_tx(const AnyTx& tx, size_t tx_index_in_block, const UtxoSetV2& utxos,
                                      const SpecialValidationContext* ctx = nullptr);

// Confidential verification weight (consensus). Unit: one range-proof byte (~0.72 us of verify).
// Computed from structure alone so a block's total can be bounded before any cryptographic
// verification or state transition:
//   64   per confidential input            spend signature + its commitment-tally term
//   proof bytes + 256 per confidential output  range proof + commitment/pubkey canonical checks
//   64   if the excess is not identity     excess authorization
//   256  if the tx has any of the above    tally, fee commitment, sighash, transparent-input work
// Transparent-only TxV2 weighs 0 (bounded by size and kMaxTxEd25519Verifies instead).
//
// Calibration (tools/bench_confidential_verify.cpp, Release, i7-1355U, single thread, idle; median
// of 7 rounds). Measured cost vs weight at 0.72 us/unit:
//   range proof verify (canonical 64-bit)  3671 us   1 proof = 5126 bytes
//   schnorr verify (input / excess)        30 / 36 us   = 42 / 50 units  -> 64
//   full T->C 1 in / 1 conf out            3950 us   weight  5702 (=4105 us)
//   full T->C 1 in / 12 conf out (max)    45297 us   weight 64904 (=46731 us)
//   full C->T 1 conf in / 1 out             187 us   weight   384 (= 276 us)
//   full C->T 16 conf in / 1 out (max)      857 us   weight  1344 (= 968 us)
// Every shape is charged within +3..+48% of its cost, never under. With all cores busy every op ran
// 2-4x slower and ratios held within ~2x. max_block_confidential_verify_weight (2,000,000) is then
// ~1.4 s single-core verify idle (~2.7 s loaded) for any mix, well inside the 30 s round timeout and
// 180 s min block interval.
inline constexpr std::uint64_t kConfidentialSignatureVerifyWeight = 64;
inline constexpr std::uint64_t kConfidentialOutputVerifyWeight = 256;
inline constexpr std::uint64_t kConfidentialTxBaseVerifyWeight = 256;
std::uint64_t txv2_confidential_verify_weight(const TxV2& tx);
std::uint64_t any_tx_confidential_verify_weight(const AnyTx& tx);
UtxoSetV2 upgrade_utxo_set_v2(const UtxoSet& utxos);
void apply_any_tx_to_utxo(const AnyTx& tx, UtxoSetV2& utxos);

}  // namespace finalis
