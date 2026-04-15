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
};

struct SlashEvidence {
  Vote a;
  Vote b;
  Bytes raw_blob;
};

inline constexpr std::size_t kMaxTxInputs = 512;
inline constexpr std::size_t kMaxTxEd25519Verifies = 1024;

TxValidationResult validate_tx(const Tx& tx, size_t tx_index_in_block, const UtxoSet& utxos,
                               const SpecialValidationContext* ctx = nullptr);
std::optional<Bytes> signing_message_for_input(const Tx& tx, std::uint32_t input_index);
std::optional<Bytes> signing_message_for_input_v2(const TxV2& tx, std::uint32_t input_index);
std::optional<Hash32> balance_proof_message_v2(const TxV2& tx);
std::optional<Bytes> unbond_message_for_input(const Tx& tx, std::uint32_t input_index);
Bytes onboarding_registration_pop_message(const PubKey32& validator_pubkey, const PubKey32& payout_pubkey);
Bytes validator_join_request_pop_message(const PubKey32& validator_pubkey, const PubKey32& payout_pubkey);
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
Bytes vote_signing_message(std::uint64_t height, std::uint32_t round, const Hash32& transition_id);
Bytes timeout_vote_signing_message(std::uint64_t height, std::uint32_t round);
bool is_p2pkh_script_pubkey(const Bytes& script_pubkey, std::array<std::uint8_t, 20>* out_hash = nullptr);
bool is_p2pkh_script_sig(const Bytes& script_sig, Sig64* out_sig = nullptr, PubKey32* out_pub = nullptr);
bool is_supported_base_layer_output_script(const Bytes& script_pubkey);
bool parse_slash_script_sig(const Bytes& script_sig, SlashEvidence* out);

struct BlockValidationResult {
  bool ok{false};
  std::string error;
  std::uint64_t total_fees{0};
};

struct ConfidentialPolicy {
  std::uint64_t activation_height{std::numeric_limits<std::uint64_t>::max()};
  std::uint32_t max_inputs_per_tx{64};
  std::uint32_t max_outputs_per_tx{32};
  std::uint32_t max_confidential_inputs_per_tx{16};
  std::uint32_t max_confidential_outputs_per_tx{16};
  std::uint32_t max_memo_bytes{128};
  std::uint32_t max_range_proof_bytes{5134};
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

using ExpectedCoinbaseOutputsBuilder = std::function<std::vector<TxOut>(std::uint64_t fees)>;

BlockValidationResult validate_block_txs(const Block& block, const UtxoSet& base_utxos, std::uint64_t block_reward,
                                         const SpecialValidationContext* ctx = nullptr,
                                         const ExpectedCoinbaseOutputsBuilder* expected_coinbase_outputs = nullptr);
void apply_block_to_utxo(const Block& block, UtxoSet& utxos);

AnyTxValidationResult validate_tx_v2(const TxV2& tx, size_t tx_index_in_block, const UtxoSetV2& utxos,
                                     const SpecialValidationContext* ctx = nullptr);
AnyTxValidationResult validate_any_tx(const AnyTx& tx, size_t tx_index_in_block, const UtxoSetV2& utxos,
                                      const SpecialValidationContext* ctx = nullptr);
UtxoSetV2 upgrade_utxo_set_v2(const UtxoSet& utxos);
void apply_any_tx_to_utxo(const AnyTx& tx, UtxoSetV2& utxos);

}  // namespace finalis
