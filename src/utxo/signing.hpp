#pragma once

#include <functional>
#include <optional>

#include "common/chain_id.hpp"
#include "common/network.hpp"
#include "utxo/tx.hpp"

namespace finalis {

constexpr std::uint64_t DEFAULT_WALLET_SEND_FEE_UNITS = 1'000;
constexpr std::uint64_t DEFAULT_WALLET_DUST_THRESHOLD_UNITS = 546;

struct WalletSendPlan {
  std::vector<std::pair<OutPoint, TxOut>> selected_prevs;
  std::vector<TxOut> outputs;
  std::uint64_t selected_units{0};
  std::uint64_t amount_units{0};
  std::uint64_t requested_fee_units{0};
  std::uint64_t applied_fee_units{0};
  std::uint64_t change_units{0};
};

struct ValidatorJoinAdmissionPowBuildContext {
  const NetworkConfig* network{nullptr};
  const ChainId* chain_id{nullptr};
  std::uint64_t current_height{0};
  // Height-indexed finalized identity witness. This remains generic because the
  // anchor may come from legacy block history or frontier transition history.
  std::function<std::optional<Hash32>(std::uint64_t)> finalized_hash_at_height;
};

std::vector<std::pair<OutPoint, TxOut>> deterministic_largest_first_prevs(
    const std::vector<std::pair<OutPoint, TxOut>>& available_prevs);
std::optional<WalletSendPlan> plan_wallet_p2pkh_send(
    const std::vector<std::pair<OutPoint, TxOut>>& available_prevs, const Bytes& recipient_script_pubkey,
    const Bytes& change_script_pubkey, std::uint64_t amount_units,
    std::uint64_t requested_fee_units = DEFAULT_WALLET_SEND_FEE_UNITS,
    std::uint64_t dust_threshold_units = DEFAULT_WALLET_DUST_THRESHOLD_UNITS, std::string* err = nullptr);

std::optional<Tx> build_signed_p2pkh_tx_single_input(const OutPoint& prev_outpoint, const TxOut& prev_out,
                                                      const Bytes& private_key_32,
                                                      const std::vector<TxOut>& outputs,
                                                      std::string* err = nullptr);
std::optional<Tx> build_signed_p2pkh_tx_multi_input(const std::vector<std::pair<OutPoint, TxOut>>& prevs,
                                                    const Bytes& private_key_32,
                                                    const std::vector<TxOut>& outputs,
                                                    std::string* err = nullptr);
std::optional<Tx> build_unbond_tx(const OutPoint& bond_outpoint, const PubKey32& validator_pubkey,
                                  std::uint64_t bond_value, std::uint64_t fee,
                                  const Bytes& validator_privkey_32, std::string* err = nullptr);
std::optional<Tx> build_validator_join_request_tx(const OutPoint& prev_outpoint, const TxOut& prev_out,
                                                  const Bytes& funding_privkey_32, const PubKey32& validator_pubkey,
                                                  const Bytes& validator_privkey_32, const PubKey32& payout_pubkey,
                                                  std::uint64_t bond_amount, std::uint64_t fee,
                                                  const Bytes& change_script_pubkey, std::string* err = nullptr,
                                                  const ValidatorJoinAdmissionPowBuildContext* pow_ctx = nullptr);
std::optional<Tx> build_validator_join_request_tx(const std::vector<std::pair<OutPoint, TxOut>>& prevs,
                                                  const Bytes& funding_privkey_32, const PubKey32& validator_pubkey,
                                                  const Bytes& validator_privkey_32, const PubKey32& payout_pubkey,
                                                  std::uint64_t bond_amount, std::uint64_t fee,
                                                  const Bytes& change_script_pubkey, std::string* err = nullptr,
                                                  const ValidatorJoinAdmissionPowBuildContext* pow_ctx = nullptr);
std::optional<Tx> build_onboarding_registration_tx(const OutPoint& prev_outpoint, const TxOut& prev_out,
                                                   const Bytes& funding_privkey_32, const PubKey32& validator_pubkey,
                                                   const Bytes& validator_privkey_32, const PubKey32& payout_pubkey,
                                                   std::uint64_t fee, const Bytes& change_script_pubkey,
                                                   std::string* err = nullptr,
                                                   const ValidatorJoinAdmissionPowBuildContext* pow_ctx = nullptr);
std::optional<Tx> build_onboarding_registration_tx(const std::vector<std::pair<OutPoint, TxOut>>& prevs,
                                                   const Bytes& funding_privkey_32, const PubKey32& validator_pubkey,
                                                   const Bytes& validator_privkey_32, const PubKey32& payout_pubkey,
                                                   std::uint64_t fee, const Bytes& change_script_pubkey,
                                                   std::string* err = nullptr,
                                                   const ValidatorJoinAdmissionPowBuildContext* pow_ctx = nullptr);
std::optional<Tx> build_slash_tx(const OutPoint& bond_outpoint, std::uint64_t bond_value, const Vote& vote_a,
                                 const Vote& vote_b, std::uint64_t fee = 0, std::string* err = nullptr);

}  // namespace finalis
