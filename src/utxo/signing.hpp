// SPDX-License-Identifier: MIT

#pragma once

#include <functional>
#include <optional>

#include "common/chain_id.hpp"
#include "common/network.hpp"
#include "utxo/confidential_tx.hpp"
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

std::optional<Tx> build_signed_p2pkh_tx_single_input(const Hash32& chain_domain, const OutPoint& prev_outpoint, const TxOut& prev_out,
                                                      const Bytes& private_key_32,
                                                      const std::vector<TxOut>& outputs,
                                                      std::string* err = nullptr);
std::optional<Tx> build_signed_p2pkh_tx_multi_input(const Hash32& chain_domain, const std::vector<std::pair<OutPoint, TxOut>>& prevs,
                                                    const Bytes& private_key_32,
                                                    const std::vector<TxOut>& outputs,
                                                    std::string* err = nullptr);
std::optional<Tx> build_unbond_tx(const Hash32& chain_domain, const OutPoint& bond_outpoint, const PubKey32& validator_pubkey,
                                  std::uint64_t bond_value, std::uint64_t fee,
                                  const Bytes& validator_privkey_32, std::string* err = nullptr);
// A time-locked transaction (utxo/confidential_tx.hpp, TxTimed): `body` sealed under a fresh key
// that is SWE-encrypted, with its well-formedness proof, to `committee_keys` (the checkpoint keys of
// epoch_of(unlock_height), in order, with root committee_root) at `threshold`; the fee input is a
// P2PKH output of `fee_private_key_32` and must hold exactly prepaid_fee + forfeit_bond + change.
// `seed_32` must be fresh and secret: whoever learns it can open the body before unlock_height.
struct TimedTxParams {
  OutPoint fee_outpoint{};
  TxOut fee_prev_out;
  std::uint64_t prepaid_fee{0};
  std::uint64_t forfeit_bond{0};
  Bytes bond_refund_script;
  std::optional<TxOut> fee_change;
  std::uint64_t unlock_height{0};
  std::uint64_t committee_epoch{0};
  Hash32 committee_root{};
  std::vector<crypto::BlsPublicKey> committee_keys;
  std::uint32_t threshold{0};
};
// Coin selection for a time-locked transparent transfer: the envelope's fee coin is the smallest coin
// covering prepaid_fee + forfeit_bond (the rest returns as change), and the sealed transfer is planned
// from the other coins. The two never share a coin, so the transfer cannot spend the fee input.
struct TimedSendPlan {
  std::pair<OutPoint, TxOut> fee_coin;
  WalletSendPlan body;
  std::uint64_t fee_change_units{0};
};
// The envelope's fee coin: the smallest of `available_prevs` covering prepaid fee + bond.
std::optional<std::pair<OutPoint, TxOut>> select_timed_fee_coin(const std::vector<std::pair<OutPoint, TxOut>>& available_prevs,
                                                                std::uint64_t prepaid_fee_units,
                                                                std::uint64_t forfeit_bond_units, std::string* err = nullptr);
std::optional<TimedSendPlan> plan_timed_p2pkh_send(const std::vector<std::pair<OutPoint, TxOut>>& available_prevs,
                                                   const Bytes& recipient_script_pubkey, const Bytes& change_script_pubkey,
                                                   std::uint64_t amount_units, std::uint64_t body_fee_units,
                                                   std::uint64_t prepaid_fee_units, std::uint64_t forfeit_bond_units,
                                                   std::string* err = nullptr);
// serialize_timed_body size of the signed P2PKH transfer `plan` describes (script_sigs are fixed-size).
std::size_t timed_p2pkh_body_bytes(const WalletSendPlan& plan);
// plan_timed_p2pkh_send with the prepaid fee the envelope needs: `prepaid_for_body_bytes` prices a
// body of that many bytes (e.g. timed_lock_terms over timed_envelope_bytes_bound); re-plans until the
// fee covers the planned transfer. The fee is returned in *prepaid_fee_out.
std::optional<TimedSendPlan> plan_timed_p2pkh_send_priced(
    const std::vector<std::pair<OutPoint, TxOut>>& available_prevs, const Bytes& recipient_script_pubkey,
    const Bytes& change_script_pubkey, std::uint64_t amount_units, std::uint64_t body_fee_units,
    std::uint64_t forfeit_bond_units, const std::function<std::optional<std::uint64_t>(std::size_t)>& prepaid_for_body_bytes,
    std::uint64_t* prepaid_fee_out, std::string* err = nullptr);
std::optional<TxTimed> build_signed_timed_tx(const Hash32& chain_domain, const TimedTxParams& params, const TimedBody& body,
                                             const Bytes& fee_private_key_32, const Hash32& seed_32,
                                             std::string* err = nullptr);
// A validator's BLS key (derived from its Ed25519 seed, crypto::bls_key_from_validator_seed) and its
// proof of possession, as registration scripts and genesis entries carry them.
struct ValidatorBlsRegistration {
  crypto::BlsPublicKey pubkey{};
  crypto::BlsSignature pop{};
};
std::optional<ValidatorBlsRegistration> validator_bls_registration(const Bytes& validator_privkey_32);
std::optional<Tx> build_validator_join_request_tx(const Hash32& chain_domain, const OutPoint& prev_outpoint, const TxOut& prev_out,
                                                  const Bytes& funding_privkey_32, const PubKey32& validator_pubkey,
                                                  const Bytes& validator_privkey_32, const PubKey32& payout_pubkey,
                                                  std::uint64_t bond_amount, std::uint64_t fee,
                                                  const Bytes& change_script_pubkey, std::string* err = nullptr,
                                                  const ValidatorJoinAdmissionPowBuildContext* pow_ctx = nullptr);
std::optional<Tx> build_validator_join_request_tx(const Hash32& chain_domain, const std::vector<std::pair<OutPoint, TxOut>>& prevs,
                                                  const Bytes& funding_privkey_32, const PubKey32& validator_pubkey,
                                                  const Bytes& validator_privkey_32, const PubKey32& payout_pubkey,
                                                  std::uint64_t bond_amount, std::uint64_t fee,
                                                  const Bytes& change_script_pubkey, std::string* err = nullptr,
                                                  const ValidatorJoinAdmissionPowBuildContext* pow_ctx = nullptr);
std::optional<Tx> build_onboarding_registration_tx(const Hash32& chain_domain, const OutPoint& prev_outpoint, const TxOut& prev_out,
                                                   const Bytes& funding_privkey_32, const PubKey32& validator_pubkey,
                                                   const Bytes& validator_privkey_32, const PubKey32& payout_pubkey,
                                                   std::uint64_t fee, const Bytes& change_script_pubkey,
                                                   std::string* err = nullptr,
                                                   const ValidatorJoinAdmissionPowBuildContext* pow_ctx = nullptr);
std::optional<Tx> build_onboarding_registration_tx(const Hash32& chain_domain, const std::vector<std::pair<OutPoint, TxOut>>& prevs,
                                                   const Bytes& funding_privkey_32, const PubKey32& validator_pubkey,
                                                   const Bytes& validator_privkey_32, const PubKey32& payout_pubkey,
                                                   std::uint64_t fee, const Bytes& change_script_pubkey,
                                                   std::string* err = nullptr,
                                                   const ValidatorJoinAdmissionPowBuildContext* pow_ctx = nullptr);
std::optional<Tx> build_slash_tx(const OutPoint& bond_outpoint, std::uint64_t bond_value, const Vote& vote_a,
                                 const Vote& vote_b, std::uint64_t fee = 0, std::string* err = nullptr,
                                 SlashVoteKind kind = SlashVoteKind::Precommit);
// Burns the whole bond (or unbond output) of the validator whose registered BLS key made `signature`
// on time_signature_message(D, height); valid only in a block at a height <= `height`
// (EarlyTimeSignatureEvidence).
Tx build_early_time_signature_slash_tx(const OutPoint& bond_outpoint, std::uint64_t bond_value, std::uint64_t height,
                                       const crypto::BlsSignature& signature);

}  // namespace finalis
