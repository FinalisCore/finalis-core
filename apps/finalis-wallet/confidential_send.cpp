// SPDX-License-Identifier: MIT

#include "confidential_send.hpp"

#include <algorithm>

#include "confidential_memo.hpp"
#include "crypto/secure_memory.hpp"
#include "wallet/confidential_keys.hpp"

namespace finalis::wallet {
namespace {

template <std::size_t N>
std::optional<std::array<std::uint8_t, N>> decode_fixed_hex(const std::string& hex) {
  auto bytes = hex_decode(hex);
  if (!bytes || bytes->size() != N) {
    if (bytes) crypto::secure_wipe(*bytes);
    return std::nullopt;
  }
  std::array<std::uint8_t, N> out{};
  std::copy(bytes->begin(), bytes->end(), out.begin());
  crypto::secure_wipe(*bytes);
  return out;
}

std::optional<ConfidentialOwnedCoin> owned_coin(const WalletStore::ConfidentialCoinRecord& record) {
  auto txid = decode_fixed_hex<32>(record.txid_hex);
  auto commitment = decode_fixed_hex<33>(record.value_commitment_hex);
  auto one_time = decode_fixed_hex<33>(record.one_time_pubkey_hex);
  auto spend = decode_fixed_hex<32>(record.spend_secret_hex);
  auto blind = decode_fixed_hex<32>(record.blinding_factor_hex);
  std::optional<ConfidentialOwnedCoin> out;
  if (txid && commitment && one_time && spend && blind) {
    out = ConfidentialOwnedCoin{.outpoint = OutPoint{*txid, record.vout},
                                .amount = record.amount,
                                .spend_secret = crypto::Blind32{*spend},
                                .value_blind = crypto::Blind32{*blind},
                                .value_commitment = crypto::Commitment33{*commitment},
                                .one_time_pubkey = *one_time};
  }
  if (spend) crypto::secure_wipe(*spend);
  if (blind) crypto::secure_wipe(*blind);
  return out;
}

std::optional<ConfidentialPayment> make_payment(const ConfidentialRecipient& recipient, std::uint64_t value,
                                                const std::optional<Hash32>& memo_key,
                                                const std::function<Hash32()>& random, std::string* err) {
  crypto::ConfidentialOutputSecrets secrets{.amount = value, .value_blind = crypto::Blind32{random()}};
  Hash32 proof_nonce = random();
  crypto::ScopedWipe<Hash32, Hash32> wipe(secrets.value_blind.bytes, proof_nonce);
  ConfidentialRecipient to = recipient;
  if (memo_key.has_value()) {
    auto memo = encrypt_confidential_recovery_memo(value, secrets.value_blind, *memo_key, to.one_time_pubkey,
                                                   to.ephemeral_pubkey);
    if (!memo) {
      if (err) *err = "failed to encrypt confidential recovery memo";
      return std::nullopt;
    }
    to.memo = *memo;
  }
  auto output = build_confidential_output(to, secrets, proof_nonce, err);
  if (!output) return std::nullopt;
  return ConfidentialPayment{.output = *output, .value = value, .value_blind = secrets.value_blind};
}

}  // namespace

std::optional<ConfidentialTransferPlan> plan_confidential_transfer(
    const WalletStore::State& state, const std::set<OutPoint>& reserved, const std::string& change_account_id,
    const ConfidentialRecipient& recipient, const std::optional<Hash32>& recipient_memo_key, std::uint64_t amount,
    std::uint64_t fee, const std::function<Hash32()>& random, std::string* err) {
  if (amount == 0) {
    if (err) *err = "amount must be positive";
    return std::nullopt;
  }
  const std::uint64_t target = amount + fee;
  if (target < amount) {
    if (err) *err = "amount plus fee overflows";
    return std::nullopt;
  }

  std::vector<ConfidentialOwnedCoin> candidates;
  for (const auto& record : state.confidential_coins) {
    if (record.spent) continue;
    auto coin = owned_coin(record);
    if (!coin || reserved.count(coin->outpoint) != 0) continue;
    candidates.push_back(*coin);
  }
  std::sort(candidates.begin(), candidates.end(), [](const auto& a, const auto& b) {
    if (a.amount != b.amount) return a.amount > b.amount;
    return std::tie(a.outpoint.txid, a.outpoint.index) < std::tie(b.outpoint.txid, b.outpoint.index);
  });
  ConfidentialTransferPlan plan;
  std::vector<ConfidentialOwnedCoin> selected;
  for (const auto& coin : candidates) {
    if (plan.input_total >= target || selected.size() == kMaxConfidentialTransferInputs) break;
    selected.push_back(coin);
    plan.input_total += coin.amount;
  }
  if (plan.input_total < target) {
    if (err) {
      *err = "unlocked confidential coins cover " + std::to_string(plan.input_total) + " of the " +
             std::to_string(target) + " base units needed (at most " + std::to_string(kMaxConfidentialTransferInputs) +
             " inputs)";
    }
    return std::nullopt;
  }
  plan.change = plan.input_total - target;

  std::vector<ConfidentialPayment> outputs;
  auto payment = make_payment(recipient, amount, recipient_memo_key, random, err);
  if (!payment) return std::nullopt;
  outputs.push_back(*payment);

  if (plan.change > 0) {
    const auto account = std::find_if(state.confidential_accounts.begin(), state.confidential_accounts.end(),
                                      [&](const auto& a) { return a.account_id == change_account_id; });
    if (account == state.confidential_accounts.end()) {
      if (err) *err = "change account not found";
      return std::nullopt;
    }
    auto view = decode_fixed_hex<32>(account->view_key_material_hex);
    auto spend = decode_fixed_hex<32>(account->spend_key_material_hex);
    std::optional<ConfidentialRequestKeys> keys;
    if (view && spend) keys = derive_confidential_request_keys(*view, *spend, account->next_request_index);
    if (view) crypto::secure_wipe(*view);
    if (spend) crypto::secure_wipe(*spend);
    if (!keys) {
      if (err) *err = "failed to derive change request keys";
      return std::nullopt;
    }
    const ConfidentialRecipient change_to{.one_time_pubkey = keys->pub.one_time_pubkey,
                                          .ephemeral_pubkey = keys->pub.ephemeral_pubkey,
                                          .scan_tag = keys->pub.scan_tag,
                                          .memo = {}};
    auto change = make_payment(change_to, plan.change, keys->pub.memo_key, random, err);
    if (!change) return std::nullopt;
    outputs.push_back(*change);
    plan.change_account_id = change_account_id;
    plan.change_request_index = account->next_request_index;
    if ((random()[0] & 1U) != 0) std::swap(outputs[0], outputs[1]);
  }

  Hash32 nonce_seed = random();
  crypto::ScopedWipe<Hash32> wipe_seed(nonce_seed);
  auto tx = build_txv2_confidential_to_confidential(selected, outputs, fee, nonce_seed, err);
  if (!tx) return std::nullopt;
  plan.tx = std::move(*tx);
  for (const auto& coin : selected) plan.spent.push_back(coin.outpoint);
  return plan;
}

}  // namespace finalis::wallet
