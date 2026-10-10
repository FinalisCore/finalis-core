// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "utxo/confidential_tx.hpp"
#include "wallet/confidential_builder.hpp"
#include "wallet_store.hpp"

namespace finalis::wallet {

// Most confidential inputs a transfer selects (ConfidentialPolicy::max_confidential_inputs_per_tx).
constexpr std::size_t kMaxConfidentialTransferInputs = 16;

struct ConfidentialTransferPlan {
  TxV2 tx;
  std::vector<OutPoint> spent;  // coins consumed; reserve them until the tx finalizes
  std::uint64_t input_total{0};
  std::uint64_t change{0};
  // Set when there is change: it pays request `change_request_index` of `change_account_id`, so the
  // wallet recognises it like any received coin. Advance that account's next_request_index past it.
  std::string change_account_id;
  std::optional<std::uint32_t> change_request_index;
};

// Confidential -> confidential send of `amount` plus `fee` to `recipient`. Selects unspent,
// unreserved coins (largest first, at most kMaxConfidentialTransferInputs). Change, if any, goes to
// the next derived request of `change_account_id` with a recovery memo, so it is never a transparent
// output and survives a restore from the account secrets. The recipient gets a recovery memo when
// `recipient_memo_key` is known (scconfreq1 URIs carry it). Output order is randomised so change is not
// recognisable by position. `random` supplies blinds, nonces and the order bit.
std::optional<ConfidentialTransferPlan> plan_confidential_transfer(
    const WalletStore::State& state, const std::set<OutPoint>& reserved, const std::string& change_account_id,
    const ConfidentialRecipient& recipient, const std::optional<Hash32>& recipient_memo_key, std::uint64_t amount,
    std::uint64_t fee, const std::function<Hash32()>& random, std::string* err);

}  // namespace finalis::wallet
