// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "common/types.hpp"
#include "utxo/confidential_tx.hpp"
#include "wallet_store.hpp"

namespace finalis::wallet {

// Requests past an account's next_request_index that matching still tries, so a wallet restored
// from its account secrets alone also finds coins paid to requests it no longer has records of.
constexpr std::uint32_t kConfidentialRequestGap = 100;

struct ConfidentialReceiveMatch {
  WalletStore::ConfidentialCoinRecord coin;
  // Stored request that matched; empty when the output matched a key derived from the account.
  std::string request_id;
  // Set when matched by derivation: the request index, so the caller advances next_request_index.
  std::optional<std::uint32_t> derived_index;
};

// Confidential outputs of finalized `tx` paying one of the wallet's receive requests whose recovery
// memo decrypts. A stored request record matches first; otherwise request keys derived from each
// account's secrets for indices [0, next_request_index + kConfidentialRequestGap) are tried.
// A request URI may be paid any number of times, so consumed requests still match.
// Outputs already in state.confidential_coins are skipped (and counted in *already_imported) so a
// re-import never overwrites a stored coin, e.g. resetting its spent flag.
std::vector<ConfidentialReceiveMatch> match_received_confidential_outputs(const TxV2& tx, const Hash32& txid,
                                                                          const WalletStore::State& state,
                                                                          std::size_t* already_imported = nullptr);

}  // namespace finalis::wallet
