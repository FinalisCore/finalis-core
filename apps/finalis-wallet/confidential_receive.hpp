// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "common/types.hpp"
#include "utxo/confidential_tx.hpp"
#include "wallet_store.hpp"

namespace finalis::wallet {

struct ConfidentialReceiveMatch {
  WalletStore::ConfidentialCoinRecord coin;
  std::string request_id;
};

// Confidential outputs of finalized `tx` paying one of the wallet's receive requests whose recovery
// memo decrypts. A request URI may be paid any number of times, so consumed requests still match.
// Outputs already in state.confidential_coins are skipped (and counted in *already_imported) so a
// re-import never overwrites a stored coin, e.g. resetting its spent flag.
std::vector<ConfidentialReceiveMatch> match_received_confidential_outputs(const TxV2& tx, const Hash32& txid,
                                                                          const WalletStore::State& state,
                                                                          std::size_t* already_imported = nullptr);

}  // namespace finalis::wallet
