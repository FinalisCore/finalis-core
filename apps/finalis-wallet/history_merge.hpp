// SPDX-License-Identifier: MIT

#pragma once

#include <string>
#include <vector>

namespace finalis::wallet {

struct ChainRecordView {
  std::string status;
  std::string kind;
  std::string amount;
  std::string reference;
  std::string height;
  std::string txid;
  std::string details;
};

std::vector<ChainRecordView> merge_chain_records_for_display(const std::vector<ChainRecordView>& records);

}  // namespace finalis::wallet
