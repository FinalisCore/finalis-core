// SPDX-License-Identifier: MIT

#include "history_merge.hpp"

#include <cctype>
#include <map>
#include <utility>

namespace finalis::wallet {
namespace {

std::string uppercase_ascii(std::string value) {
  for (char& ch : value) ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
  return value;
}

int chain_record_display_priority(const ChainRecordView& rec) {
  const std::string status = uppercase_ascii(rec.status);
  if (status == "FINALIZED") return 2;
  if (status == "PENDING") return 1;
  return 0;
}

}  // namespace

std::vector<ChainRecordView> merge_chain_records_for_display(const std::vector<ChainRecordView>& records) {
  std::vector<ChainRecordView> merged;
  std::map<std::string, std::size_t> txid_index;
  for (const auto& rec : records) {
    if (rec.txid.empty()) {
      merged.push_back(rec);
      continue;
    }
    const auto found = txid_index.find(rec.txid);
    if (found == txid_index.end()) {
      txid_index.emplace(rec.txid, merged.size());
      merged.push_back(rec);
      continue;
    }
    auto& existing = merged[found->second];
    if (chain_record_display_priority(rec) > chain_record_display_priority(existing)) existing = rec;
  }
  return merged;
}

}  // namespace finalis::wallet
