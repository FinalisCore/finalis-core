#include "common/merkle.hpp"

#include "crypto/hash.hpp"

namespace finalis::merkle {

std::optional<Hash32> compute_merkle_root_from_leaves(const std::vector<Hash32>& leaf_hashes) {
  if (leaf_hashes.empty()) return std::nullopt;

  std::vector<Hash32> level = leaf_hashes;
  while (level.size() > 1) {
    if (level.size() % 2 == 1) {
      level.push_back(level.back());
    }
    std::vector<Hash32> next;
    next.reserve(level.size() / 2);
    for (size_t i = 0; i < level.size(); i += 2) {
      Bytes cat;
      cat.insert(cat.end(), level[i].begin(), level[i].end());
      cat.insert(cat.end(), level[i + 1].begin(), level[i + 1].end());
      next.push_back(crypto::sha256d(cat));
    }
    level = std::move(next);
  }
  return level.front();
}

std::optional<Hash32> compute_merkle_root_from_txs(const std::vector<Bytes>& tx_bytes) {
  if (tx_bytes.empty()) return std::nullopt;
  std::vector<Hash32> leaves;
  leaves.reserve(tx_bytes.size());
  for (const auto& tx : tx_bytes) {
    leaves.push_back(crypto::sha256d(tx));
  }
  return compute_merkle_root_from_leaves(leaves);
}

}  // namespace finalis::merkle
