#pragma once

#include <array>
#include <optional>
#include <string>
#include <vector>

#include "common/types.hpp"
#include "storage/db.hpp"

namespace finalis::crypto {

struct SmtUpdate {
  Hash32 key{};
  std::optional<Bytes> value;
};

struct SmtProof {
  std::vector<Hash32> siblings;  // leaf->root order (256 entries)
};

class SparseMerkleTree {
 public:
  SparseMerkleTree(storage::DB& db, std::string tree_id);

  Hash32 root() const;
  void apply_updates(const std::vector<SmtUpdate>& updates);
  SmtProof get_proof(const Hash32& key) const;
  std::optional<Bytes> get_value(const Hash32& key) const;

  bool set_root_for_height(std::uint64_t height, const Hash32& root_hash);
  std::optional<Hash32> root_for_height(std::uint64_t height) const;

  static bool verify_proof(const Hash32& root, const Hash32& key, const std::optional<Bytes>& value, const SmtProof& proof);
  static Hash32 compute_root_from_leaves(const std::vector<std::pair<Hash32, Bytes>>& leaves);

 private:
  storage::DB& db_;
  std::string tree_id_;

  static Hash32 leaf_hash(const Hash32& key, const Bytes& value);
  static Hash32 empty_leaf_hash();
  static Hash32 node_hash(const Hash32& left, const Hash32& right);
  static std::array<Hash32, 257> empty_hashes();
  static bool bit_at(const Hash32& key, std::size_t bit_index_msb0);
  static std::string path_prefix(const Hash32& key, std::size_t bits);

  std::string leaf_key_prefix() const;
  std::string leaf_key(const Hash32& key) const;
  std::string root_key_for_height(std::uint64_t height) const;
};

}  // namespace finalis::crypto
