// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "common/types.hpp"

namespace finalis::storage {
class DB;
}  // namespace finalis::storage

namespace finalis::crypto {

struct SmtUpdate {
  Hash32 key{};
  std::optional<Bytes> value;
};

struct SmtProof {
  std::vector<Hash32> siblings;  // leaf->root order (256 entries)
};

class PersistentSmt;
class PersistentSmtOps;

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
  static Hash32 leaf_hash(const Hash32& key, const Bytes& value);

 private:
  friend class PersistentSmt;
  friend class PersistentSmtOps;
  storage::DB& db_;
  std::string tree_id_;

  struct LeafRef {
    Hash32 key{};
    Hash32 hash{};  // leaf_hash(key, value)
  };
  // Root of `leaves` (sorted by key, keys unique); with `proof_key`, also the siblings on its path.
  static Hash32 hash_sorted_leaves(const std::vector<LeafRef>& leaves, const Hash32* proof_key, SmtProof* proof);

  static Hash32 empty_leaf_hash();
  static Hash32 node_hash(const Hash32& left, const Hash32& right);
  static std::array<Hash32, 257> empty_hashes();
  static bool bit_at(const Hash32& key, std::size_t bit_index_msb0);
  static std::string path_prefix(const Hash32& key, std::size_t bits);

  std::string leaf_key_prefix() const;
  std::string leaf_key(const Hash32& key) const;
  std::string root_key_for_height(std::uint64_t height) const;
};

// The same sparse Merkle tree as SparseMerkleTree::compute_root_from_leaves (identical roots), held
// as an immutable compressed binary trie. updated() returns a new version that shares every untouched
// subtree with this one, so a version is cheap to copy and to keep, and changing k leaves costs about
// k * 256 hashes regardless of the tree size.
class PersistentSmt {
 public:
  PersistentSmt() = default;
  // From (key, leaf hash) pairs; a repeated key keeps its last value.
  static PersistentSmt from_leaf_hashes(std::vector<std::pair<Hash32, Hash32>> leaves);
  // Sets each key to its leaf hash, or removes it (nullopt). Later entries win.
  PersistentSmt updated(const std::vector<std::pair<Hash32, std::optional<Hash32>>>& changes) const;
  Hash32 root() const;
  std::size_t size() const { return size_; }
  // Membership or non-membership proof for `key` against root(), in SparseMerkleTree's format.
  SmtProof proof(const Hash32& key) const;

 private:
  friend class PersistentSmtOps;
  struct Node;
  std::shared_ptr<const Node> root_;
  std::size_t size_{0};
};

using SmtChange = std::pair<Hash32, std::optional<Hash32>>;  // key -> new leaf hash, or removed
Bytes encode_smt_delta(const std::vector<SmtChange>& changes);
std::optional<std::vector<SmtChange>> decode_smt_delta(const Bytes& bytes);

}  // namespace finalis::crypto
