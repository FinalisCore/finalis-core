#include "crypto/smt.hpp"

#include <algorithm>
#include <map>
#include <unordered_map>

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"

namespace finalis::crypto {

namespace {

using LevelMap = std::map<std::string, Hash32>;

Hash32 hash_tagged(const Bytes& tag, const Bytes& payload) {
  Bytes in = tag;
  in.insert(in.end(), payload.begin(), payload.end());
  return crypto::sha256(in);
}

std::string hex_of_key(const Hash32& key) { return hex_encode(Bytes(key.begin(), key.end())); }

std::vector<std::pair<Hash32, Bytes>> load_leaves(storage::DB& db, const std::string& prefix) {
  std::vector<std::pair<Hash32, Bytes>> out;
  for (const auto& [k, v] : db.scan_prefix(prefix)) {
    if (v.empty()) continue;  // tombstone / deleted leaf
    const std::string hex = k.substr(prefix.size());
    auto kb = hex_decode(hex);
    if (!kb.has_value() || kb->size() != 32) continue;
    Hash32 key{};
    std::copy(kb->begin(), kb->end(), key.begin());
    out.push_back({key, v});
  }
  std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
  return out;
}

}  // namespace

SparseMerkleTree::SparseMerkleTree(storage::DB& db, std::string tree_id) : db_(db), tree_id_(std::move(tree_id)) {}

Hash32 SparseMerkleTree::leaf_hash(const Hash32& key, const Bytes& value) {
  const Hash32 vh = crypto::sha256(value);
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'S', 'M', 'T', '-', 'L', 'E', 'A', 'F', '-', 'V', '0'});
  w.bytes_fixed(key);
  w.bytes_fixed(vh);
  return crypto::sha256(w.data());
}

Hash32 SparseMerkleTree::empty_leaf_hash() {
  return hash_tagged(Bytes{'S', 'C', '-', 'S', 'M', 'T', '-', 'E', 'M', 'P', 'T', 'Y', '-', 'V', '0'}, {});
}

Hash32 SparseMerkleTree::node_hash(const Hash32& left, const Hash32& right) {
  codec::ByteWriter w;
  w.bytes(Bytes{'S', 'C', '-', 'S', 'M', 'T', '-', 'N', 'O', 'D', 'E', '-', 'V', '0'});
  w.bytes_fixed(left);
  w.bytes_fixed(right);
  return crypto::sha256(w.data());
}

std::array<Hash32, 257> SparseMerkleTree::empty_hashes() {
  std::array<Hash32, 257> out{};
  out[256] = empty_leaf_hash();
  for (int d = 255; d >= 0; --d) out[d] = node_hash(out[d + 1], out[d + 1]);
  return out;
}

bool SparseMerkleTree::bit_at(const Hash32& key, std::size_t bit_index_msb0) {
  const std::size_t byte = bit_index_msb0 / 8;
  const std::size_t bit = 7 - (bit_index_msb0 % 8);
  return ((key[byte] >> bit) & 1U) != 0;
}

std::string SparseMerkleTree::path_prefix(const Hash32& key, std::size_t bits) {
  std::string out;
  out.reserve(bits);
  for (std::size_t i = 0; i < bits; ++i) out.push_back(bit_at(key, i) ? '1' : '0');
  return out;
}

std::string SparseMerkleTree::leaf_key_prefix() const { return storage::key_smt_leaf_prefix(tree_id_); }
std::string SparseMerkleTree::leaf_key(const Hash32& key) const { return storage::key_smt_leaf(tree_id_, key); }
std::string SparseMerkleTree::root_key_for_height(std::uint64_t height) const { return storage::key_smt_root(tree_id_, height); }

Hash32 SparseMerkleTree::root() const {
  return compute_root_from_leaves(load_leaves(db_, leaf_key_prefix()));
}

void SparseMerkleTree::apply_updates(const std::vector<SmtUpdate>& updates) {
  for (const auto& u : updates) {
    if (u.value.has_value()) {
      (void)db_.put(leaf_key(u.key), *u.value);
    } else {
      const auto k = leaf_key(u.key);
#ifdef SC_HAS_ROCKSDB
      // DB has no public delete-by-key except typed helpers; use tombstone empty value to stay deterministic.
      (void)db_.put(k, {});
#else
      (void)db_.put(k, {});
#endif
    }
  }
}

std::optional<Bytes> SparseMerkleTree::get_value(const Hash32& key) const {
  auto v = db_.get(leaf_key(key));
  if (!v.has_value() || v->empty()) return std::nullopt;
  return v;
}

SmtProof SparseMerkleTree::get_proof(const Hash32& key) const {
  SmtProof proof;
  proof.siblings.reserve(256);
  const auto empties = empty_hashes();
  const auto leaves = load_leaves(db_, leaf_key_prefix());
  std::vector<LevelMap> levels(257);
  for (const auto& [k, v] : leaves) levels[256][path_prefix(k, 256)] = leaf_hash(k, v);
  for (int depth = 256; depth > 0; --depth) {
    LevelMap parents;
    for (const auto& [p, _] : levels[depth]) {
      const std::string parent = p.substr(0, depth - 1);
      if (parents.find(parent) != parents.end()) continue;
      const std::string l = parent + "0";
      const std::string r = parent + "1";
      const auto li = levels[depth].find(l);
      const auto ri = levels[depth].find(r);
      const Hash32 lh = (li != levels[depth].end()) ? li->second : empties[depth];
      const Hash32 rh = (ri != levels[depth].end()) ? ri->second : empties[depth];
      parents[parent] = node_hash(lh, rh);
    }
    levels[depth - 1] = std::move(parents);
  }

  for (int depth = 256; depth > 0; --depth) {
    const std::size_t bit_index = static_cast<std::size_t>(depth - 1);
    const bool bit = bit_at(key, bit_index);
    const std::string parent = path_prefix(key, bit_index);
    const std::string sib = parent + (bit ? "0" : "1");
    const auto it = levels[depth].find(sib);
    proof.siblings.push_back((it != levels[depth].end()) ? it->second : empties[depth]);
  }
  return proof;
}

bool SparseMerkleTree::set_root_for_height(std::uint64_t height, const Hash32& root_hash) {
  return db_.put(root_key_for_height(height), Bytes(root_hash.begin(), root_hash.end()));
}

std::optional<Hash32> SparseMerkleTree::root_for_height(std::uint64_t height) const {
  auto b = db_.get(root_key_for_height(height));
  if (!b.has_value() || b->size() != 32) return std::nullopt;
  Hash32 out{};
  std::copy(b->begin(), b->end(), out.begin());
  return out;
}

bool SparseMerkleTree::verify_proof(const Hash32& root, const Hash32& key, const std::optional<Bytes>& value,
                                    const SmtProof& proof) {
  if (proof.siblings.size() != 256) return false;
  Hash32 cur = value.has_value() ? leaf_hash(key, *value) : empty_leaf_hash();
  for (std::size_t i = 0; i < proof.siblings.size(); ++i) {
    const std::size_t bit_index = 255 - i;
    if (bit_at(key, bit_index)) cur = node_hash(proof.siblings[i], cur);
    else cur = node_hash(cur, proof.siblings[i]);
  }
  return cur == root;
}

Hash32 SparseMerkleTree::compute_root_from_leaves(const std::vector<std::pair<Hash32, Bytes>>& leaves_in) {
  const auto empties = empty_hashes();
  if (leaves_in.empty()) return empties[0];

  std::vector<std::pair<Hash32, Bytes>> leaves = leaves_in;
  std::sort(leaves.begin(), leaves.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
  leaves.erase(std::unique(leaves.begin(), leaves.end(),
                           [](const auto& a, const auto& b) { return a.first == b.first; }),
               leaves.end());

  std::vector<LevelMap> levels(257);
  for (const auto& [k, v] : leaves) levels[256][path_prefix(k, 256)] = leaf_hash(k, v);
  for (int depth = 256; depth > 0; --depth) {
    LevelMap parents;
    for (const auto& [p, _] : levels[depth]) {
      const std::string parent = p.substr(0, depth - 1);
      if (parents.find(parent) != parents.end()) continue;
      const std::string l = parent + "0";
      const std::string r = parent + "1";
      const auto li = levels[depth].find(l);
      const auto ri = levels[depth].find(r);
      const Hash32 lh = (li != levels[depth].end()) ? li->second : empties[depth];
      const Hash32 rh = (ri != levels[depth].end()) ? ri->second : empties[depth];
      parents[parent] = node_hash(lh, rh);
    }
    levels[depth - 1] = std::move(parents);
  }
  auto it = levels[0].find("");
  return (it == levels[0].end()) ? empties[0] : it->second;
}

}  // namespace finalis::crypto
