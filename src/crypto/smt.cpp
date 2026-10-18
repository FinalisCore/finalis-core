// SPDX-License-Identifier: MIT

#include "crypto/smt.hpp"

#include <algorithm>
#include <cstring>
#include <map>
#include <mutex>
#include <unordered_map>

#include "codec/bytes.hpp"
#include "crypto/hash.hpp"
#include "storage/db.hpp"

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
  static constexpr char kTag[] = "SC-SMT-NODE-V0";
  constexpr std::size_t kTagLen = sizeof(kTag) - 1;
  thread_local Bytes buf = [] {
    Bytes b(kTagLen + 64);
    std::memcpy(b.data(), kTag, kTagLen);
    return b;
  }();
  std::memcpy(buf.data() + kTagLen, left.data(), 32);
  std::memcpy(buf.data() + kTagLen + 32, right.data(), 32);
  return crypto::sha256(buf);
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
  std::vector<LeafRef> leaves;
  for (const auto& [k, v] : load_leaves(db_, leaf_key_prefix())) leaves.push_back(LeafRef{k, leaf_hash(k, v)});
  SmtProof proof;
  (void)hash_sorted_leaves(leaves, &key, &proof);
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

namespace {

// Memo of single-leaf paths: the hash of the subtree at `depth` that holds only this leaf. Keyed by the
// leaf hash, which binds key and value, so an entry is a pure function of its key; it is never stale.
// A leaf's branching depth changes only when a neighbour with a long shared prefix comes or goes, so
// recomputing a large, slowly changing set (the UTXO set every block) costs O(1) hashes per leaf
// instead of 256.
struct LeafPathMemo {
  std::uint16_t depth{256};
  Hash32 hash{};
};
constexpr std::size_t kLeafPathMemoMaxEntries = std::size_t{1} << 21;

struct Hash32Hasher {
  std::size_t operator()(const Hash32& h) const {
    std::size_t out = 0;
    std::memcpy(&out, h.data(), sizeof(out));
    return out;
  }
};

// One process-wide memo, so the node's threads share it; guarded by g_memo_mu.
std::mutex g_memo_mu;
std::unordered_map<Hash32, LeafPathMemo, Hash32Hasher>& memo_table() {
  static std::unordered_map<Hash32, LeafPathMemo, Hash32Hasher> table;
  return table;
}

}  // namespace

Hash32 SparseMerkleTree::compute_root_from_leaves(const std::vector<std::pair<Hash32, Bytes>>& leaves_in) {
  // Callers pass unique keys; on a duplicate the first in input order wins.
  std::vector<std::size_t> order(leaves_in.size());
  for (std::size_t i = 0; i < order.size(); ++i) order[i] = i;
  std::stable_sort(order.begin(), order.end(),
                   [&](std::size_t a, std::size_t b) { return leaves_in[a].first < leaves_in[b].first; });
  std::vector<LeafRef> leaves;
  leaves.reserve(order.size());
  for (const auto i : order) {
    if (!leaves.empty() && leaves.back().key == leaves_in[i].first) continue;
    leaves.push_back(LeafRef{leaves_in[i].first, leaf_hash(leaves_in[i].first, leaves_in[i].second)});
  }
  return hash_sorted_leaves(leaves, nullptr, nullptr);
}

Hash32 SparseMerkleTree::hash_sorted_leaves(const std::vector<LeafRef>& leaves, const Hash32* proof_key, SmtProof* proof) {
  static const auto empties = empty_hashes();
  if (proof) proof->siblings.assign(256, Hash32{});

  std::lock_guard<std::mutex> lock(g_memo_mu);
  auto& memo = memo_table();
  if (memo.size() > kLeafPathMemoMaxEntries) memo.clear();

  // Hash of the subtree at `depth` holding only `leaf`: climb from the leaf with empty siblings.
  const auto single_leaf = [&](const LeafRef& leaf, std::size_t depth) {
    auto& m = memo[leaf.hash];
    if (m.depth < depth) m = LeafPathMemo{};  // memo is above this depth; restart from the leaf
    std::size_t d = m.depth;
    Hash32 cur = d == 256 ? leaf.hash : m.hash;
    for (; d > depth; --d) {
      cur = bit_at(leaf.key, d - 1) ? node_hash(empties[d], cur) : node_hash(cur, empties[d]);
    }
    m.depth = static_cast<std::uint16_t>(depth);
    m.hash = cur;
    return cur;
  };
  // First index in [lo, hi) whose key has bit `depth` set (the range shares its first `depth` bits).
  const auto split_at = [&](std::size_t depth, std::size_t lo, std::size_t hi) {
    return static_cast<std::size_t>(
        std::partition_point(leaves.begin() + static_cast<std::ptrdiff_t>(lo), leaves.begin() + static_cast<std::ptrdiff_t>(hi),
                             [&](const LeafRef& l) { return !bit_at(l.key, depth); }) -
        leaves.begin());
  };
  // leaves[lo, hi) share their first `depth` bits; returns the hash of that subtree.
  const auto subtree = [&](const auto& self, std::size_t depth, std::size_t lo, std::size_t hi) -> Hash32 {
    if (lo == hi) return empties[depth];
    if (hi - lo == 1) return single_leaf(leaves[lo], depth);
    // Keys are unique, so two leaves always split before depth 256.
    const auto split = split_at(depth, lo, hi);
    return node_hash(self(self, depth + 1, lo, split), self(self, depth + 1, split, hi));
  };

  if (proof && proof_key) {
    // Walk down the key's path; at each depth the sibling is the subtree on the other side.
    std::size_t lo = 0;
    std::size_t hi = leaves.size();
    for (std::size_t depth = 0; depth < 256; ++depth) {
      const auto split = split_at(depth, lo, hi);
      const bool right = bit_at(*proof_key, depth);
      const auto sibling = right ? subtree(subtree, depth + 1, lo, split) : subtree(subtree, depth + 1, split, hi);
      proof->siblings[255 - depth] = sibling;  // leaf -> root order
      if (right) lo = split; else hi = split;
    }
  }
  return subtree(subtree, 0, 0, leaves.size());
}

// ---- PersistentSmt --------------------------------------------------------------------------------

// A leaf (depth 256) or a branch at `depth`: the prefix length at which its two children's keys first
// differ. `key` is any key in the subtree (it carries the shared prefix); `hash` is the subtree's hash at
// its own depth.
struct PersistentSmt::Node {
  bool leaf{false};
  std::uint16_t depth{256};
  Hash32 key{};
  Hash32 hash{};
  std::shared_ptr<const Node> child[2];
};

namespace {

std::size_t first_diff_bit(const Hash32& a, const Hash32& b) {
  for (std::size_t i = 0; i < 32; ++i) {
    const std::uint8_t x = a[i] ^ b[i];
    if (x != 0) {
      std::size_t bit = 0;
      while ((x & (0x80 >> bit)) == 0) ++bit;
      return i * 8 + bit;
    }
  }
  return 256;
}

}  // namespace

// Implemented with SparseMerkleTree's hashing (friend) and its leaf-path memo; callers hold g_memo_mu.
class PersistentSmtOps {
 public:
  using Node = PersistentSmt::Node;
  using SmtNode = std::shared_ptr<const Node>;

  static const std::array<Hash32, 257>& empties() {
    static const auto e = SparseMerkleTree::empty_hashes();
    return e;
  }

  // The subtree's hash as seen at prefix length `target` (<= node depth): climb with empty siblings.
  static Hash32 lift(const Node& n, std::size_t target) {
    if (n.leaf) {
      auto& m = memo_table()[n.hash];
      if (m.depth < target) m = LeafPathMemo{};
      std::size_t d = m.depth;
      Hash32 cur = d == 256 ? n.hash : m.hash;
      for (; d > target; --d) cur = climb(n.key, d, cur);
      m.depth = static_cast<std::uint16_t>(target);
      m.hash = cur;
      return cur;
    }
    Hash32 cur = n.hash;
    for (std::size_t d = n.depth; d > target; --d) cur = climb(n.key, d, cur);
    return cur;
  }

  static Hash32 climb(const Hash32& key, std::size_t d, const Hash32& cur) {
    return SparseMerkleTree::bit_at(key, d - 1) ? SparseMerkleTree::node_hash(empties()[d], cur)
                                                 : SparseMerkleTree::node_hash(cur, empties()[d]);
  }

  static SmtNode leaf(const Hash32& key, const Hash32& leaf_hash) {
    auto n = std::make_shared<Node>();
    n->leaf = true;
    n->depth = 256;
    n->key = key;
    n->hash = leaf_hash;
    return n;
  }

  // Branch at `depth` over two subtrees that agree on the first `depth` bits and differ at bit `depth`.
  static SmtNode branch(std::size_t depth, SmtNode a, SmtNode b) {
    if (SparseMerkleTree::bit_at(a->key, depth)) std::swap(a, b);
    auto n = std::make_shared<Node>();
    n->depth = static_cast<std::uint16_t>(depth);
    n->key = a->key;
    n->hash = SparseMerkleTree::node_hash(lift(*a, depth + 1), lift(*b, depth + 1));
    n->child[0] = std::move(a);
    n->child[1] = std::move(b);
    return n;
  }

  static SmtNode set(const SmtNode& n, const Hash32& key, const Hash32& leaf_hash, bool* inserted) {
    if (!n) {
      *inserted = true;
      return leaf(key, leaf_hash);
    }
    const auto diff = first_diff_bit(n->key, key);
    if (n->leaf) {
      if (diff == 256) return leaf(key, leaf_hash);
      *inserted = true;
      return branch(diff, n, leaf(key, leaf_hash));
    }
    if (diff < n->depth) {
      *inserted = true;
      return branch(diff, n, leaf(key, leaf_hash));
    }
    const int side = SparseMerkleTree::bit_at(key, n->depth) ? 1 : 0;
    auto replaced = set(n->child[side], key, leaf_hash, inserted);
    return side == 0 ? branch(n->depth, replaced, n->child[1]) : branch(n->depth, n->child[0], replaced);
  }

  static SmtNode erase(const SmtNode& n, const Hash32& key, bool* removed) {
    if (!n) return n;
    const auto diff = first_diff_bit(n->key, key);
    if (n->leaf) {
      if (diff != 256) return n;
      *removed = true;
      return nullptr;
    }
    if (diff < n->depth) return n;
    const int side = SparseMerkleTree::bit_at(key, n->depth) ? 1 : 0;
    auto replaced = erase(n->child[side], key, removed);
    if (replaced == n->child[side]) return n;
    if (!replaced) return n->child[1 - side];  // the branch collapses into the other subtree
    return side == 0 ? branch(n->depth, replaced, n->child[1]) : branch(n->depth, n->child[0], replaced);
  }

  // leaves[lo, hi) sorted by key, unique.
  static SmtNode build(const std::vector<std::pair<Hash32, Hash32>>& leaves, std::size_t lo, std::size_t hi) {
    if (hi - lo == 1) return leaf(leaves[lo].first, leaves[lo].second);
    const auto depth = first_diff_bit(leaves[lo].first, leaves[hi - 1].first);
    const auto split = static_cast<std::size_t>(
        std::partition_point(leaves.begin() + static_cast<std::ptrdiff_t>(lo), leaves.begin() + static_cast<std::ptrdiff_t>(hi),
                             [&](const auto& l) { return !SparseMerkleTree::bit_at(l.first, depth); }) -
        leaves.begin());
    return branch(depth, build(leaves, lo, split), build(leaves, split, hi));
  }
};

PersistentSmt PersistentSmt::from_leaf_hashes(std::vector<std::pair<Hash32, Hash32>> leaves) {
  std::stable_sort(leaves.begin(), leaves.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
  // A repeated key keeps its last value (as updated() would); build() needs unique keys.
  std::vector<std::pair<Hash32, Hash32>> unique;
  unique.reserve(leaves.size());
  for (auto& leaf : leaves) {
    if (!unique.empty() && unique.back().first == leaf.first) unique.back() = leaf;
    else unique.push_back(leaf);
  }
  leaves = std::move(unique);
  PersistentSmt out;
  if (leaves.empty()) return out;
  std::lock_guard<std::mutex> lock(g_memo_mu);
  if (memo_table().size() > kLeafPathMemoMaxEntries) memo_table().clear();
  out.root_ = PersistentSmtOps::build(leaves, 0, leaves.size());
  out.size_ = leaves.size();
  return out;
}

PersistentSmt PersistentSmt::updated(const std::vector<std::pair<Hash32, std::optional<Hash32>>>& changes) const {
  PersistentSmt out = *this;
  if (changes.empty()) return out;
  std::lock_guard<std::mutex> lock(g_memo_mu);
  if (memo_table().size() > kLeafPathMemoMaxEntries) memo_table().clear();
  for (const auto& [key, leaf_hash] : changes) {
    if (leaf_hash.has_value()) {
      bool inserted = false;
      out.root_ = PersistentSmtOps::set(out.root_, key, *leaf_hash, &inserted);
      if (inserted) ++out.size_;
    } else {
      bool removed = false;
      out.root_ = PersistentSmtOps::erase(out.root_, key, &removed);
      if (removed) --out.size_;
    }
  }
  return out;
}

SmtProof PersistentSmt::proof(const Hash32& key) const {
  const auto& empties = PersistentSmtOps::empties();
  SmtProof out;
  out.siblings.resize(256);
  // siblings[255 - d] is the sibling at depth d + 1 of the node on key's path at depth d.
  for (std::size_t d = 0; d < 256; ++d) out.siblings[255 - d] = empties[d + 1];
  std::lock_guard<std::mutex> lock(g_memo_mu);
  const Node* n = root_.get();
  while (n != nullptr) {
    const auto diff = first_diff_bit(n->key, key);
    if (n->leaf || diff < n->depth) {
      // key leaves this subtree at depth `diff` (or is this leaf): the whole subtree is its sibling there.
      if (diff < 256) out.siblings[255 - diff] = PersistentSmtOps::lift(*n, diff + 1);
      break;
    }
    const int side = SparseMerkleTree::bit_at(key, n->depth) ? 1 : 0;
    out.siblings[255 - n->depth] = PersistentSmtOps::lift(*n->child[1 - side], n->depth + 1u);
    n = n->child[side].get();
  }
  return out;
}

Bytes encode_smt_delta(const std::vector<SmtChange>& changes) {
  codec::ByteWriter w;
  w.varint(changes.size());
  for (const auto& [key, leaf] : changes) {
    w.bytes_fixed(key);
    w.u8(leaf.has_value() ? 1 : 0);
    if (leaf.has_value()) w.bytes_fixed(*leaf);
  }
  return w.take();
}

std::optional<std::vector<SmtChange>> decode_smt_delta(const Bytes& bytes) {
  std::vector<SmtChange> out;
  if (!codec::parse_exact(bytes, [&](codec::ByteReader& r) {
        const auto count = r.varint();
        if (!count || *count > bytes.size()) return false;
        for (std::uint64_t i = 0; i < *count; ++i) {
          const auto key = r.bytes_fixed<32>();
          const auto present = r.u8();
          if (!key || !present || *present > 1) return false;
          std::optional<Hash32> leaf;
          if (*present == 1) {
            const auto h = r.bytes_fixed<32>();
            if (!h) return false;
            leaf = *h;
          }
          out.push_back({*key, leaf});
        }
        return true;
      })) {
    return std::nullopt;
  }
  return out;
}

Hash32 PersistentSmt::root() const {
  if (!root_) return PersistentSmtOps::empties()[0];
  std::lock_guard<std::mutex> lock(g_memo_mu);
  return PersistentSmtOps::lift(*root_, 0);
}

}  // namespace finalis::crypto
